/**
 * captureWorker.js
 * ----------------
 * Runs as an isolated child process (forked by capture.js), doing the
 * actual libpcap packet capture and decoding. This code was originally
 * inline in the parent process — it was moved here after a real SIGSEGV
 * was observed coming from the native `cap` binding during live capture.
 * A native crash can only take down the process it happens in, so
 * running it here means a pcap crash kills this worker, not the whole
 * dashboard server. See capture.js for the supervising/restart logic.
 *
 * Talks to the parent over the standard child_process IPC channel:
 *   -> parent: { type: "stats", snapshot }
 *   -> parent: { type: "error", message }   (explicit, non-crash failure —
 *              e.g. missing module, no matching device, permission denied)
 * An unexpected process exit (including death by signal, e.g. SIGSEGV) is
 * NOT reported here — the parent detects that itself via the child's
 * "exit" event, since a crashed process can't send a final message.
 */

const config = JSON.parse(process.argv[2] || "{}");
const { localIp, filter = "ip or arp", statsIntervalMs = 2000 } = config;

// Safety valves — same rationale as before: don't let a traffic flood (or
// running on a busy gateway) grow memory without bound.
const MAX_TRACKED_HOSTS = 300;
const MAX_PORTS_PER_HOST = 40;

function fail(message) {
  // process.exit() right after process.send() can drop the message before
  // the IPC channel flushes it — wait for the send callback before exiting.
  if (process.send) {
    process.send({ type: "error", message }, () => process.exit(1));
  } else {
    process.exit(1);
  }
}

let Cap, decoders, PROTOCOL;
try {
  ({ Cap, decoders, PROTOCOL } = require("cap"));
} catch (err) {
  fail(
    "Packet capture requires the 'cap' package and libpcap headers. " +
    `Run: sudo apt-get install libpcap-dev && npm install cap — then restart. (${err.message})`
  );
}

const device = Cap.findDevice(localIp);
if (!device) {
  fail(`No capture-able device found for local IP ${localIp}.`);
}

const cap = new Cap();
const buffer = Buffer.alloc(65535);
const bufSize = 10 * 1024 * 1024;

let linkType;
try {
  linkType = cap.open(device, filter, bufSize, buffer);
} catch (err) {
  fail(
    "Failed to open capture device — this almost always means insufficient privileges. " +
    'Run as root, or: sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f $(which node))" ' +
    `(${err.message})`
  );
}
if (cap.setMinBytes) cap.setMinBytes(0);

function protocolLabel(ipProtocol) {
  if (ipProtocol === PROTOCOL.IP.TCP) return "tcp";
  if (ipProtocol === PROTOCOL.IP.UDP) return "udp";
  if (ipProtocol === PROTOCOL.IP.ICMP) return "icmp";
  return "other";
}

const totals = { packets: 0, bytes: 0, tcp: 0, udp: 0, icmp: 0, arp: 0, other: 0, startedAt: Date.now() };
const hosts = new Map(); // ip -> stats entry

function getEntry(ip) {
  let entry = hosts.get(ip);
  if (!entry) {
    if (hosts.size >= MAX_TRACKED_HOSTS) return null; // drop, don't grow unbounded
    entry = {
      ip,
      isLocal: ip === localIp,
      bytesSent: 0,
      bytesReceived: 0,
      packetsSent: 0,
      packetsReceived: 0,
      tcp: 0,
      udp: 0,
      icmp: 0,
      arp: 0,
      other: 0,
      ports: new Map(), // "protocol/port" -> count
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      prevBytesSent: 0,
      prevBytesReceived: 0,
    };
    hosts.set(ip, entry);
  }
  entry.lastSeen = Date.now();
  return entry;
}

function notePort(entry, protoLabel, port) {
  if (!entry || port == null) return;
  const key = `${protoLabel}/${port}`;
  if (!entry.ports.has(key) && entry.ports.size >= MAX_PORTS_PER_HOST) return;
  entry.ports.set(key, (entry.ports.get(key) || 0) + 1);
}

function onIpPacket(protoLabel, srcaddr, dstaddr, length, srcport, dstport) {
  totals.packets++;
  totals.bytes += length;
  totals[protoLabel] = (totals[protoLabel] || 0) + 1;

  const src = getEntry(srcaddr);
  if (src) {
    src.bytesSent += length;
    src.packetsSent++;
    src[protoLabel] = (src[protoLabel] || 0) + 1;
    notePort(src, protoLabel, srcport);
  }

  const dst = getEntry(dstaddr);
  if (dst) {
    dst.bytesReceived += length;
    dst.packetsReceived++;
    dst[protoLabel] = (dst[protoLabel] || 0) + 1;
    notePort(dst, protoLabel, dstport);
  }
}

function handlePacket(nbytes) {
  if (linkType !== "ETHERNET") return;

  let ret;
  try {
    ret = decoders.Ethernet(buffer);
  } catch {
    return; // malformed/truncated frame — skip
  }

  if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
    totals.packets++;
    totals.arp++;
    return;
  }

  if (ret.info.type !== PROTOCOL.ETHERNET.IPV4) return; // IPv6/other: skip for now

  try {
    const ip = decoders.IPV4(buffer, ret.offset);
    const protoLabel = protocolLabel(ip.info.protocol);
    const length = ip.info.totallen || nbytes;

    if (protoLabel === "tcp") {
      const tcp = decoders.TCP(buffer, ip.offset);
      onIpPacket("tcp", ip.info.srcaddr, ip.info.dstaddr, length, tcp.info.srcport, tcp.info.dstport);
    } else if (protoLabel === "udp") {
      const udp = decoders.UDP(buffer, ip.offset);
      onIpPacket("udp", ip.info.srcaddr, ip.info.dstaddr, length, udp.info.srcport, udp.info.dstport);
    } else {
      onIpPacket(protoLabel, ip.info.srcaddr, ip.info.dstaddr, length, null, null);
    }
  } catch {
    // malformed/truncated packet — skip
  }
}

cap.on("packet", handlePacket);

function rateMbps(deltaBytes, elapsedMs) {
  if (elapsedMs <= 0) return 0;
  return Number(((deltaBytes * 8) / (elapsedMs / 1000) / 1_000_000).toFixed(3));
}

let lastTickAt = Date.now();
const timer = setInterval(() => {
  const now = Date.now();
  const elapsedMs = now - lastTickAt;
  lastTickAt = now;

  const hostSnapshots = [...hosts.values()]
    .map((h) => {
      const mbpsSent = rateMbps(h.bytesSent - h.prevBytesSent, elapsedMs);
      const mbpsReceived = rateMbps(h.bytesReceived - h.prevBytesReceived, elapsedMs);
      h.prevBytesSent = h.bytesSent;
      h.prevBytesReceived = h.bytesReceived;
      return {
        ...h,
        mbpsSent,
        mbpsReceived,
        ports: [...h.ports.entries()].map(([key, count]) => ({ key, count })),
      };
    })
    .sort((a, b) => b.bytesSent + b.bytesReceived - (a.bytesSent + a.bytesReceived));

  if (process.send) {
    process.send({
      type: "stats",
      snapshot: {
        totals: { ...totals, uptimeSec: Math.round((now - totals.startedAt) / 1000) },
        hosts: hostSnapshots,
      },
    });
  }
}, statsIntervalMs);

function shutdown() {
  clearInterval(timer);
  try {
    cap.close();
  } catch {
    // already closed
  }
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("disconnect", shutdown); // parent's IPC channel closed (e.g. parent exited)
