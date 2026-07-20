/**
 * capture.js
 * ----------------
 * Live packet capture (via libpcap, through the `cap` native binding) and
 * per-device traffic accounting: bytes/packets in and out, protocol
 * breakdown (TCP/UDP/ICMP/ARP/other), and ports observed in live traffic
 * for every IP seen on the wire.
 *
 * VISIBILITY LIMITATION — read before relying on this: on a normal
 * switched LAN, a capture on this host only sees traffic to/from *this*
 * host, plus broadcast/multicast frames (ARP, mDNS, SSDP, DHCP, etc.).
 * It does NOT see traffic between two *other* devices unless this host
 * is the gateway/router, or the switch port it's on is mirrored/SPANned.
 * Treat live stats for hosts other than this machine as partial —
 * broadcast/multicast visibility only, not their full traffic.
 *
 * REQUIREMENTS (both best-effort at call time, never crash the caller):
 *   - libpcap + headers on the OS (e.g. `apt install libpcap-dev`) so the
 *     native `cap` package can build — `npm install cap`.
 *   - Permission to open a live capture: run as root, or grant the node
 *     binary the capability directly:
 *       sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f $(which node))"
 *
 * `cap` is require()'d lazily (inside startCapture, not at module load)
 * so a missing/unbuilt native module can never take down the rest of the
 * app — callers get a rejected promise / thrown Error with a clear cause
 * instead.
 */

const { getInterfaces } = require("./subnet");

// Safety valve: cap how many distinct IPs we track live stats for, so a
// port-scan-like flood of traffic (or being run on a busy gateway) can't
// grow the stats map without bound.
const MAX_TRACKED_HOSTS = 300;

// Safety valve: cap how many distinct "protocol/port" keys we remember
// per host, for the same reason.
const MAX_PORTS_PER_HOST = 40;

/**
 * Best-effort check for whether packet capture is usable in this
 * environment, without throwing. Does NOT check for capture permission
 * (that's only knowable by actually trying to open a device).
 * @returns {{available: boolean, reason?: string}}
 */
function checkAvailable() {
  try {
    require("cap");
    return { available: true };
  } catch (err) {
    return {
      available: false,
      reason:
        "The 'cap' native module isn't installed/built. Install libpcap headers and the package: " +
        "sudo apt-get install libpcap-dev && npm install cap (" + err.message + ")",
    };
  }
}

/**
 * List capture-able network devices as libpcap sees them (distinct from
 * the OS interface names subnet.js reports).
 * @returns {Array<object>}
 */
function listDevices() {
  const { Cap } = require("cap");
  return Cap.deviceList();
}

function protocolLabel(PROTOCOL, ipProtocol) {
  if (ipProtocol === PROTOCOL.IP.TCP) return "tcp";
  if (ipProtocol === PROTOCOL.IP.UDP) return "udp";
  if (ipProtocol === PROTOCOL.IP.ICMP) return "icmp";
  return "other";
}

/**
 * Start a live capture session, accounting traffic per source/destination
 * IP address as packets arrive.
 *
 * @param {object} [options]
 * @param {string} [options.filter="ip or arp"] - BPF filter expression.
 * @param {number} [options.statsIntervalMs=2000] - How often onStats fires.
 * @param {(snapshot: {totals: object, hosts: object[]}) => void} [options.onStats]
 * @returns {{stop(): void, isRunning(): boolean}}
 * @throws {Error} synchronously if `cap` isn't installed, no matching
 *   capture device can be found, or the OS refuses to open it (usually a
 *   permissions problem — see the module doc comment above).
 */
function startCapture(options = {}) {
  const { filter = "ip or arp", statsIntervalMs = 2000, onStats } = options;

  let Cap, decoders, PROTOCOL;
  try {
    ({ Cap, decoders, PROTOCOL } = require("cap"));
  } catch (err) {
    throw new Error(
      "Packet capture requires the 'cap' package and libpcap headers. " +
      "Run: sudo apt-get install libpcap-dev && npm install cap — then restart. " +
      `(${err.message})`
    );
  }

  const interfaces = getInterfaces();
  if (interfaces.length === 0) {
    throw new Error("startCapture: no active network interface found.");
  }
  const localIp = interfaces[0].ip;

  const device = Cap.findDevice(localIp);
  if (!device) {
    throw new Error(`startCapture: no capture-able device found for local IP ${localIp}.`);
  }

  const cap = new Cap();
  const buffer = Buffer.alloc(65535);
  const bufSize = 10 * 1024 * 1024;

  let linkType;
  try {
    linkType = cap.open(device, filter, bufSize, buffer);
  } catch (err) {
    throw new Error(
      "startCapture: failed to open capture device — this almost always means insufficient " +
      "privileges. Run as root, or: sudo setcap cap_net_raw,cap_net_admin+eip \"$(readlink -f $(which node))\" " +
      `(${err.message})`
    );
  }
  if (cap.setMinBytes) cap.setMinBytes(0);

  const totals = { packets: 0, bytes: 0, tcp: 0, udp: 0, icmp: 0, arp: 0, other: 0, startedAt: Date.now() };
  const hosts = new Map(); // ip -> stats entry

  function getEntry(ip) {
    let entry = hosts.get(ip);
    if (!entry) {
      if (hosts.size >= MAX_TRACKED_HOSTS) return null; // safety valve — drop, don't grow unbounded
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
        // Cumulative byte counts as of the last stats tick — diffed each
        // tick to compute a live Mbps rate. Not reset; only read/updated
        // by the stats-emitting interval below.
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
      return; // malformed/truncated frame — skip rather than crash the capture loop
    }

    if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
      totals.packets++;
      totals.arp++;
      return;
    }

    if (ret.info.type !== PROTOCOL.ETHERNET.IPV4) return; // IPv6/other: skip for now

    try {
      const ip = decoders.IPV4(buffer, ret.offset);
      const protoLabel = protocolLabel(PROTOCOL, ip.info.protocol);
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
      // malformed/truncated packet — skip rather than crash the capture loop
    }
  }

  cap.on("packet", handlePacket);

  function rateMbps(deltaBytes, elapsedMs) {
    if (elapsedMs <= 0) return 0;
    return Number(((deltaBytes * 8) / (elapsedMs / 1000) / 1_000_000).toFixed(3));
  }

  let running = true;
  let lastTickAt = Date.now();
  const timer = setInterval(() => {
    const now = Date.now();
    const elapsedMs = now - lastTickAt;
    lastTickAt = now;

    if (!onStats) return;

    // Live per-device throughput ("speed between devices"): each host's
    // Mbps sent/received since the *previous* tick, not a cumulative
    // average — so it reflects current activity, not history.
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

    onStats({
      totals: { ...totals, uptimeSec: Math.round((now - totals.startedAt) / 1000) },
      hosts: hostSnapshots,
    });
  }, statsIntervalMs);

  return {
    stop() {
      if (!running) return;
      running = false;
      clearInterval(timer);
      try {
        cap.removeAllListeners();
        cap.close();
      } catch {
        // already closed
      }
    },
    isRunning() {
      return running;
    },
  };
}

module.exports = {
  checkAvailable,
  listDevices,
  startCapture,
  MAX_TRACKED_HOSTS,
  MAX_PORTS_PER_HOST,
};
