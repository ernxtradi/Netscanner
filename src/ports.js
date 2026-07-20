/**
 * ports.js
 * ----------------
 * TCP port scanning utility for local network inventory/monitoring.
 *
 * Notes vs. the original portScanner.js:
 *   - scanPorts() now works with NO port list supplied (defaults to a
 *     top-20 common-ports list), fixing scanner.js which called
 *     scanPorts(ip) with a single argument.
 *   - Concurrency-limited batch scanning via shared runWithConcurrency.
 *   - Common service name lookup for discovered open ports.
 *   - Proper socket listener cleanup (no leaked event handlers).
 *   - Input validation.
 *   - Runnable directly from the CLI for quick manual scans.
 */

const net = require("net");
const dgram = require("dgram");
const { runWithConcurrency } = require("./utils");

// A small, common-port -> service-name table.
// Extend this as needed for your environment.
const COMMON_SERVICES = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
  53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
  111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
  143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
  445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
  587: "smtp-submission", 631: "ipp", 636: "ldaps", 993: "imaps",
  995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
  3000: "dev-http", 3306: "mysql", 3389: "rdp", 5000: "dev-http",
  5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
  8080: "http-proxy", 8443: "https-alt", 9000: "http-alt",
  9200: "elasticsearch", 27017: "mongodb",
};

// UDP port numbers frequently mean something different than their TCP
// counterpart (e.g. 161/tcp is rarely used, but 161/udp is SNMP). Checked
// first for UDP lookups, falling back to COMMON_SERVICES.
const UDP_SERVICES = {
  53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
  111: "rpcbind", 123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
  161: "snmp", 162: "snmptrap", 500: "isakmp", 514: "syslog",
  520: "rip", 1900: "ssdp", 5353: "mdns",
};

// Default ports checked when scanPorts() is called with no port list —
// a fast, "top 20" style sweep suitable for scanning an entire /24.
const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
  443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017,
];

// Default UDP ports checked when scanUdpPorts() is called with no port
// list — common LAN/service discovery and infrastructure ports.
const DEFAULT_UDP_PORTS = [
  53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353,
];

/**
 * Look up a friendly service name for a port. Falls back to "unknown".
 * @param {number} port
 * @param {"tcp"|"udp"} [protocol="tcp"]
 * @returns {string}
 */
function serviceName(port, protocol = "tcp") {
  if (protocol === "udp") return UDP_SERVICES[port] || COMMON_SERVICES[port] || "unknown";
  return COMMON_SERVICES[port] || "unknown";
}

/**
 * Scan a single TCP port on a host.
 * @param {string} ip - Target IPv4/IPv6 address or hostname.
 * @param {number} port - Port number (1-65535).
 * @param {number} [timeout=500] - Connection timeout in ms.
 * @returns {Promise<boolean>} true if the port is open, false otherwise.
 */
function scanPort(ip, port, timeout = 500) {
  if (!ip || typeof ip !== "string") {
    return Promise.reject(new Error("scanPort: 'ip' must be a non-empty string"));
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return Promise.reject(new Error(`scanPort: invalid port '${port}'`));
  }

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeout);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.once("timeout", () => finish(false));

    socket.connect(port, ip);
  });
}

/**
 * Scan a list of ports on a host. If `ports` is omitted, scans DEFAULT_PORTS.
 * @param {string} ip
 * @param {number[]} [ports=DEFAULT_PORTS]
 * @param {object} [options]
 * @param {number} [options.timeout=500] - Per-port timeout in ms.
 * @param {number} [options.concurrency=50] - Max simultaneous connections.
 * @returns {Promise<Array<{port: number, open: boolean, service: string}>>}
 *   Only OPEN ports are returned, matching how scanner.js consumes the result.
 */
async function scanPorts(ip, ports = DEFAULT_PORTS, options = {}) {
  const { timeout = 500, concurrency = 50 } = options;

  if (!Array.isArray(ports) || ports.length === 0) {
    throw new Error("scanPorts: 'ports' must be a non-empty array");
  }

  const tasks = ports.map((port) => async () => ({
    port,
    protocol: "tcp",
    state: (await scanPort(ip, port, timeout)) ? "open" : "closed",
    service: serviceName(port, "tcp"),
  }));

  const results = await runWithConcurrency(tasks, concurrency);
  return results
    .filter((r) => r.state === "open")
    .sort((a, b) => a.port - b.port);
}

/**
 * Probe a single UDP port on a host.
 *
 * UDP is connectionless, so "open" can't be detected the way TCP's
 * SYN/ACK can — this uses the same technique as nmap's UDP scan:
 *   - send an empty datagram
 *   - a reply datagram means the port is definitely open
 *   - on Linux/macOS, a connected UDP socket surfaces an ICMP
 *     "port unreachable" as an ECONNREFUSED error event, meaning closed
 *   - no reply and no error before the timeout is ambiguous (the
 *     datagram or an ICMP reply may have been silently dropped by a
 *     firewall) — reported as "open|filtered", matching standard
 *     UDP-scan terminology
 * @param {string} ip
 * @param {number} port
 * @param {number} [timeout=1000]
 * @returns {Promise<"open"|"closed"|"open|filtered">}
 */
function scanUdpPort(ip, port, timeout = 1000) {
  if (!ip || typeof ip !== "string") {
    return Promise.reject(new Error("scanUdpPort: 'ip' must be a non-empty string"));
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return Promise.reject(new Error(`scanUdpPort: invalid port '${port}'`));
  }

  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    let timer = null;

    const finish = (state) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.removeAllListeners();
      try {
        socket.close();
      } catch {
        // already closed
      }
      resolve(state);
    };

    socket.once("error", (err) => finish(err.code === "ECONNREFUSED" ? "closed" : "open|filtered"));
    socket.once("message", () => finish("open"));

    socket.connect(port, ip, () => {
      timer = setTimeout(() => finish("open|filtered"), timeout);
      socket.send(Buffer.from([0]));
    });
  });
}

/**
 * Scan a list of UDP ports on a host. If `ports` is omitted, scans
 * DEFAULT_UDP_PORTS. Matches scanPorts()'s shape/behavior but excludes
 * only definitively "closed" ports — "open|filtered" results are kept,
 * since silence is expected/common for UDP even on an open port.
 * @param {string} ip
 * @param {number[]} [ports=DEFAULT_UDP_PORTS]
 * @param {object} [options]
 * @param {number} [options.timeout=1000] - Per-port timeout in ms.
 * @param {number} [options.concurrency=50] - Max simultaneous probes.
 * @returns {Promise<Array<{port: number, protocol: "udp", state: string, service: string}>>}
 */
async function scanUdpPorts(ip, ports = DEFAULT_UDP_PORTS, options = {}) {
  const { timeout = 1000, concurrency = 50 } = options;

  if (!Array.isArray(ports) || ports.length === 0) {
    throw new Error("scanUdpPorts: 'ports' must be a non-empty array");
  }

  const tasks = ports.map((port) => async () => ({
    port,
    protocol: "udp",
    state: await scanUdpPort(ip, port, timeout),
    service: serviceName(port, "udp"),
  }));

  const results = await runWithConcurrency(tasks, concurrency);
  return results
    .filter((r) => r.state !== "closed")
    .sort((a, b) => a.port - b.port);
}

/**
 * Scan both the default TCP and UDP port lists on a host and merge the
 * results into one list, each entry tagged with its protocol — this is
 * what scanner.js uses to populate a host's `openPorts`.
 * @param {string} ip
 * @param {object} [options]
 * @param {number[]} [options.tcpPorts=DEFAULT_PORTS]
 * @param {number[]} [options.udpPorts=DEFAULT_UDP_PORTS]
 * @param {number} [options.timeout]
 * @param {number} [options.concurrency]
 * @returns {Promise<Array<object>>}
 */
async function scanHostPorts(ip, options = {}) {
  const { tcpPorts = DEFAULT_PORTS, udpPorts = DEFAULT_UDP_PORTS, ...rest } = options;
  const [tcp, udp] = await Promise.all([
    scanPorts(ip, tcpPorts, rest),
    scanUdpPorts(ip, udpPorts, rest),
  ]);
  return [...tcp, ...udp].sort((a, b) => a.port - b.port);
}

/**
 * Scan a contiguous range of ports on a host.
 * @param {string} ip
 * @param {number} start - Start port (inclusive).
 * @param {number} end - End port (inclusive).
 * @param {object} [options] - Same options as scanPorts.
 * @returns {Promise<Array<{port: number, open: boolean, service: string}>>}
 */
function scanPortRange(ip, start, end, options = {}) {
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || start > end) {
    throw new Error(`scanPortRange: invalid range ${start}-${end}`);
  }
  const ports = [];
  for (let p = start; p <= end; p++) ports.push(p);
  return scanPorts(ip, ports, options);
}

module.exports = {
  scanPort,
  scanPorts,
  scanPortRange,
  scanUdpPort,
  scanUdpPorts,
  scanHostPorts,
  serviceName,
  COMMON_SERVICES,
  UDP_SERVICES,
  DEFAULT_PORTS,
  DEFAULT_UDP_PORTS,
};

// ---------------------------------------------------------------------------
// CLI usage:
//   node ports.js <ip> <port|start-end> [timeout] [concurrency] [udp]
// Examples:
//   node ports.js 192.168.0.1 22
//   node ports.js 192.168.0.1 1-1024
//   node ports.js 192.168.0.1 1-65535 300 100
//   node ports.js 192.168.0.1 53 1000 50 udp
// ---------------------------------------------------------------------------
if (require.main === module) {
  (async () => {
    const [, , ip, portArg, timeoutArg, concurrencyArg, protoArg] = process.argv;

    if (!ip) {
      console.error("Usage: node ports.js <ip> [port|start-end] [timeout] [concurrency] [udp]");
      process.exit(1);
    }

    const udp = protoArg === "udp";
    const timeout = timeoutArg ? parseInt(timeoutArg, 10) : udp ? 1000 : 500;
    const concurrency = concurrencyArg ? parseInt(concurrencyArg, 10) : 50;

    try {
      let results;
      if (!portArg) {
        console.log(`Scanning ${ip} default ${udp ? "UDP" : "TCP"} ports (timeout=${timeout}ms)...`);
        results = udp
          ? await scanUdpPorts(ip, DEFAULT_UDP_PORTS, { timeout, concurrency })
          : await scanPorts(ip, DEFAULT_PORTS, { timeout, concurrency });
      } else if (portArg.includes("-")) {
        const [start, end] = portArg.split("-").map(Number);
        console.log(`Scanning ${ip} ${udp ? "UDP" : "TCP"} ports ${start}-${end} (timeout=${timeout}ms, concurrency=${concurrency})...`);
        const ports = [];
        for (let p = start; p <= end; p++) ports.push(p);
        results = udp
          ? await scanUdpPorts(ip, ports, { timeout, concurrency })
          : await scanPortRange(ip, start, end, { timeout, concurrency });
      } else {
        const port = Number(portArg);
        console.log(`Scanning ${ip} ${udp ? "UDP" : "TCP"} port ${port} (timeout=${timeout}ms)...`);
        if (udp) {
          const state = await scanUdpPort(ip, port, timeout);
          results = state === "closed" ? [] : [{ port, protocol: "udp", state, service: serviceName(port, "udp") }];
        } else {
          const open = await scanPort(ip, port, timeout);
          results = open ? [{ port, protocol: "tcp", state: "open", service: serviceName(port, "tcp") }] : [];
        }
      }

      if (results.length === 0) {
        console.log("No open ports found.");
      } else {
        console.log(`\nOpen ports on ${ip}:`);
        results.forEach((r) => console.log(`  ${r.port}/${r.protocol}  ${r.state}  ${r.service}`));
      }
      console.log(`\n${results.length} open port(s) found.`);
    } catch (err) {
      console.error("Scan failed:", err.message);
      process.exit(1);
    }
  })();
}