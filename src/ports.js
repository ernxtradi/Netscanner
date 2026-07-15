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

// Default ports checked when scanPorts() is called with no port list —
// a fast, "top 20" style sweep suitable for scanning an entire /24.
const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
  443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017,
];

/**
 * Look up a friendly service name for a port. Falls back to "unknown".
 * @param {number} port
 * @returns {string}
 */
function serviceName(port) {
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
    open: await scanPort(ip, port, timeout),
    service: serviceName(port),
  }));

  const results = await runWithConcurrency(tasks, concurrency);
  return results
    .filter((r) => r.open)
    .sort((a, b) => a.port - b.port);
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
  serviceName,
  COMMON_SERVICES,
  DEFAULT_PORTS,
};

// ---------------------------------------------------------------------------
// CLI usage:
//   node ports.js <ip> <port|start-end> [timeout] [concurrency]
// Examples:
//   node ports.js 192.168.0.1 22
//   node ports.js 192.168.0.1 1-1024
//   node ports.js 192.168.0.1 1-65535 300 100
// ---------------------------------------------------------------------------
if (require.main === module) {
  (async () => {
    const [, , ip, portArg, timeoutArg, concurrencyArg] = process.argv;

    if (!ip) {
      console.error("Usage: node ports.js <ip> [port|start-end] [timeout] [concurrency]");
      process.exit(1);
    }

    const timeout = timeoutArg ? parseInt(timeoutArg, 10) : 500;
    const concurrency = concurrencyArg ? parseInt(concurrencyArg, 10) : 50;

    try {
      let results;
      if (!portArg) {
        console.log(`Scanning ${ip} default ports (timeout=${timeout}ms)...`);
        results = await scanPorts(ip, DEFAULT_PORTS, { timeout, concurrency });
      } else if (portArg.includes("-")) {
        const [start, end] = portArg.split("-").map(Number);
        console.log(`Scanning ${ip} ports ${start}-${end} (timeout=${timeout}ms, concurrency=${concurrency})...`);
        results = await scanPortRange(ip, start, end, { timeout, concurrency });
      } else {
        const port = Number(portArg);
        console.log(`Scanning ${ip} port ${port} (timeout=${timeout}ms)...`);
        const open = await scanPort(ip, port, timeout);
        results = open ? [{ port, open: true, service: serviceName(port) }] : [];
      }

      if (results.length === 0) {
        console.log("No open ports found.");
      } else {
        console.log(`\nOpen ports on ${ip}:`);
        results.forEach((r) => console.log(`  ${r.port}/tcp  open  ${r.service}`));
      }
      console.log(`\n${results.length} open port(s) found.`);
    } catch (err) {
      console.error("Scan failed:", err.message);
      process.exit(1);
    }
  })();
}