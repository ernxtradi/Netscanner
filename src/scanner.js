const { pingHost } = require("./ping");
const { getHostRange } = require("./subnet");
const { getHostname } = require("./dns");
const { scanPorts } = require("./ports");
const { getMac } = require("./arp");
const { getVendor } = require("./vendor");
const { classifyDevice } = require("./classify");
const report = require("./report");
const { runWithConcurrency } = require("./utils");

// How many hosts to probe (ping + DNS + ARP + port scan) at the same time.
// The original code fired all 254 hosts at once with Promise.all, which
// on a full /24 (or larger, once subnet math was fixed) can exhaust
// available sockets/file descriptors. This caps it to a sane pool size.
const HOST_CONCURRENCY = 30;

const onlineHosts = [];
let scanned = 0;
let totalHosts = 0;

/**
 * Scan a single host: liveness, hostname, MAC/vendor, open ports, classification.
 * @param {string} ip
 * @param {string|null} gatewayIp - The subnet's gateway IP, if known, so it
 *   can be flagged for classification.
 */
async function scanHost(ip, gatewayIp = null) {
  scanned++;
  process.stdout.write(`\rScanning ${scanned}/${totalHosts} : ${ip}          `);

  const ping = await pingHost(ip);
  if (!ping.alive) return;

  const [hostname, openPorts, mac] = await Promise.all([
    getHostname(ip),
    scanPorts(ip),
    getMac(ip),
  ]);

  const vendor = mac ? await getVendor(mac) : "Unknown Vendor";
  const isGateway = gatewayIp === ip;
  const { type } = classifyDevice({ hostname, vendor, openPorts, isGateway });

  const host = {
    ip,
    hostname,
    mac: mac || "Unknown",
    vendor,
    deviceType: type,
    latency: `${ping.latency} ms`,
    openPorts,
    scannedAt: new Date().toISOString(),
  };

  onlineHosts.push(host);

  console.log(`

========================================
HOST ONLINE
========================================
IP        : ${host.ip}
Hostname  : ${host.hostname}
MAC       : ${host.mac}
Vendor    : ${host.vendor}
Type      : ${host.deviceType}
Latency   : ${host.latency}
Ports     : ${
    openPorts.length ? openPorts.map((p) => `${p.port} (${p.service})`).join(", ") : "None"
  }
========================================`);
}

/**
 * Scan a list of host IPs with bounded concurrency.
 * @param {string[]} ips
 * @param {string|null} gatewayIp
 */
async function scanNetwork(ips, gatewayIp = null) {
  totalHosts = ips.length;
  console.log(`\nScanning ${ips.length} host(s)\n`);

  const tasks = ips.map((ip) => () => scanHost(ip, gatewayIp));
  await runWithConcurrency(tasks, HOST_CONCURRENCY);
}

/**
 * Main entry point.
 */
async function start() {
  console.clear();
  console.log("==================================");
  console.log("      Node Network Scanner");
  console.log("==================================");

  const { subnet, ips, range, capped } = getHostRange();

  console.log(`\nSubnet detected: ${range.network}/${range.cidr}`);
  if (capped) {
    console.log(
      `Note: subnet has ${range.totalHosts} usable hosts; capping scan to the first ${ips.length} for safety.`
    );
  }

  // Best-effort guess at the gateway: conventionally the first usable host.
  const gatewayIp = range.firstHost;

  const startTime = Date.now();
  await scanNetwork(ips, gatewayIp);
  const endTime = Date.now();
  const durationSec = ((endTime - startTime) / 1000).toFixed(2);

  const paths = report.saveAll(onlineHosts, { subnet, durationSec });

  console.log("\n\n==================================");
  console.log("SCAN COMPLETE");
  console.log("==================================");
  console.log(`Subnet        : ${range.network}/${range.cidr}`);
  console.log(`Hosts Online  : ${onlineHosts.length}`);
  console.log(`Hosts Scanned : ${ips.length}`);
  console.log(`Time Taken    : ${durationSec} sec`);
  console.log(`\nReports saved:`);
  console.log(`  JSON : ${paths.json}`);
  console.log(`  CSV  : ${paths.csv}`);
  console.log(`  HTML : ${paths.html}`);

  console.table(
    onlineHosts.map((h) => ({
      ip: h.ip,
      hostname: h.hostname,
      vendor: h.vendor,
      type: h.deviceType,
      latency: h.latency,
      ports: h.openPorts.length,
    }))
  );
}

module.exports = {
  start,
};