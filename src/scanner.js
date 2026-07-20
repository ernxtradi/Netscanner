const { pingHost } = require("./ping");
const { getHostRange } = require("./subnet");
const { getHostname } = require("./dns");
const { scanHostPorts } = require("./ports");
const { getMac } = require("./arp");
const { getVendor } = require("./vendor");
const { getGatewayIp } = require("./gateway");
const { classifyDevice } = require("./classify");
const { runWithConcurrency } = require("./utils");

// How many hosts to probe (ping + DNS + ARP + port scan) at the same time.
// The original code fired all 254 hosts at once with Promise.all, which
// on a full /24 (or larger, once subnet math was fixed) can exhaust
// available sockets/file descriptors. This caps it to a sane pool size.
const HOST_CONCURRENCY = 30;

/**
 * Scan the local subnet: liveness, hostname, MAC/vendor, open ports,
 * classification, for every host in range.
 *
 * Stateless and reentrant — all mutable state lives in local variables,
 * so this is safe to call repeatedly or concurrently (e.g. from a web
 * dashboard handling on-demand scans while a monitor loop is also
 * ticking). Has no side effects of its own (no console output, no
 * report files) — callers own presentation and persistence.
 *
 * @param {object} [options]
 * @param {number} [options.hostConcurrency=30] - Max hosts probed at once.
 * @param {string[]} [options.ips] - Explicit IP list to scan; defaults to
 *   the detected subnet's usable host range.
 * @param {(ip: string, scanned: number, total: number) => void} [options.onProgress]
 *   - Called before each host is probed.
 * @param {(host: object) => void} [options.onHost] - Called as each host
 *   resolves online, with the fully-assembled host record.
 * @returns {Promise<{hosts: object[], subnet: string, range: object, capped: boolean, gatewayIp: string, durationSec: string}>}
 */
async function scan(options = {}) {
  const { hostConcurrency = HOST_CONCURRENCY, onProgress, onHost } = options;

  const { subnet, ips: rangeIps, range, capped } = getHostRange();
  const ips = options.ips || rangeIps;

  // Best-effort real default gateway, falling back to the subnet's first
  // usable host if the OS routing table can't be read/parsed.
  const gatewayIp = await getGatewayIp(range);

  const onlineHosts = [];
  let scanned = 0;
  const totalHosts = ips.length;

  async function scanHost(ip) {
    scanned++;
    if (onProgress) onProgress(ip, scanned, totalHosts);

    const ping = await pingHost(ip);
    if (!ping.alive) return;

    const [hostname, openPorts, mac] = await Promise.all([
      getHostname(ip),
      scanHostPorts(ip),
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
    if (onHost) onHost(host);
  }

  const startTime = Date.now();
  const tasks = ips.map((ip) => () => scanHost(ip));
  await runWithConcurrency(tasks, hostConcurrency);
  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);

  return { hosts: onlineHosts, subnet, range, capped, gatewayIp, durationSec };
}

module.exports = {
  scan,
};
