/**
 * gateway.js
 * ----------------
 * Default gateway detection via the OS routing table.
 *
 * Mirrors arp.js's shell-out pattern: a missing command or unparsable
 * output isn't fatal, callers just fall back to a best-effort guess.
 */

const { exec } = require("child_process");
const os = require("os");

const IP_REGEX = /\d{1,3}(?:\.\d{1,3}){3}/;

function run(command) {
  return new Promise((resolve) => {
    exec(command, { timeout: 5000 }, (err, stdout) => {
      resolve(err ? "" : stdout);
    });
  });
}

/**
 * Parse the default gateway IP out of a routing table command's output.
 * @param {string} output
 * @param {string} platform - os.platform() value
 * @returns {string|null}
 */
function parseGatewayOutput(output, platform) {
  const lines = output.split("\n");

  if (platform === "win32") {
    // `route print -4` — look for the "0.0.0.0  0.0.0.0  <gateway>  ..." row.
    const line = lines.find((l) => /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+\d/.test(l));
    if (!line) return null;
    const cols = line.trim().split(/\s+/);
    return cols[2] || null;
  }

  if (platform === "darwin") {
    // `route -n get default` — look for the "gateway: x.x.x.x" line.
    const line = lines.find((l) => /gateway:/i.test(l));
    const match = line && line.match(IP_REGEX);
    return match ? match[0] : null;
  }

  // Linux: `ip route show default` — "default via x.x.x.x dev eth0 ..."
  const line = lines.find((l) => l.trim().startsWith("default"));
  const match = line && line.match(IP_REGEX);
  return match ? match[0] : null;
}

/**
 * Detect the machine's default gateway IP from the OS routing table.
 * @returns {Promise<string|null>}
 */
async function detectGateway() {
  const platform = os.platform();
  const command =
    platform === "win32"
      ? "route print -4"
      : platform === "darwin"
      ? "route -n get default"
      : "ip route show default";

  const output = await run(command);
  return parseGatewayOutput(output, platform);
}

/**
 * Resolve the gateway IP to use for a scan, falling back to the subnet's
 * first usable host if real detection fails.
 * @param {{firstHost: string}} range - the `range` object from subnet.getHostRange()
 * @returns {Promise<string>}
 */
async function getGatewayIp(range) {
  const detected = await detectGateway();
  return detected || range.firstHost;
}

module.exports = {
  detectGateway,
  getGatewayIp,
  parseGatewayOutput,
};
