/**
 * arp.js
 * ----------------
 * MAC address discovery via the operating system's ARP cache.
 *
 * There's no cross-platform way to read the ARP table without shelling
 * out to a system command, so this parses `arp -a` output on macOS/Linux
 * and Windows. A host must have already been contacted (e.g. pinged)
 * for its entry to exist in the ARP cache — call pingHost() first.
 */

const { exec } = require("child_process");
const os = require("os");

const MAC_REGEX = /([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/;

function run(command) {
  return new Promise((resolve) => {
    exec(command, { timeout: 5000 }, (err, stdout) => {
      // Don't reject — a missing `arp` binary or empty table isn't fatal,
      // callers just get an empty result.
      resolve(err ? "" : stdout);
    });
  });
}

/**
 * Parse `arp -a` output into {ip, mac} entries. Handles both the
 * macOS/Linux format ("? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0")
 * and the Windows format ("  192.168.0.1          aa-bb-cc-dd-ee-ff     dynamic").
 * @param {string} output
 * @returns {Array<{ip: string, mac: string}>}
 */
function parseArpOutput(output) {
  const entries = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const ipMatch = line.match(/\d{1,3}(?:\.\d{1,3}){3}/);
    const macMatch = line.match(MAC_REGEX);

    if (ipMatch && macMatch) {
      entries.push({
        ip: ipMatch[0],
        mac: macMatch[0].replace(/-/g, ":").toUpperCase(),
      });
    }
  }

  return entries;
}

/**
 * Return the full current ARP table as {ip, mac} entries.
 * @returns {Promise<Array<{ip: string, mac: string}>>}
 */
async function getArpTable() {
  const command = os.platform() === "win32" ? "arp -a" : "arp -a";
  const output = await run(command);
  return parseArpOutput(output);
}

/**
 * Look up the MAC address for a specific IP from the ARP table.
 * Note: the host must be reachable/recently contacted for an entry
 * to exist — pair this with pingHost(ip) beforehand.
 * @param {string} ip
 * @returns {Promise<string|null>}
 */
async function getMac(ip) {
  const table = await getArpTable();
  const entry = table.find((e) => e.ip === ip);
  return entry ? entry.mac : null;
}

module.exports = {
  getArpTable,
  getMac,
  parseArpOutput,
};