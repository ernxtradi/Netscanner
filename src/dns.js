const dns = require("dns").promises;

/**
 * Race a promise against a timeout.
 */
function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

/**
 * Reverse DNS lookup.
 * @param {string} ip
 * @param {number} [timeout=1500] - Max time to wait, in ms.
 * @returns {Promise<string>}
 */
async function getHostname(ip, timeout = 1500) {
  try {
    const hostnames = await withTimeout(dns.reverse(ip), timeout, []);
    return hostnames.length > 0 ? hostnames[0] : "Unknown";
  } catch {
    return "Unknown";
  }
}

/**
 * Forward DNS lookup.
 * @param {string} hostname
 * @param {number} [timeout=1500] - Max time to wait, in ms.
 * @returns {Promise<string[]>}
 */
async function resolveHostname(hostname, timeout = 1500) {
  try {
    return await withTimeout(dns.resolve(hostname), timeout, []);
  } catch {
    return [];
  }
}

module.exports = {
  getHostname,
  resolveHostname,
};