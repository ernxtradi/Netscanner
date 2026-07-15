const os = require("os");
const ping = require("ping");

// The `ping` npm package's `extra` option is passed straight through to the
// system ping binary, so the flags must match the OS. The original code
// hardcoded `-c` (count), which Windows' ping.exe doesn't understand
// (it uses `-n`) — every ping on Windows would have silently failed.
const isWindows = os.platform() === "win32";
const extraArgs = isWindows ? ["-n", "1"] : ["-c", "1"];

/**
 * Ping a single host.
 * @param {string} ip
 * @param {number} [timeoutSeconds=1] - Timeout in seconds (per the `ping` lib's convention).
 * @returns {Promise<{ip: string, alive: boolean, latency: (number|null), output: (string|undefined), error: (string|undefined)}>}
 */
async function pingHost(ip, timeoutSeconds = 1) {
  try {
    const res = await ping.promise.probe(ip, {
      timeout: timeoutSeconds,
      extra: extraArgs,
    });

    return {
      ip,
      alive: res.alive,
      latency: res.time,
      output: res.output,
    };
  } catch (err) {
    return {
      ip,
      alive: false,
      latency: null,
      error: err.message,
    };
  }
}

module.exports = {
  pingHost,
};