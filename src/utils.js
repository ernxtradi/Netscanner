/**
 * utils.js
 * ----------------
 * Shared helpers used across the scanner modules.
 */

/**
 * Run an array of task factories with a concurrency cap.
 * Each task is a zero-arg function returning a Promise.
 * @param {Array<() => Promise<any>>} tasks
 * @param {number} limit - Max number of tasks running at once.
 * @returns {Promise<any[]>} Results in the same order as `tasks`.
 */
async function runWithConcurrency(tasks, limit) {
  if (!Array.isArray(tasks) || tasks.length === 0) return [];

  const results = new Array(tasks.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < tasks.length) {
      const current = nextIndex++;
      try {
        results[current] = await tasks[current]();
      } catch (err) {
        results[current] = { error: err.message };
      }
    }
  }

  const workerCount = Math.max(1, Math.min(limit, tasks.length));
  const workers = Array.from({ length: workerCount }, worker);
  await Promise.all(workers);
  return results;
}

/**
 * Convert a dotted IPv4 string to a 32-bit unsigned integer.
 * @param {string} ip
 * @returns {number}
 */
function ipToInt(ip) {
  return ip
    .split(".")
    .reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

/**
 * Convert a 32-bit unsigned integer back to a dotted IPv4 string.
 * @param {number} int
 * @returns {string}
 */
function intToIp(int) {
  return [24, 16, 8, 0].map((shift) => (int >>> shift) & 255).join(".");
}

module.exports = {
  runWithConcurrency,
  ipToInt,
  intToIp,
};