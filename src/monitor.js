/**
 * monitor.js
 * ----------------
 * Continuous monitoring: re-scan the subnet on an interval and diff
 * each new result against the previous one to detect devices going
 * online/offline or changing (hostname, MAC, vendor, classification,
 * open ports).
 */

const { scan } = require("./scanner");

/**
 * Diff the mutable properties of a host between two scans.
 * @param {object} prev
 * @param {object} curr
 * @returns {Array<object>}
 */
function diffHostProps(prev, curr) {
  const diffs = [];

  for (const field of ["hostname", "mac", "vendor", "deviceType"]) {
    if (prev[field] !== curr[field]) {
      diffs.push({ field, from: prev[field], to: curr[field] });
    }
  }

  const prevPorts = new Set((prev.openPorts || []).map((p) => p.port));
  const currPorts = new Set((curr.openPorts || []).map((p) => p.port));
  const added = [...currPorts].filter((p) => !prevPorts.has(p));
  const removed = [...prevPorts].filter((p) => !currPorts.has(p));

  if (added.length) diffs.push({ field: "openPorts", added });
  if (removed.length) diffs.push({ field: "openPorts", removed });

  return diffs;
}

/**
 * Diff two scans' host lists (keyed by IP) into change events.
 * @param {Map<string, object>} previousMap
 * @param {Map<string, object>} currentMap
 * @returns {Array<{type: "new"|"offline"|"changed", host: object, previous?: object, changes?: object[]}>}
 */
function diffHosts(previousMap, currentMap) {
  const changes = [];

  for (const [ip, host] of currentMap) {
    if (!previousMap.has(ip)) {
      changes.push({ type: "new", host });
      continue;
    }
    const previous = previousMap.get(ip);
    const changed = diffHostProps(previous, host);
    if (changed.length) changes.push({ type: "changed", host, previous, changes: changed });
  }

  for (const [ip, host] of previousMap) {
    if (!currentMap.has(ip)) changes.push({ type: "offline", host });
  }

  return changes;
}

/**
 * Start continuous monitoring: scan on a recurring interval, diffing
 * each result against the previous one.
 *
 * Uses a recursive setTimeout (not setInterval) — scan duration varies
 * with subnet size and can exceed intervalMs, and setInterval would let
 * scans pile up/overlap. Rescheduling only after a tick fully completes
 * guarantees exactly one in-flight scan at a time.
 *
 * @param {object} [options]
 * @param {number} [options.intervalMs=60000]
 * @param {(result: object) => void} [options.onScanComplete] - scan()'s return value, each tick.
 * @param {(change: object) => void} [options.onChange] - called once per detected change.
 * @param {object} [options.scanOptions] - forwarded to scan().
 * @returns {{stop(): void, isRunning(): boolean}}
 */
function startMonitoring({ intervalMs = 60000, onScanComplete, onChange, scanOptions = {} } = {}) {
  let previousHosts = null;
  let timer = null;
  let ticking = false;
  let stopped = false;

  async function tick() {
    if (ticking) return;
    ticking = true;
    try {
      const result = await scan(scanOptions);
      const currentMap = new Map(result.hosts.map((h) => [h.ip, h]));

      if (previousHosts) {
        for (const change of diffHosts(previousHosts, currentMap)) {
          if (onChange) onChange(change);
        }
      }
      previousHosts = currentMap;
      if (onScanComplete) onScanComplete(result);
    } catch {
      // A single bad tick shouldn't kill the monitor loop.
    } finally {
      ticking = false;
      if (!stopped) timer = setTimeout(tick, intervalMs);
    }
  }

  timer = setTimeout(tick, 0);

  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
    },
    isRunning() {
      return ticking;
    },
  };
}

module.exports = {
  startMonitoring,
  diffHosts,
  diffHostProps,
};
