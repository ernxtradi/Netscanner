/**
 * capture.js
 * ----------------
 * Live packet capture and per-device traffic accounting: bytes/packets in
 * and out, protocol breakdown (TCP/UDP/ICMP/ARP/other), live Mbps
 * throughput, and ports observed in live traffic for every IP seen on
 * the wire.
 *
 * VISIBILITY LIMITATION — read before relying on this: on a normal
 * switched LAN, a capture on this host only sees traffic to/from *this*
 * host, plus broadcast/multicast frames (ARP, mDNS, SSDP, DHCP, etc.).
 * It does NOT see traffic between two *other* devices unless this host
 * is the gateway/router, or the switch port it's on is mirrored/SPANned.
 * Treat live stats for hosts other than this machine as partial —
 * broadcast/multicast visibility only, not their full traffic.
 *
 * PROCESS ISOLATION — why this file forks a child (captureWorker.js)
 * instead of opening the capture inline: the native `cap`/libpcap
 * binding has been observed to SIGSEGV during live capture. A native
 * crash can only be caught by the OS, not by JS try/catch, and it takes
 * down whatever process it happens in. Running the actual capture in a
 * forked child means that crash kills the (disposable, respawnable)
 * child — never this process or the rest of the dashboard server. This
 * module supervises that child: relays its stats, and turns an
 * unexpected exit (including death by signal) into a bounded, backed-off
 * restart, or a reported error once restarts are exhausted.
 *
 * REQUIREMENTS:
 *   - libpcap + headers on the OS (e.g. `apt install libpcap-dev`) so the
 *     native `cap` package can build — `npm install cap`.
 *   - Permission to open a live capture: run as root, or grant the node
 *     binary the capability directly:
 *       sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f $(which node))"
 *   Both are best-effort — missing either produces a reported error via
 *   onError, never a crash of the caller.
 */

const path = require("path");
const { fork } = require("child_process");
const { getInterfaces } = require("./subnet");

const WORKER_PATH = path.join(__dirname, "captureWorker.js");
const MAX_RESTARTS = 3;
const RESTART_DELAY_MS = 1500;
// If the worker survives at least this long before crashing, its next
// crash is treated as a fresh, unrelated problem (restart budget is
// forgiven) rather than counted against the crash-loop limit above.
// Without this, a worker that runs briefly and sends stats before every
// crash (observed: opens fine, captures for a while, then SIGSEGVs)
// would never accumulate toward MAX_RESTARTS and would respawn forever.
const HEALTHY_UPTIME_MS = 10000;

/**
 * Best-effort check for whether packet capture is usable in this
 * environment, without throwing. Does NOT check for capture permission
 * or native stability (only knowable by actually trying to open a
 * device, which is what the forked worker does).
 * @returns {{available: boolean, reason?: string}}
 */
function checkAvailable() {
  try {
    require("cap");
    return { available: true };
  } catch (err) {
    return {
      available: false,
      reason:
        "The 'cap' native module isn't installed/built. Install libpcap headers and the package: " +
        "sudo apt-get install libpcap-dev && npm install cap (" + err.message + ")",
    };
  }
}

/**
 * List capture-able network devices as libpcap sees them (distinct from
 * the OS interface names subnet.js reports).
 * @returns {Array<object>}
 */
function listDevices() {
  const { Cap } = require("cap");
  return Cap.deviceList();
}

/**
 * Start a supervised, isolated capture session.
 *
 * @param {object} [options]
 * @param {string} [options.filter="ip or arp"] - BPF filter expression.
 * @param {number} [options.statsIntervalMs=2000] - How often onStats fires.
 * @param {(snapshot: {totals: object, hosts: object[]}) => void} [options.onStats]
 * @param {(err: Error) => void} [options.onError] - Called for both
 *   explicit failures (missing module, no device, permission denied) and
 *   unexpected crashes (after restarts are exhausted). The session is
 *   over once this fires — isRunning() will report false.
 * @returns {{stop(): void, isRunning(): boolean}}
 * @throws {Error} synchronously only if no local network interface can
 *   be found at all — everything capture-specific is reported async via
 *   onError instead, since opening a device happens in the child.
 */
function startCapture(options = {}) {
  const { filter = "ip or arp", statsIntervalMs = 2000, onStats, onError } = options;

  const interfaces = getInterfaces();
  if (interfaces.length === 0) {
    throw new Error("startCapture: no active network interface found.");
  }
  const localIp = interfaces[0].ip;

  let child = null;
  let intentionalStop = false;
  let restartCount = 0;
  let restartTimer = null;

  function report(err) {
    intentionalStop = true; // terminal — caller must call startCapture() again to retry
    if (onError) onError(err);
  }

  function spawn() {
    const startedAt = Date.now();
    child = fork(WORKER_PATH, [JSON.stringify({ localIp, filter, statsIntervalMs })]);

    child.on("message", (msg) => {
      if (!msg) return;
      if (msg.type === "stats") {
        if (onStats) onStats(msg.snapshot);
      } else if (msg.type === "error") {
        // Explicit, non-crash failure (bad config/permissions/missing module)
        // — retrying won't help, so this is terminal.
        report(new Error(msg.message));
      }
    });

    child.on("exit", (code, signal) => {
      if (intentionalStop) return; // stop() was called, or report() already handled it

      if (Date.now() - startedAt >= HEALTHY_UPTIME_MS) {
        restartCount = 0; // was healthy for a while — don't penalize this crash
      }

      if (restartCount >= MAX_RESTARTS) {
        report(
          new Error(
            `Packet capture crashed repeatedly (last: ${signal ? `signal ${signal}` : `exit code ${code}`}) ` +
            `and was not restarted after ${MAX_RESTARTS} attempts. This points to instability in the ` +
            "underlying pcap library on this system."
          )
        );
        return;
      }

      restartCount++;
      restartTimer = setTimeout(spawn, RESTART_DELAY_MS);
    });
  }

  spawn();

  return {
    stop() {
      if (intentionalStop) return;
      intentionalStop = true;
      if (restartTimer) clearTimeout(restartTimer);
      if (child) {
        child.removeAllListeners();
        child.kill("SIGTERM");
      }
    },
    isRunning() {
      return !intentionalStop;
    },
  };
}

module.exports = {
  checkAvailable,
  listDevices,
  startCapture,
};
