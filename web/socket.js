/**
 * socket.js
 * ----------------
 * Socket.IO connection handling. Holds the shared, server-side scan/
 * monitor state and broadcasts it to every connected client — there's
 * one scan/monitor "session" for the whole dashboard, not one per tab.
 */

const { scan } = require("../src/scanner");
const { startMonitoring } = require("../src/monitor");
const { buildTopology } = require("../src/topology");
const capture = require("../src/capture");
const { runSpeedTest } = require("../src/speedtest");
const report = require("../src/report");

let latestResult = null; // last scan:complete payload
let scanInFlight = false;
let scanCounter = 0;
let monitorHandle = null;
let monitorIntervalMs = 60000;
let captureHandle = null;
let speedTestInFlight = false;

function buildCompletePayload(result, { source, saveReports }) {
  const reportPaths = saveReports ? report.saveAll(result.hosts, { subnet: result.subnet, durationSec: result.durationSec }) : null;
  const topology = buildTopology(result.hosts, result.gatewayIp);

  return {
    scanId: scanCounter,
    source,
    subnet: result.subnet,
    range: result.range,
    gatewayIp: result.gatewayIp,
    durationSec: result.durationSec,
    hostCount: result.hosts.length,
    hosts: result.hosts,
    reportPaths,
    topology,
  };
}

function registerSocketHandlers(io) {
  async function runScan({ source, saveReports }) {
    scanCounter++;
    const scanId = scanCounter;
    scanInFlight = true;

    try {
      const result = await scan({
        onProgress: (ip, scanned, total) => {
          io.emit("scan:progress", { scanId, ip, scanned, total });
        },
        onHost: (host) => {
          io.emit("scan:host", { scanId, host });
        },
      });

      const payload = buildCompletePayload(result, { source, saveReports });
      latestResult = payload;
      io.emit("scan:complete", payload);
      return result;
    } catch (err) {
      io.emit("scan:error", { scanId, message: err.message });
      throw err;
    } finally {
      scanInFlight = false;
    }
  }

  io.on("connection", (socket) => {
    if (latestResult) socket.emit("scan:complete", latestResult);
    socket.emit("monitor:status", { running: Boolean(monitorHandle), intervalMs: monitorIntervalMs });
    socket.emit("capture:status", { running: Boolean(captureHandle), ...capture.checkAvailable() });

    socket.on("scan:start", async () => {
      if (scanInFlight || (monitorHandle && monitorHandle.isRunning())) {
        socket.emit("scan:error", { scanId: scanCounter, message: "A scan is already in progress." });
        return;
      }
      try {
        await runScan({ source: "manual", saveReports: true });
      } catch {
        // already broadcast via scan:error
      }
    });

    socket.on("monitor:start", ({ intervalMs } = {}) => {
      if (monitorHandle) return;
      monitorIntervalMs = Number(intervalMs) > 0 ? Number(intervalMs) : monitorIntervalMs;

      monitorHandle = startMonitoring({
        intervalMs: monitorIntervalMs,
        scanOptions: {}, // monitor ticks skip if a manual scan is already in flight (checked below)
        onScanComplete: (result) => {
          scanCounter++;
          const payload = buildCompletePayload(result, { source: "monitor", saveReports: false });
          latestResult = payload;
          io.emit("scan:complete", payload);
        },
        onChange: (change) => {
          io.emit("monitor:change", change);
        },
      });

      io.emit("monitor:status", { running: true, intervalMs: monitorIntervalMs });
    });

    socket.on("monitor:stop", () => {
      if (!monitorHandle) return;
      monitorHandle.stop();
      monitorHandle = null;
      io.emit("monitor:status", { running: false, intervalMs: monitorIntervalMs });
    });

    socket.on("capture:start", () => {
      if (captureHandle) return;
      try {
        captureHandle = capture.startCapture({
          onStats: (snapshot) => io.emit("capture:stats", snapshot),
        });
        io.emit("capture:status", { running: true, ...capture.checkAvailable() });
      } catch (err) {
        captureHandle = null;
        socket.emit("capture:error", { message: err.message });
        io.emit("capture:status", { running: false, ...capture.checkAvailable() });
      }
    });

    socket.on("capture:stop", () => {
      if (!captureHandle) return;
      captureHandle.stop();
      captureHandle = null;
      io.emit("capture:status", { running: false, ...capture.checkAvailable() });
    });

    socket.on("speedtest:run", async () => {
      if (speedTestInFlight) return;
      speedTestInFlight = true;
      io.emit("speedtest:status", { running: true });
      try {
        const result = await runSpeedTest({
          onPhase: (phase) => io.emit("speedtest:phase", { phase }),
        });
        io.emit("speedtest:result", result);
      } catch (err) {
        io.emit("speedtest:error", { message: err.message });
      } finally {
        speedTestInFlight = false;
        io.emit("speedtest:status", { running: false });
      }
    });
  });
}

module.exports = {
  registerSocketHandlers,
  getLatestResult: () => latestResult,
};
