/**
 * speedtest.js
 * ----------------
 * Internet speed test: ping latency + download/upload throughput,
 * measured against Cloudflare's public speed-test endpoints
 * (speed.cloudflare.com) — the same infrastructure Cloudflare's own
 * speed.cloudflare.com page uses. No API key required, but this does
 * make outbound requests to a third-party service.
 */

const crypto = require("crypto");
const axios = require("axios");
const { pingHost } = require("./ping");

const PING_TARGET = "1.1.1.1"; // Cloudflare's public DNS resolver
const DOWNLOAD_URL = "https://speed.cloudflare.com/__down";
const UPLOAD_URL = "https://speed.cloudflare.com/__up";

const DEFAULT_DOWNLOAD_BYTES = 10_000_000; // 10 MB
const DEFAULT_UPLOAD_BYTES = 5_000_000; // 5 MB

function mbps(bytes, ms) {
  if (ms <= 0) return 0;
  return Number(((bytes * 8) / (ms / 1000) / 1_000_000).toFixed(2));
}

/**
 * Measure round-trip latency to a well-known public host.
 * @returns {Promise<number|null>} milliseconds, or null if unreachable.
 */
async function measurePing() {
  const result = await pingHost(PING_TARGET, 2);
  return result.alive ? result.latency : null;
}

/**
 * Download a fixed-size payload from Cloudflare's speed-test endpoint
 * and measure throughput.
 * @param {number} [bytes=DEFAULT_DOWNLOAD_BYTES]
 * @returns {Promise<number>} Mbps
 */
async function measureDownload(bytes = DEFAULT_DOWNLOAD_BYTES) {
  const start = Date.now();
  const res = await axios.get(DOWNLOAD_URL, {
    params: { bytes },
    responseType: "arraybuffer",
    timeout: 20000,
  });
  const elapsedMs = Date.now() - start;
  return mbps(res.data.length, elapsedMs);
}

/**
 * Upload a fixed-size random payload to Cloudflare's speed-test endpoint
 * and measure throughput.
 * @param {number} [bytes=DEFAULT_UPLOAD_BYTES]
 * @returns {Promise<number>} Mbps
 */
async function measureUpload(bytes = DEFAULT_UPLOAD_BYTES) {
  const payload = crypto.randomBytes(bytes);
  const start = Date.now();
  await axios.post(UPLOAD_URL, payload, {
    headers: { "Content-Type": "application/octet-stream" },
    timeout: 20000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
  });
  const elapsedMs = Date.now() - start;
  return mbps(bytes, elapsedMs);
}

/**
 * Run a full internet speed test: ping, then download, then upload —
 * sequential so each measurement isn't skewed by the others competing
 * for the same bandwidth.
 * @param {object} [options]
 * @param {number} [options.downloadBytes]
 * @param {number} [options.uploadBytes]
 * @param {(phase: "ping"|"download"|"upload") => void} [options.onPhase]
 * @returns {Promise<{pingMs: number|null, downloadMbps: number, uploadMbps: number, testedAt: string}>}
 */
async function runSpeedTest(options = {}) {
  const { downloadBytes, uploadBytes, onPhase } = options;

  if (onPhase) onPhase("ping");
  const pingMs = await measurePing();

  if (onPhase) onPhase("download");
  const downloadMbps = await measureDownload(downloadBytes);

  if (onPhase) onPhase("upload");
  const uploadMbps = await measureUpload(uploadBytes);

  return { pingMs, downloadMbps, uploadMbps, testedAt: new Date().toISOString() };
}

module.exports = {
  runSpeedTest,
  measurePing,
  measureDownload,
  measureUpload,
};
