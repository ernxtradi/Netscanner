/**
 * report.js
 * ----------------
 * Save scan results to disk as JSON, CSV, and a simple HTML report.
 */

const fs = require("fs");
const path = require("path");

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function csvEscape(value) {
  const str = String(value ?? "");
  return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

/**
 * Save hosts as a JSON file.
 * @param {Array<object>} hosts
 * @param {string} [dir="reports"]
 * @returns {string} The file path written.
 */
function saveJSON(hosts, dir = "reports") {
  ensureDir(dir);
  const filepath = path.join(dir, `scan-${Date.now()}.json`);
  fs.writeFileSync(filepath, JSON.stringify(hosts, null, 2));
  return filepath;
}

/**
 * Save hosts as a CSV file.
 * @param {Array<object>} hosts
 * @param {string} [dir="reports"]
 * @returns {string} The file path written.
 */
function saveCSV(hosts, dir = "reports") {
  ensureDir(dir);
  const filepath = path.join(dir, `scan-${Date.now()}.csv`);

  const headers = ["ip", "hostname", "mac", "vendor", "deviceType", "latency", "openPorts", "scannedAt"];
  const rows = hosts.map((h) =>
    headers
      .map((key) => {
        if (key === "openPorts") {
          return csvEscape((h.openPorts || []).map((p) => `${p.port}/${p.protocol || "tcp"}(${p.service})`).join("; "));
        }
        return csvEscape(h[key]);
      })
      .join(",")
  );

  fs.writeFileSync(filepath, [headers.join(","), ...rows].join("\n"));
  return filepath;
}

/**
 * Save hosts as a simple, self-contained HTML report.
 * @param {Array<object>} hosts
 * @param {object} [meta] - Extra info to show in the header (subnet, duration, etc.)
 * @param {string} [dir="reports"]
 * @returns {string} The file path written.
 */
function saveHTML(hosts, meta = {}, dir = "reports") {
  ensureDir(dir);
  const filepath = path.join(dir, `scan-${Date.now()}.html`);

  const escapeHtml = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const rows = hosts
    .map(
      (h) => `
      <tr>
        <td>${escapeHtml(h.ip)}</td>
        <td>${escapeHtml(h.hostname)}</td>
        <td>${escapeHtml(h.mac)}</td>
        <td>${escapeHtml(h.vendor)}</td>
        <td>${escapeHtml(h.deviceType)}</td>
        <td>${escapeHtml(h.latency)}</td>
        <td>${escapeHtml((h.openPorts || []).map((p) => `${p.port}/${p.protocol || "tcp"} (${p.service})`).join(", ") || "None")}</td>
      </tr>`
    )
    .join("");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Netscanner Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #555; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; }
  th { background: #f4f4f4; }
  tr:nth-child(even) { background: #fafafa; }
</style>
</head>
<body>
  <h1>Netscanner Report</h1>
  <div class="meta">
    ${meta.subnet ? `Subnet: ${escapeHtml(meta.subnet)}<br>` : ""}
    ${meta.durationSec ? `Duration: ${escapeHtml(meta.durationSec)}s<br>` : ""}
    Hosts online: ${hosts.length}<br>
    Generated: ${new Date().toLocaleString()}
  </div>
  <table>
    <thead>
      <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Latency</th><th>Open Ports</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;

  fs.writeFileSync(filepath, html);
  return filepath;
}

/**
 * Save all three report formats at once.
 * @param {Array<object>} hosts
 * @param {object} [meta]
 * @param {string} [dir="reports"]
 * @returns {{json: string, csv: string, html: string}}
 */
function saveAll(hosts, meta = {}, dir = "reports") {
  return {
    json: saveJSON(hosts, dir),
    csv: saveCSV(hosts, dir),
    html: saveHTML(hosts, meta, dir),
  };
}

module.exports = {
  saveJSON,
  saveCSV,
  saveHTML,
  saveAll,
};