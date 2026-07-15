/**
 * vendor.js
 * ----------------
 * MAC address vendor (OUI) lookup.
 *
 * Strategy:
 *   1. Check an in-memory cache (avoids repeat lookups within one scan).
 *   2. Check a small built-in table of common home/office network vendors
 *      (fast, no network call, no rate limit).
 *   3. Fall back to the free https://api.macvendors.com API for anything
 *      not in the local table.
 *
 * Caveats:
 *   - The local OUI table below is a small, illustrative starter set, not
 *     the full IEEE registry — treat unmatched vendors as "unknown" rather
 *     than assuming absence means anything.
 *   - api.macvendors.com is a free third-party service with a rate limit
 *     (~1 request/sec on the free tier). This module debounces requests
 *     and caches results in-memory, but for large subnet scans expect
 *     some lookups to come back "Unknown Vendor" if you're rate-limited.
 *     If you need guaranteed offline accuracy, download the official
 *     IEEE OUI registry (https://standards-oui.ieee.org/) and load it
 *     via loadOuiTable() instead.
 */

const axios = require("axios");

// A small starter table of common OUIs (first 3 octets). Not authoritative —
// see caveats above. Format: "AA:BB:CC": "Vendor Name"
let OUI_TABLE = {
  "B8:27:EB": "Raspberry Pi Foundation",
  "DC:A6:32": "Raspberry Pi Foundation",
  "E4:5F:01": "Raspberry Pi Foundation",
  "F0:18:98": "Apple, Inc.",
  "A4:83:E7": "Apple, Inc.",
  "3C:15:C2": "Apple, Inc.",
  "00:1C:B3": "Apple, Inc.",
  "5C:0A:5B": "Samsung Electronics",
  "8C:79:F5": "Samsung Electronics",
  "50:C7:BF": "TP-Link Technologies",
  "98:DA:C4": "TP-Link Technologies",
  "A0:40:A0": "Netgear",
  "20:E5:2A": "Netgear",
  "00:1B:11": "D-Link Corporation",
  "14:D6:4D": "D-Link Corporation",
  "44:65:0D": "Amazon Technologies",
  "FC:65:DE": "Amazon Technologies",
  "54:60:09": "Google, Inc.",
  "F4:F5:D8": "Google, Inc.",
  "5C:AA:FD": "Sonos, Inc.",
  "24:A4:3C": "Ubiquiti Networks",
  "74:83:C2": "Ubiquiti Networks",
  "00:50:56": "VMware, Inc.",
  "00:15:5D": "Microsoft (Hyper-V)",
  "24:6F:28": "Espressif Inc. (IoT/ESP)",
  "30:AE:A4": "Espressif Inc. (IoT/ESP)",
};

const lookupCache = new Map();

// Simple request pacing so we don't slam the free API endpoint.
let lastRequestAt = 0;
const MIN_REQUEST_GAP_MS = 350;

function normalizeMac(mac) {
  return mac.replace(/-/g, ":").toUpperCase();
}

function ouiPrefix(mac) {
  return normalizeMac(mac).split(":").slice(0, 3).join(":");
}

/**
 * Merge additional OUI entries into the local table, e.g. loaded from
 * a downloaded IEEE registry file. Keys/values same shape as OUI_TABLE.
 * @param {Record<string,string>} entries
 */
function loadOuiTable(entries) {
  OUI_TABLE = { ...OUI_TABLE, ...entries };
}

async function queryMacVendorsApi(mac) {
  const wait = Math.max(0, MIN_REQUEST_GAP_MS - (Date.now() - lastRequestAt));
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  lastRequestAt = Date.now();

  try {
    const res = await axios.get(`https://api.macvendors.com/${mac}`, { timeout: 3000 });
    return typeof res.data === "string" ? res.data.trim() : null;
  } catch {
    // 404 (unknown vendor), 429 (rate limited), or network error — all
    // treated the same way: we just don't have an answer.
    return null;
  }
}

/**
 * Look up the vendor for a MAC address.
 * @param {string} mac
 * @param {object} [options]
 * @param {boolean} [options.useApi=true] - Fall back to the online API if not found locally.
 * @returns {Promise<string>} Vendor name, or "Unknown Vendor".
 */
async function getVendor(mac, options = {}) {
  const { useApi = true } = options;
  if (!mac || typeof mac !== "string") return "Unknown Vendor";

  const normalized = normalizeMac(mac);
  if (lookupCache.has(normalized)) return lookupCache.get(normalized);

  const localMatch = OUI_TABLE[ouiPrefix(normalized)];
  if (localMatch) {
    lookupCache.set(normalized, localMatch);
    return localMatch;
  }

  if (useApi) {
    const apiMatch = await queryMacVendorsApi(normalized);
    if (apiMatch) {
      lookupCache.set(normalized, apiMatch);
      return apiMatch;
    }
  }

  lookupCache.set(normalized, "Unknown Vendor");
  return "Unknown Vendor";
}

module.exports = {
  getVendor,
  loadOuiTable,
  OUI_TABLE,
};