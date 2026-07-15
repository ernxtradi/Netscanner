/**
 * classify.js
 * ----------------
 * Best-effort device classification based on hostname, vendor, and
 * open ports. This is heuristic, not authoritative — treat the output
 * as a labeled guess for a network inventory view, not ground truth.
 */

const RULES = [
  {
    type: "Router / Gateway",
    test: ({ hostname, ports, isGateway }) =>
      isGateway || /router|gateway|.*fi\b/i.test(hostname) || (ports.includes(80) && ports.includes(53)),
  },
  {
    type: "Printer",
    test: ({ hostname, ports }) => ports.includes(631) || ports.includes(515) || /printer|epson|canon|hp[-_ ]/i.test(hostname),
  },
  {
    type: "Windows Computer",
    test: ({ ports }) => ports.includes(3389) || ports.includes(445) || ports.includes(135),
  },
  {
    type: "Linux / Unix Server",
    test: ({ ports }) => ports.includes(22) && !ports.includes(3389),
  },
  {
    type: "Database Server",
    test: ({ ports }) => [3306, 5432, 1433, 27017, 6379].some((p) => ports.includes(p)),
  },
  {
    type: "Web Server",
    test: ({ ports }) => [80, 443, 8080, 8443].some((p) => ports.includes(p)),
  },
  {
    type: "Apple Device",
    test: ({ vendor }) => /apple/i.test(vendor || ""),
  },
  {
    type: "IoT / Smart Home Device",
    test: ({ vendor }) => /espressif|sonos|amazon|nest|ring|ecobee/i.test(vendor || ""),
  },
  {
    type: "Raspberry Pi",
    test: ({ vendor }) => /raspberry pi/i.test(vendor || ""),
  },
];

/**
 * Classify a scanned host.
 * @param {object} host
 * @param {string} [host.hostname]
 * @param {string} [host.vendor]
 * @param {Array<{port: number}>} [host.openPorts]
 * @param {boolean} [host.isGateway] - Pass true if this IP is the default gateway.
 * @returns {{type: string, matchedRules: string[]}}
 */
function classifyDevice(host) {
  const hostname = host.hostname && host.hostname !== "Unknown" ? host.hostname : "";
  const vendor = host.vendor || "";
  const ports = (host.openPorts || []).map((p) => p.port);
  const isGateway = Boolean(host.isGateway);

  const context = { hostname, vendor, ports, isGateway };
  const matched = RULES.filter((rule) => rule.test(context)).map((rule) => rule.type);

  return {
    type: matched[0] || "Unknown Device",
    matchedRules: matched,
  };
}

module.exports = {
  classifyDevice,
};