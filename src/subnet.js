const os = require("os");
const { ipToInt, intToIp } = require("./utils");

// Safety cap so a misread netmask (e.g. a /8) can't trigger scanning
// millions of hosts by accident.
const MAX_SCANNABLE_HOSTS = 4096;

/**
 * Returns all active, non-internal IPv4 interfaces.
 */
function getInterfaces() {
  const interfaces = os.networkInterfaces();
  const results = [];

  for (const name in interfaces) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        results.push({
          interface: name,
          ip: iface.address,
          subnet: iface.address.split(".").slice(0, 3).join("."),
          netmask: iface.netmask,
          mac: iface.mac,
        });
      }
    }
  }

  return results;
}

/**
 * Returns the first active interface's /24-style subnet prefix
 * (e.g. "192.168.0"). Kept for backwards compatibility with code
 * that only needs a /24 assumption.
 */
function getSubnet() {
  const interfaces = getInterfaces();
  if (interfaces.length === 0) {
    throw new Error("No active network interface found.");
  }
  return interfaces[0].subnet;
}

/**
 * Given an IP and netmask, calculate the real network range.
 * @param {string} ip
 * @param {string} netmask
 * @returns {{network: string, broadcast: string, firstHost: string, lastHost: string, totalHosts: number, cidr: number}}
 */
function calculateRange(ip, netmask) {
  const ipInt = ipToInt(ip);
  const maskInt = ipToInt(netmask);

  const networkInt = (ipInt & maskInt) >>> 0;
  const broadcastInt = (networkInt | (~maskInt >>> 0)) >>> 0;

  const cidr = netmask
    .split(".")
    .reduce((bits, octet) => bits + Number(octet).toString(2).split("1").length - 1, 0);

  const totalHosts = Math.max(broadcastInt - networkInt - 1, 0);

  return {
    network: intToIp(networkInt),
    broadcast: intToIp(broadcastInt),
    firstHost: intToIp(networkInt + 1),
    lastHost: intToIp(Math.max(broadcastInt - 1, networkInt)),
    totalHosts,
    cidr,
  };
}

/**
 * Returns the list of usable host IPs to scan on the first active
 * interface, based on its real netmask (not a hardcoded /24 assumption).
 * Falls back to a /24 sweep if the netmask can't be parsed, and always
 * caps the result at MAX_SCANNABLE_HOSTS for safety.
 * @returns {{ subnet: string, ips: string[], range: object, capped: boolean }}
 */
function getHostRange() {
  const interfaces = getInterfaces();
  if (interfaces.length === 0) {
    throw new Error("No active network interface found.");
  }

  const primary = interfaces[0];
  let range;

  try {
    range = calculateRange(primary.ip, primary.netmask);
  } catch {
    // Fallback: assume /24 if netmask parsing fails for any reason.
    range = calculateRange(primary.ip, "255.255.255.0");
  }

  const capped = range.totalHosts > MAX_SCANNABLE_HOSTS;
  const count = capped ? MAX_SCANNABLE_HOSTS : range.totalHosts;

  const startInt = ipToInt(range.firstHost);
  const ips = Array.from({ length: count }, (_, i) => intToIp(startInt + i));

  return { subnet: primary.subnet, ips, range, capped };
}

module.exports = {
  getSubnet,
  getInterfaces,
  calculateRange,
  getHostRange,
  MAX_SCANNABLE_HOSTS,
};