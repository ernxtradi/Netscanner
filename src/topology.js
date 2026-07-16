/**
 * topology.js
 * ----------------
 * Builds a { nodes, edges } graph from scan results, in the shape
 * vis-network's `new vis.Network(container, {nodes, edges}, options)`
 * accepts directly (plain arrays, no DataSet wrapping required).
 */

/**
 * Turn a device type / label into a stable, CSS/vis-group-safe slug.
 * @param {string} s
 * @returns {string}
 */
function slugify(s) {
  return String(s || "unknown-device")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

/**
 * Build a star topology: the gateway as hub, every other host as a leaf
 * with one edge back to the gateway.
 * @param {Array<object>} hosts - scan().hosts
 * @param {string} gatewayIp
 * @param {string|null} [localIp] - this machine's own IP, for a styling hint
 * @returns {{nodes: Array<object>, edges: Array<object>}}
 */
function buildTopology(hosts, gatewayIp, localIp = null) {
  const nodes = [];
  const edges = [];

  const gatewayHost = hosts.find((h) => h.ip === gatewayIp);

  nodes.push({
    id: gatewayIp,
    label: gatewayHost && gatewayHost.hostname !== "Unknown" ? gatewayHost.hostname : gatewayIp,
    group: gatewayHost ? slugify(gatewayHost.deviceType) : "router-gateway",
    shape: "hexagon",
    isGateway: true,
    title: gatewayHost
      ? `${gatewayHost.ip}\n${gatewayHost.vendor}\n${gatewayHost.deviceType}`
      : `${gatewayIp}\n(gateway — not directly reachable)`,
  });

  for (const host of hosts) {
    if (host.ip === gatewayIp) continue;

    nodes.push({
      id: host.ip,
      label: host.hostname !== "Unknown" ? host.hostname : host.ip,
      group: slugify(host.deviceType),
      shape: host.ip === localIp ? "star" : "dot",
      isSelf: host.ip === localIp,
      title: `${host.ip}\n${host.vendor}\n${host.deviceType}\nPorts: ${
        (host.openPorts || []).map((p) => p.port).join(", ") || "none"
      }`,
    });

    edges.push({ id: `${gatewayIp}-${host.ip}`, from: gatewayIp, to: host.ip });
  }

  return { nodes, edges };
}

module.exports = {
  buildTopology,
  slugify,
};
