const socket = io();

const GROUP_COLORS = {
  "router-gateway": "#f97316",
  "printer": "#a855f7",
  "windows-computer": "#38bdf8",
  "linux-unix-server": "#22c55e",
  "database-server": "#eab308",
  "web-server": "#06b6d4",
  "apple-device": "#e5e7eb",
  "iot-smart-home-device": "#ec4899",
  "raspberry-pi": "#dc2626",
  "unknown-device": "#94a3b8",
};

const scanBtn = document.getElementById("scan-btn");
const monitorToggle = document.getElementById("monitor-toggle");
const monitorInterval = document.getElementById("monitor-interval");
const captureToggle = document.getElementById("capture-toggle");
const statusPill = document.getElementById("status-pill");
const subnetInfo = document.getElementById("subnet-info");
const hostCountEl = document.getElementById("host-count");
const tableBody = document.querySelector("#host-table tbody");
const reportLinks = document.getElementById("report-links");
const changeLog = document.getElementById("change-log");
const topologyEl = document.getElementById("topology");
const trafficSummary = document.getElementById("traffic-summary");
const trafficBody = document.querySelector("#traffic-table tbody");
const captureMessage = document.getElementById("capture-message");
const speedtestBtn = document.getElementById("speedtest-btn");
const speedtestBar = document.getElementById("speedtest-bar");

let network = null;
let nodesDataSet = new vis.DataSet([]);
let edgesDataSet = new vis.DataSet([]);
let rows = new Map(); // ip -> host, for live table upserts during a scan

function setStatus(text) {
  statusPill.textContent = text;
}

function renderTable(hostsMap) {
  tableBody.innerHTML = "";
  for (const h of hostsMap.values()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${h.ip}</td>
      <td>${h.hostname}</td>
      <td>${h.mac}</td>
      <td>${h.vendor}</td>
      <td>${h.deviceType}</td>
      <td>${h.latency}</td>
      <td>${(h.openPorts || []).map((p) => `${p.port}/${p.protocol || "tcp"}(${p.service})`).join(", ") || "—"}</td>
    `;
    tableBody.appendChild(tr);
  }
  hostCountEl.textContent = `(${hostsMap.size})`;
}

function renderTopology(topology) {
  nodesDataSet.clear();
  edgesDataSet.clear();
  nodesDataSet.add(
    topology.nodes.map((n) => ({
      ...n,
      color: GROUP_COLORS[n.group] || GROUP_COLORS["unknown-device"],
    }))
  );
  edgesDataSet.add(topology.edges);

  if (!network) {
    network = new vis.Network(
      topologyEl,
      { nodes: nodesDataSet, edges: edgesDataSet },
      {
        physics: { stabilization: true, barnesHut: { springLength: 120 } },
        nodes: { font: { color: "#e5e7eb" }, borderWidth: 1 },
        edges: { color: "#475569", smooth: false },
      }
    );
  }
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function renderTraffic(snapshot) {
  const { totals, hosts } = snapshot;
  trafficSummary.textContent = `(${totals.packets} pkts, ${formatBytes(totals.bytes)} — ` +
    `tcp ${totals.tcp} · udp ${totals.udp} · icmp ${totals.icmp} · arp ${totals.arp} · other ${totals.other})`;

  trafficBody.innerHTML = "";
  for (const h of hosts) {
    const tr = document.createElement("tr");
    const ports = (h.ports || []).map((p) => p.key).join(", ") || "—";
    tr.innerHTML = `
      <td>${h.ip}${h.isLocal ? " (this host)" : ""}</td>
      <td>${formatBytes(h.bytesSent)} / ${h.packetsSent} pkt</td>
      <td>${formatBytes(h.bytesReceived)} / ${h.packetsReceived} pkt</td>
      <td>${(h.mbpsSent || 0).toFixed(2)} Mbps</td>
      <td>${(h.mbpsReceived || 0).toFixed(2)} Mbps</td>
      <td>${h.tcp || 0}</td>
      <td>${h.udp || 0}</td>
      <td>${h.icmp || 0}</td>
      <td>${h.other || 0}</td>
      <td>${ports}</td>
      <td>${new Date(h.lastSeen).toLocaleTimeString()}</td>
    `;
    trafficBody.appendChild(tr);
  }
}

function renderReportLinks(paths) {
  if (!paths) {
    reportLinks.innerHTML = "";
    return;
  }
  reportLinks.innerHTML = `Reports:
    <a href="/${paths.json}" target="_blank">JSON</a> ·
    <a href="/${paths.csv}" target="_blank">CSV</a> ·
    <a href="/${paths.html}" target="_blank">HTML</a>`;
}

function logChange(change) {
  const li = document.createElement("li");
  const time = new Date().toLocaleTimeString();
  if (change.type === "new") {
    li.textContent = `[${time}] + NEW  ${change.host.ip} (${change.host.hostname}) — ${change.host.deviceType}`;
    li.className = "log-new";
  } else if (change.type === "offline") {
    li.textContent = `[${time}] - OFFLINE  ${change.host.ip} (${change.host.hostname})`;
    li.className = "log-offline";
  } else {
    const summary = change.changes
      .map((c) => (c.field === "openPorts" ? `ports ${c.added ? "opened " + c.added.join(",") : "closed " + c.removed.join(",")}` : `${c.field}: ${c.from} -> ${c.to}`))
      .join("; ");
    li.textContent = `[${time}] ~ CHANGED  ${change.host.ip} — ${summary}`;
    li.className = "log-changed";
  }
  changeLog.prepend(li);
}

scanBtn.addEventListener("click", () => {
  socket.emit("scan:start");
});

monitorToggle.addEventListener("change", () => {
  if (monitorToggle.checked) {
    socket.emit("monitor:start", { intervalMs: Number(monitorInterval.value) * 1000 });
  } else {
    socket.emit("monitor:stop");
  }
});

captureToggle.addEventListener("change", () => {
  captureMessage.textContent = "";
  if (captureToggle.checked) {
    socket.emit("capture:start");
  } else {
    socket.emit("capture:stop");
  }
});

speedtestBtn.addEventListener("click", () => {
  socket.emit("speedtest:run");
});

socket.on("scan:progress", ({ ip, scanned, total }) => {
  setStatus(`scanning ${scanned}/${total} (${ip})`);
});

socket.on("scan:host", ({ host }) => {
  rows.set(host.ip, host);
  renderTable(rows);
});

socket.on("scan:complete", (payload) => {
  rows = new Map(payload.hosts.map((h) => [h.ip, h]));
  renderTable(rows);
  renderTopology(payload.topology);
  renderReportLinks(payload.reportPaths);
  subnetInfo.textContent = `${payload.subnet}.0/${payload.range.cidr} — gateway ${payload.gatewayIp}`;
  setStatus(payload.source === "monitor" ? "monitoring" : "idle");
});

socket.on("scan:error", ({ message }) => {
  setStatus(`error: ${message}`);
});

socket.on("monitor:status", ({ running, intervalMs }) => {
  monitorToggle.checked = running;
  monitorInterval.value = Math.round(intervalMs / 1000);
  if (running) setStatus("monitoring");
});

socket.on("monitor:change", logChange);

socket.on("capture:status", ({ running, available, reason }) => {
  captureToggle.checked = running;
  captureToggle.disabled = !available && !running;
  captureMessage.textContent = !available ? reason || "Packet capture is unavailable." : "";
});

socket.on("capture:stats", renderTraffic);

socket.on("capture:error", ({ message }) => {
  captureToggle.checked = false;
  captureMessage.textContent = message;
});

socket.on("speedtest:status", ({ running }) => {
  speedtestBtn.disabled = running;
  speedtestBtn.textContent = running ? "Testing…" : "Speed Test";
});

socket.on("speedtest:phase", ({ phase }) => {
  speedtestBar.textContent = `Speed test: ${phase}…`;
});

socket.on("speedtest:result", ({ pingMs, downloadMbps, uploadMbps, testedAt }) => {
  const ping = pingMs != null ? `${pingMs} ms` : "N/A (ICMP blocked?)";
  speedtestBar.textContent =
    `Internet speed — ping: ${ping} · download: ${downloadMbps} Mbps · upload: ${uploadMbps} Mbps ` +
    `(${new Date(testedAt).toLocaleTimeString()})`;
});

socket.on("speedtest:error", ({ message }) => {
  speedtestBar.textContent = `Speed test failed: ${message}`;
});

fetch("/api/interfaces")
  .then((r) => r.json())
  .then((interfaces) => {
    if (interfaces[0]) {
      subnetInfo.textContent = `${interfaces[0].subnet}.0 (${interfaces[0].interface}) — click Start Scan`;
    }
  })
  .catch(() => {});
