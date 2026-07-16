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
const statusPill = document.getElementById("status-pill");
const subnetInfo = document.getElementById("subnet-info");
const hostCountEl = document.getElementById("host-count");
const tableBody = document.querySelector("#host-table tbody");
const reportLinks = document.getElementById("report-links");
const changeLog = document.getElementById("change-log");
const topologyEl = document.getElementById("topology");

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
      <td>${(h.openPorts || []).map((p) => `${p.port}(${p.service})`).join(", ") || "—"}</td>
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

fetch("/api/interfaces")
  .then((r) => r.json())
  .then((interfaces) => {
    if (interfaces[0]) {
      subnetInfo.textContent = `${interfaces[0].subnet}.0 (${interfaces[0].interface}) — click Start Scan`;
    }
  })
  .catch(() => {});
