const { scan } = require("./scanner");
const { getHostRange } = require("./subnet");
const { startMonitoring } = require("./monitor");
const report = require("./report");

function printHost(host) {
  console.log(`

========================================
HOST ONLINE
========================================
IP        : ${host.ip}
Hostname  : ${host.hostname}
MAC       : ${host.mac}
Vendor    : ${host.vendor}
Type      : ${host.deviceType}
Latency   : ${host.latency}
Ports     : ${
    host.openPorts.length
      ? host.openPorts.map((p) => `${p.port}/${p.protocol || "tcp"} (${p.service})`).join(", ")
      : "None"
  }
========================================`);
}

function printProgress(ip, scanned, total) {
  process.stdout.write(`\rScanning ${scanned}/${total} : ${ip}          `);
}

function printChange(change) {
  const { type, host } = change;
  if (type === "new") {
    console.log(`\n[+] NEW DEVICE ONLINE: ${host.ip} (${host.hostname}) — ${host.deviceType}`);
  } else if (type === "offline") {
    console.log(`\n[-] DEVICE OFFLINE: ${host.ip} (${host.hostname})`);
  } else if (type === "changed") {
    console.log(`\n[~] DEVICE CHANGED: ${host.ip} (${host.hostname})`);
    for (const c of change.changes) {
      if (c.field === "openPorts") {
        if (c.added) console.log(`      + ports opened: ${c.added.join(", ")}`);
        if (c.removed) console.log(`      - ports closed: ${c.removed.join(", ")}`);
      } else {
        console.log(`      ${c.field}: ${c.from} -> ${c.to}`);
      }
    }
  }
}

/**
 * One-shot scan: print the subnet banner, run scan() with console-output
 * callbacks, save reports, print the summary table.
 */
async function runOneShotScan() {
  const { subnet, ips, range, capped } = getHostRange();

  console.log(`\nSubnet detected: ${range.network}/${range.cidr}`);
  if (capped) {
    console.log(
      `Note: subnet has ${range.totalHosts} usable hosts; capping scan to the first ${ips.length} for safety.`
    );
  }
  console.log(`\nScanning ${ips.length} host(s)\n`);

  const result = await scan({
    ips,
    onProgress: printProgress,
    onHost: printHost,
  });

  const paths = report.saveAll(result.hosts, { subnet, durationSec: result.durationSec });

  console.log("\n\n==================================");
  console.log("SCAN COMPLETE");
  console.log("==================================");
  console.log(`Subnet        : ${range.network}/${range.cidr}`);
  console.log(`Gateway       : ${result.gatewayIp}`);
  console.log(`Hosts Online  : ${result.hosts.length}`);
  console.log(`Hosts Scanned : ${ips.length}`);
  console.log(`Time Taken    : ${result.durationSec} sec`);
  console.log(`\nReports saved:`);
  console.log(`  JSON : ${paths.json}`);
  console.log(`  CSV  : ${paths.csv}`);
  console.log(`  HTML : ${paths.html}`);

  console.table(
    result.hosts.map((h) => ({
      ip: h.ip,
      hostname: h.hostname,
      vendor: h.vendor,
      type: h.deviceType,
      latency: h.latency,
      ports: h.openPorts.length,
    }))
  );
}

/**
 * Continuous monitoring: scan on an interval, print a summary table each
 * cycle and log new/offline/changed devices as they're detected.
 */
async function runMonitor(intervalMs) {
  console.log(`\nStarting continuous monitoring (every ${intervalMs / 1000}s). Press Ctrl+C to stop.\n`);

  startMonitoring({
    intervalMs,
    onChange: printChange,
    onScanComplete: (result) => {
      console.log(`\n\n[${new Date().toLocaleTimeString()}] Scan cycle complete — ${result.hosts.length} host(s) online (${result.durationSec}s)`);
      console.table(
        result.hosts.map((h) => ({
          ip: h.ip,
          hostname: h.hostname,
          vendor: h.vendor,
          type: h.deviceType,
          latency: h.latency,
          ports: h.openPorts.length,
        }))
      );
    },
  });
}

function parseArgs(argv) {
  const monitor = argv.includes("--monitor");
  const intervalArg = argv.find((a) => a.startsWith("--interval="));
  const intervalMs = intervalArg ? Number(intervalArg.split("=")[1]) : 60000;
  return { monitor, intervalMs };
}

async function main() {
  console.clear();
  console.log("==================================");
  console.log("      Node Network Scanner");
  console.log("==================================");

  const { monitor, intervalMs } = parseArgs(process.argv.slice(2));

  try {
    if (monitor) {
      await runMonitor(intervalMs);
    } else {
      await runOneShotScan();
    }
  } catch (err) {
    console.error(err);
    process.exitCode = 1;
  }
}

main();
