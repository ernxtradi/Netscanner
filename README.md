# netscanner

A local network scanner: ping sweep → reverse DNS → ARP/MAC → vendor lookup →
TCP+UDP port scan → device classification, with JSON/CSV/HTML reports, a live
web dashboard with topology graph, continuous monitoring mode, and live
packet-capture traffic monitoring.

```
netscanner/
│
├── package.json
├── package-lock.json
├── README.md
├── .gitignore
│
├── src/
│   ├── index.js              # CLI entry point (one-shot scan or --monitor)
│   ├── scanner.js            # Reentrant scan() orchestration
│   ├── ping.js                # Ping hosts
│   ├── dns.js                 # Reverse DNS
│   ├── arp.js                 # MAC address discovery
│   ├── vendor.js               # Vendor (OUI) lookup
│   ├── gateway.js              # Default gateway detection
│   ├── subnet.js                # Network interface/subnet detection
│   ├── ports.js                 # TCP + UDP port scanner (with protocol/type tagging)
│   ├── classify.js              # Device classification
│   ├── topology.js              # Network graph (vis-network shape) builder
│   ├── monitor.js               # Continuous monitoring / change detection
│   ├── capture.js               # Live packet capture + per-device traffic stats
│   ├── report.js                # Save JSON/CSV/HTML
│   └── utils.js
│
├── reports/                  # Generated scan reports (gitignored)
│
└── web/                      # Live dashboard
    ├── server.js              # Express + Socket.IO server
    ├── routes.js               # Read-only REST endpoints
    ├── socket.js                # Scan/monitor socket event handlers
    └── public/
        ├── index.html
        ├── app.js
        └── style.css
```

## Usage

```
npm install

# One-shot scan (CLI, saves JSON/CSV/HTML reports to reports/)
npm start

# Continuous monitoring (CLI, logs new/offline/changed devices)
npm run monitor
npm run monitor -- --interval=30000   # custom interval in ms (default 60000)

# Live web dashboard (host table + topology graph + monitor toggle)
npm run web              # http://localhost:3000
npm run dev:web          # same, with nodemon auto-restart
```

## Web dashboard

`npm run web` starts an Express + Socket.IO server on port `3000` (override with
`PORT`). It serves a single-page dashboard that can trigger on-demand scans,
toggle continuous monitoring, toggle live packet-capture traffic monitoring,
and renders discovered hosts as both a live table and a `vis-network` topology
graph rooted at the detected default gateway.

REST endpoints (read-only; scans/monitoring/capture are triggered over Socket.IO):
- `GET /api/interfaces` — detected network interfaces
- `GET /api/scan/latest` — most recent completed scan result
- `GET /api/topology` — most recent topology graph

## Port scanning

Every scanned host is probed for both TCP and UDP open ports (`src/ports.js`),
and each entry in `host.openPorts` carries a `protocol` (`"tcp"`/`"udp"`) and
`state` field so the UI, reports, and monitor diffs can show/track the type of
port, not just the number — e.g. `53/udp` (DNS) and `53/tcp` are tracked as
distinct ports. TCP detection is a definite open/closed; UDP is inherently
ambiguous (connectionless), so ports may come back as `"open"` (got a reply),
`"closed"` (got an ICMP port-unreachable), or `"open|filtered"` (no response
either way within the timeout — normal for UDP even on an open port).

## Live traffic monitoring (packet capture)

The "Live Traffic" toggle in the dashboard starts a live packet capture
(`src/capture.js`, via the native `cap`/libpcap binding) and shows, per IP
address seen on the wire: bytes/packets sent and received, a TCP/UDP/ICMP/
other protocol breakdown, and the `protocol/port` combinations observed in
live traffic — refreshed every 2 seconds.

**Visibility limitation:** on a normal switched LAN, this only sees traffic
to/from *this* machine, plus broadcast/multicast frames (ARP, mDNS, SSDP,
DHCP). It does **not** see traffic between two *other* devices unless this
host is the gateway/router itself, or its switch port is mirrored/SPANned.
The dashboard shows this caveat directly above the traffic table.

**Setup** (one-time, requires root):
```
sudo apt-get install libpcap-dev   # headers needed to build the native module
npm install cap                     # already in package.json — rebuilds if needed
```

**Running with capture privileges** — packet capture needs elevated OS
permissions. Either run the dashboard as root, or grant the capability to the
node binary directly (persists until removed with `sudo setcap -r`):
```
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which node)")"
```
Without either of these, toggling "Live Traffic" will show a clear
permission error in the dashboard instead of any data — it never crashes the
rest of the app (scanning/monitoring keep working normally). If `cap` itself
isn't installed/built, the same graceful-error behavior applies.

## Notes

- Gateway detection (`src/gateway.js`) reads the OS routing table
  (`ip route` / `route -n get default` / `route print`) and falls back to the
  subnet's first usable host if that fails.
- `mongoose`, `net-snmp`, `node-nmap`, and `cytoscape` are installed but
  currently unused — no persistence layer or SNMP polling is wired up.
