# netscanner

A local network scanner: ping sweep → reverse DNS → ARP/MAC → vendor lookup →
port scan → device classification, with JSON/CSV/HTML reports, a live web
dashboard with topology graph, and a continuous monitoring mode.

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
│   ├── ports.js                 # Port scanner
│   ├── classify.js              # Device classification
│   ├── topology.js              # Network graph (vis-network shape) builder
│   ├── monitor.js               # Continuous monitoring / change detection
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
toggle continuous monitoring, and renders discovered hosts as both a live table
and a `vis-network` topology graph rooted at the detected default gateway.

REST endpoints (read-only; scans/monitoring are triggered over Socket.IO):
- `GET /api/interfaces` — detected network interfaces
- `GET /api/scan/latest` — most recent completed scan result
- `GET /api/topology` — most recent topology graph

## Notes

- Gateway detection (`src/gateway.js`) reads the OS routing table
  (`ip route` / `route -n get default` / `route print`) and falls back to the
  subnet's first usable host if that fails.
- `mongoose`, `net-snmp`, `node-nmap`, and `cytoscape` are installed but
  currently unused — no persistence layer or SNMP polling is wired up.
