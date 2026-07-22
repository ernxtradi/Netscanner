# netscanner

A local network scanner: ping sweep → reverse DNS → ARP/MAC → vendor lookup →
TCP+UDP port scan → device classification, with JSON/CSV/HTML reports, a live
web dashboard with topology graph, continuous monitoring mode, live
packet-capture traffic monitoring (with live per-device throughput), and an
internet speed test.

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
│   ├── capture.js               # Capture supervisor: forks/restarts captureWorker.js
│   ├── captureWorker.js         # Isolated child process: actual pcap open/decode
│   ├── speedtest.js             # Internet ping/download/upload speed test
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
run an internet speed test, and renders discovered hosts as both a live table
and a `vis-network` topology graph rooted at the detected default gateway.

REST endpoints (read-only; scans/monitoring/capture/speed test are triggered over Socket.IO):
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

The "Live Traffic" toggle in the dashboard starts a live packet capture and
shows, per IP address seen on the wire: bytes/packets sent and received,
**live throughput in Mbps** (i.e. current speed between this device and each
other device it can see), a TCP/UDP/ICMP/other protocol breakdown, and the
`protocol/port` combinations observed in live traffic — refreshed every 2
seconds.

**Visibility limitation:** on a normal switched LAN, this only sees traffic
to/from *this* machine, plus broadcast/multicast frames (ARP, mDNS, SSDP,
DHCP). It does **not** see traffic between two *other* devices unless this
host is the gateway/router itself, or its switch port is mirrored/SPANned.
The dashboard shows this caveat directly above the traffic table.

**Architecture — why capture runs in a child process:** the native
`cap`/libpcap binding has been observed to crash with SIGSEGV during live
capture. A native crash can't be caught by JS `try/catch` and kills whatever
process it happens in — so `src/capture.js` never opens the capture itself;
it forks `src/captureWorker.js` to do that, and only relays its stats over
IPC. If the worker crashes, `capture.js` restarts it automatically (up to 3
times; a worker that stays up 10+ seconds before crashing again gets a fresh
restart budget). If it keeps crashing immediately, capture.js gives up and
reports a clear error — the dashboard process itself is never at risk either
way. This is a real reliability caveat of `cap`/libpcap on some systems, not
just theoretical — worth knowing if "Live Traffic" stops updating and
restarts a few times before giving up.

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
permission error in the dashboard instead of any data. If `cap` itself isn't
installed/built, the same graceful-error behavior applies. Neither case, nor
a capture crash, ever takes down the rest of the app — scanning, monitoring,
and the speed test below keep working normally.

## Internet speed test

The "Speed Test" button (`src/speedtest.js`) measures ping latency, download,
and upload throughput against Cloudflare's public speed-test endpoints
(`speed.cloudflare.com` — no API key required, but this does make outbound
requests to a third-party service). Runs sequentially (ping, then download,
then upload) so each measurement isn't skewed by the others competing for
the same bandwidth. Ping uses ICMP (via `src/ping.js`), so it'll read "N/A"
on networks/environments that block outbound ICMP even though download/
upload still work fine over HTTP.

## Notes

- Gateway detection (`src/gateway.js`) reads the OS routing table
  (`ip route` / `route -n get default` / `route print`) and falls back to the
  subnet's first usable host if that fails.
- `mongoose`, `net-snmp`, `node-nmap`, and `cytoscape` are installed but
  currently unused — no persistence layer or SNMP polling is wired up.
