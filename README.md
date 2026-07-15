netscanner/
│
├── package.json
├── package-lock.json
├── README.md
├── .gitignore
├── config/
│   └── config.js
│
├── src/
│   ├── index.js              # Entry point
│   ├── scanner.js            # Main scan orchestration
│   ├── ping.js               # Ping hosts
│   ├── dns.js                # Reverse DNS
│   ├── arp.js                # MAC address discovery
│   ├── vendor.js             # Vendor lookup
│   ├── gateway.js            # Gateway detection
│   ├── subnet.js             # Network interface/subnet detection
│   ├── ports.js              # Port scanner
│   ├── classify.js           # Device classification
│   ├── topology.js           # Network graph generation
│   ├── report.js             # Save JSON/CSV/HTML
│   ├── monitor.js            # Continuous monitoring
│   ├── logger.js             # Colored logging
│   ├── progress.js           # Progress bar
│   └── utils.js
│
├── scans/
│
├── reports/
│
├── topology/
│
└── web/
    ├── server.js
    ├── routes.js
    ├── socket.js
    └── public/
        ├── index.html
        ├── app.js
        └── style.css