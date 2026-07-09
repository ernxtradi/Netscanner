const ping = require("ping");
const dns = require("dns").promises;
const fs = require("fs");

const subnet = "192.168.1";
const onlineHosts = [];
let scanned = 0;

async function getHostname(ip) {
    try {
        const hostnames = await dns.reverse(ip);
        return hostnames[0];
    } catch {
        return "Unknown";
    }
}

async function scanHost(ip) {
    try {
        const res = await ping.promise.probe(ip, {
            timeout: 1,
            extra: ["-c", "1"],
        });

        scanned++;

        process.stdout.write(
            `\rScanned ${scanned}/254 hosts...`
        );

        if (res.alive) {
            const hostname = await getHostname(ip);

            const device = {
                ip,
                hostname,
                latency: res.time + " ms",
                scannedAt: new Date().toLocaleString(),
            };

            onlineHosts.push(device);

            console.log("\n------------------------");
            console.log(`IP       : ${ip}`);
            console.log(`Hostname : ${hostname}`);
            console.log(`Latency  : ${res.time} ms`);
            console.log("------------------------");
        }
    } catch (err) {
        // Ignore unreachable hosts
    }
}

async function scanNetwork() {
    console.log(`Scanning ${subnet}.0/24\n`);

    const tasks = [];

    for (let i = 1; i <= 254; i++) {
        tasks.push(scanHost(`${subnet}.${i}`));
    }

    await Promise.all(tasks);

    fs.writeFileSync(
        "network-scan.json",
        JSON.stringify(onlineHosts, null, 2)
    );

    console.log("\n\n====== Scan Summary ======");
    console.log(`Online Hosts : ${onlineHosts.length}`);
    console.log(`Results saved to network-scan.json`);

    console.table(onlineHosts);
}

scanNetwork();
