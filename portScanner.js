const net = require("net");

function scanPort(ip, port, timeout = 500) {
    return new Promise(resolve => {
        const socket = new net.Socket();

        socket.setTimeout(timeout);

        socket.connect(port, ip, () => {
            socket.destroy();
            resolve(true);
        });

        socket.on("error", () => resolve(false));
        socket.on("timeout", () => {
            socket.destroy();
            resolve(false);
        });
    });
}