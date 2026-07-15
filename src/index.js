const Scanner = require("./scanner");

async function main() {
    try {
        await Scanner.start();
    } catch (err) {
        console.error(err);
    }
}

main();