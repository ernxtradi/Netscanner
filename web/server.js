const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const socketModule = require("./socket");
const { registerRoutes } = require("./routes");

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer);

app.use(express.static(path.join(__dirname, "public")));
app.use(
  "/vendor/vis-network",
  express.static(path.join(__dirname, "../node_modules/vis-network/standalone/umd"))
);
app.use("/reports", express.static(path.join(__dirname, "../reports")));

registerRoutes(app, socketModule);
socketModule.registerSocketHandlers(io);

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Netscanner dashboard running at http://localhost:${PORT}`);
});
