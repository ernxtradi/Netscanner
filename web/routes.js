/**
 * routes.js
 * ----------------
 * Read-only REST endpoints. Scan/monitor triggering is socket-only
 * (see socket.js) to avoid two competing ways to start a scan.
 */

const express = require("express");
const { getInterfaces } = require("../src/subnet");

function registerRoutes(app, socketModule) {
  const router = express.Router();

  router.get("/interfaces", (req, res) => {
    res.json(getInterfaces());
  });

  router.get("/scan/latest", (req, res) => {
    const latest = socketModule.getLatestResult();
    if (!latest) return res.status(404).json({ message: "No scan has completed yet." });
    res.json(latest);
  });

  router.get("/topology", (req, res) => {
    const latest = socketModule.getLatestResult();
    if (!latest) return res.status(404).json({ message: "No scan has completed yet." });
    res.json(latest.topology);
  });

  app.use("/api", router);
}

module.exports = { registerRoutes };
