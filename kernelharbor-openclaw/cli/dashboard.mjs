#!/usr/bin/env node

import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const dashboardDir = join(root, "dashboard");

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

function serveFile(res, filePath) {
  if (!existsSync(filePath)) {
    res.writeHead(404);
    res.end("Not found");
    return;
  }
  const ext = extname(filePath);
  res.writeHead(200, { "Content-Type": MIME[ext] || "text/plain" });
  res.end(readFileSync(filePath));
}

async function fetchJSON(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(null);
        }
      });
    }).on("error", () => resolve(null));
  });
}

const analysisAddr = process.env.KH_ANALYSIS_HTTP_ADDR || "localhost:8080";

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // API proxy to analysis service
  if (url.pathname.startsWith("/api/")) {
    const targetURL = `http://${analysisAddr}${url.pathname}${url.search}`;
    const data = await fetchJSON(targetURL);
    if (data) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(data));
    } else {
      res.writeHead(502);
      res.end(JSON.stringify({ error: "Analysis service unavailable" }));
    }
    return;
  }

  // Static files
  let filePath = join(dashboardDir, url.pathname === "/" ? "index.html" : url.pathname);
  serveFile(res, filePath);
});

const port = parseInt(process.env.KH_DASHBOARD_PORT || "8181", 10);
server.listen(port, () => {
  console.log(`KernelHarbor dashboard: http://localhost:${port}`);
  console.log("Press Ctrl+C to stop");
});
