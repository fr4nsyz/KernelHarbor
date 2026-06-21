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

const analysisAddr = process.env.KH_ANALYSIS_HTTP_ADDR || "localhost:8080";

const PROXY_PREFIXES = ["/api/", "/health", "/ready"];

function shouldProxy(pathname) {
  return PROXY_PREFIXES.some((p) => pathname === p || pathname.startsWith(p));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // API proxy to analysis service (supports any method + body)
  if (shouldProxy(url.pathname)) {
    const targetURL = `http://${analysisAddr}${url.pathname}${url.search}`;
    const proxyReq = http.request(
      targetURL,
      {
        method: req.method,
        headers: { ...req.headers, host: analysisAddr.split(":")[0] },
      },
      (proxyRes) => {
        let body = "";
        proxyRes.on("data", (c) => (body += c));
        proxyRes.on("end", () => {
          res.writeHead(proxyRes.statusCode, {
            "Content-Type": proxyRes.headers["content-type"] || "application/json",
          });
          res.end(body);
        });
      }
    );
    proxyReq.on("error", () => {
      res.writeHead(502);
      res.end(JSON.stringify({ error: "Analysis service unavailable" }));
    });
    req.pipe(proxyReq);
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
