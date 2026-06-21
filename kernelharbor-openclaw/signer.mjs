#!/usr/bin/env node
import { createHmac } from "node:crypto";
import http from "node:http";

const SECRET = process.env.KH_SIGNING_SECRET;
if (!SECRET) {
  console.error("KH_SIGNING_SECRET is required");
  process.exit(1);
}

const PORT = parseInt(process.env.KH_SIGNER_PORT || "28079", 10);
const TARGET = process.env.KH_WEBHOOK_TARGET || "http://127.0.0.1:28080/falco/event";
const targetUrl = new URL(TARGET);

const srv = http.createServer((req, res) => {
  if (req.method !== "POST") {
    res.writeHead(405);
    return res.end();
  }

  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const sig = createHmac("sha256", SECRET).update(body).digest("hex");

    const opts = {
      hostname: targetUrl.hostname,
      port: targetUrl.port,
      path: targetUrl.pathname,
      method: "POST",
      headers: {
        "Content-Type": req.headers["content-type"] || "application/json",
        "X-KH-Signature-256": sig,
        "Content-Length": body.length,
      },
    };

    const proxy = http.request(opts, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });
    proxy.on("error", (err) => {
      res.writeHead(502);
      res.end(JSON.stringify({ error: err.message }));
    });
    proxy.write(body);
    proxy.end();
  });
});

srv.listen(PORT, () => {
  console.error(`signer: listening :${PORT} -> ${TARGET}`);
});
