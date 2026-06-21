import http from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dashboardDir = join(__dirname, "dashboard");

const ANALYSIS_HTTP = process.env.KH_ANALYSIS_HTTP_ADDR || "analysis:8080";
const DASHBOARD_PORT = parseInt(process.env.KH_DASHBOARD_PORT || "8181", 10);
const SIGNING_SECRET = process.env.KH_SIGNING_SECRET || "";
const SIGNER_PORT = parseInt(process.env.KH_SIGNER_PORT || "28079", 10);
const WEBHOOK_PORT = parseInt(process.env.KH_WEBHOOK_PORT || "28080", 10);
const CONFIG = JSON.parse(process.env.KH_PLUGIN_CONFIG || "{}");
const EXTERNAL_ANALYSIS = process.env.KH_EXTERNAL_ANALYSIS === "1";

function createGatewayApi() {
  const services = [];
  const gatewayMethods = {};
  const alertListeners = [];

  const logger = {
    info: (...args) => console.log(`[gw:info]`, ...args),
    warn: (...args) => console.warn(`[gw:warn]`, ...args),
    error: (...args) => console.error(`[gw:error]`, ...args),
  };

  const api = {
    pluginConfig: CONFIG,
    logger,
    registerService(svc) {
      services.push(svc);
      logger.info(`service registered: ${svc.id}`);
    },
    registerGatewayMethod(name, fn) {
      gatewayMethods[name] = fn;
      logger.info(`gateway method registered: ${name}`);
    },
    registerHttpRoute(prefix, handler) {
      logger.info(`http route registered: ${prefix}`);
    },
    pushEvent(name, payload) {
      for (const cb of alertListeners) {
        try { cb(name, payload); } catch {}
      }
    },
    onAlert(cb) {
      alertListeners.push(cb);
    },
  };

  return { api, services, gatewayMethods };
}

function verifyHmac(body, signature, secret) {
  if (!secret) return true;
  if (!signature) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  const actual = Buffer.from(signature, "hex");
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

function convertFalcoEvent(falcoEvent) {
  const of = falcoEvent.output_fields || {};
  const evtType = mapEventType(of["evt.type"]);
  if (!evtType) return null;

  const event = {
    "@timestamp": falcoEvent.time || new Date().toISOString(),
    "host.name": falcoEvent.hostname || "unknown",
    "event.type": evtType,
    "command.line": of["proc.cmdline"] || "",
    "image.path": of["proc.exe"] || "",
    "process.pid": parseInt(of["proc.pid"]) || 0,
    "parent.pid": parseInt(of["proc.ppid"]) || 0,
    "user.name": of["user.name"] || "",
    "file.path": "",
    metadata: {
      falco_rule: falcoEvent.rule || "",
      falco_priority: falcoEvent.priority || "",
      falco_tags: falcoEvent.tags || [],
      falco_output: falcoEvent.output || "",
    },
  };

  if (evtType === "network" && of["fd.name"]) {
    const parts = of["fd.name"].split("->");
    if (parts.length === 2) {
      const [l, r] = [parts[0].trim(), parts[1].trim()];
      const lp = l.lastIndexOf(":"), rp = r.lastIndexOf(":");
      event["local.address"] = l.slice(0, lp);
      event["local.port"] = parseInt(l.slice(lp + 1)) || 0;
      event["remote.address"] = r.slice(0, rp);
      event["remote.port"] = parseInt(r.slice(rp + 1)) || 0;
    }
    event["socket.info"] = of["fd.name"];
  } else {
    event["file.path"] = of["fd.name"] || "";
  }
  return event;
}

function mapEventType(falcoEvtType) {
  if (!falcoEvtType) return null;
  switch (falcoEvtType) {
    case "execve": case "execveat": case "fork": case "clone": case "vfork":
      return "execve";
    case "open": case "openat": case "creat":
      return "open";
    case "connect":
      return "network";
    default:
      return null;
  }
}

function postEvent(httpAddr, event) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(event);
    const req = http.request(
      `http://${httpAddr}/ingest`,
      { method: "POST", headers: { "Content-Type": "application/json" } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(data);
          else reject(new Error(`HTTP ${res.statusCode}`));
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function startSignerProcess() {
  if (!SIGNING_SECRET) return null;
  const signerPath = join(__dirname, "signer.mjs");
  if (!existsSync(signerPath)) {
    console.warn("[gw] signer.mjs not found, HMAC disabled");
    return null;
  }

  const proc = spawn(process.execPath, [signerPath], {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      KH_SIGNING_SECRET: SIGNING_SECRET,
      KH_SIGNER_PORT: String(SIGNER_PORT),
      KH_WEBHOOK_TARGET: `http://127.0.0.1:${WEBHOOK_PORT}/falco/event`,
    },
  });

  proc.stdout?.on("data", (d) => {
    const m = d.toString().trim();
    if (m) console.log(`[signer] ${m}`);
  });
  proc.stderr?.on("data", (d) => {
    const m = d.toString().trim();
    if (m) console.warn(`[signer] ${m}`);
  });
  proc.on("exit", (code) => console.warn(`[signer] exited (code ${code})`));

  return proc;
}

function startWebhookServer() {
  const useSigner = !!SIGNING_SECRET;
  const analysisApiKey = CONFIG.analysisApiKey || process.env.KH_API_KEY || "";

  const srv = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/falco/event") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (useSigner) {
          const sig = req.headers["x-kh-signature-256"];
          if (!sig || !verifyHmac(body, sig, SIGNING_SECRET)) {
            res.writeHead(401, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ error: "invalid hmac signature" }));
          }
        }
        try {
          const fe = JSON.parse(body);
          if (fe.tags && fe.tags.includes("kernelharbor")) {
            const ev = convertFalcoEvent(fe);
            if (ev) {
              postEvent(ANALYSIS_HTTP, ev).catch((err) => console.warn(`[webhook] post failed: ${err.message}`));
            }
          }
        } catch (e) { console.warn(`[webhook] ${e.message}`); }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
      });
    } else {
      res.writeHead(404);
      res.end("Not found");
    }
  });

  srv.listen(WEBHOOK_PORT, () => {
    console.log(`[webhook] Falco webhook receiver on :${WEBHOOK_PORT}`);
  });

  return srv;
}

async function fetchAlerts() {
  return new Promise((resolve) => {
    http.get(`http://${ANALYSIS_HTTP}/api/alerts?since=24h&min_verdict=suspicious&limit=50`, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => { try { resolve(JSON.parse(data).alerts || []); } catch { resolve([]); } });
    }).on("error", () => resolve([]));
  });
}

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
};

function serveStatic(res, filePath) {
  if (!existsSync(filePath)) {
    res.writeHead(404);
    res.end("Not found");
    return;
  }
  const ext = filePath.slice(filePath.lastIndexOf("."));
  res.writeHead(200, { "Content-Type": MIME[ext] || "text/plain" });
  res.end(readFileSync(filePath));
}

function proxyRequest(req, res, targetURL) {
  const proxyReq = http.request(
    targetURL,
    {
      method: req.method,
      headers: { ...req.headers, host: new URL(targetURL).host },
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
    res.end(JSON.stringify({ error: "upstream unavailable" }));
  });
  req.pipe(proxyReq);
}

async function main() {
  console.log("====================================");
  console.log(" KernelHarbor OpenClaw Gateway");
  console.log("====================================");
  console.log("");

  const { api, services, gatewayMethods } = createGatewayApi();
  const plugin = (await import(join(__dirname, "plugin.mjs"))).default;

  console.log(`Loading plugin: ${plugin.id} (${plugin.name})`);
  plugin.register(api);

  if (plugin.activate) plugin.activate(api);

  for (const svc of services) {
    if (svc.start && svc.id !== "kernelharbor.sidecar") {
      console.log(`Starting service: ${svc.id}`);
      svc.start();
    }
  }

  startWebhookServer();
  const signerProc = startSignerProcess();
  if (signerProc) {
    console.log(`[signer] HMAC signer on :${SIGNER_PORT} -> webhook :${WEBHOOK_PORT}`);
  }

  if (EXTERNAL_ANALYSIS) {
    console.log(`[analysis] Using external service at ${ANALYSIS_HTTP}`);
  }

  const pipelineDesc = SIGNING_SECRET
    ? "Falco -> falcosidekick -> signer(HMAC) -> webhook -> analysis"
    : "Falco -> falcosidekick -> webhook -> analysis";
  console.log(`\nPipeline: ${pipelineDesc}`);

  const polling = setInterval(async () => {
    const alerts = await fetchAlerts();
    for (const alert of alerts) {
      api.pushEvent("kernelharbor.alert", alert);
    }
  }, 10000);

  const PROXY_PREFIXES = ["/api/", "/health", "/ready", "/ingest", "/actions", "/analyze"];

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (PROXY_PREFIXES.some((p) => url.pathname === p || url.pathname.startsWith(p))) {
      proxyRequest(req, res, `http://${ANALYSIS_HTTP}${url.pathname}${url.search}`);
      return;
    }

    if (url.pathname === "/kh/status") {
      if (gatewayMethods["kernelharbor.status"]) {
        gatewayMethods["kernelharbor.status"]().then(
          (data) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(data)); },
          (err) => { res.writeHead(500); res.end(JSON.stringify({ error: err.message })); }
        );
      } else {
        res.writeHead(404);
        res.end("not found");
      }
      return;
    }

    if (url.pathname.startsWith("/dashboard") || url.pathname === "/") {
      const subPath = url.pathname === "/" || url.pathname === "/dashboard"
        ? "index.html"
        : url.pathname.replace(/^\/dashboard\/?/, "");
      serveStatic(res, join(dashboardDir, subPath));
      return;
    }

    serveStatic(res, join(dashboardDir, url.pathname === "/" ? "index.html" : url.pathname));
  });

  server.listen(DASHBOARD_PORT, () => {
    console.log("");
    console.log(`Dashboard: http://0.0.0.0:${DASHBOARD_PORT}`);
    console.log(`API proxy: /api/* /health /ready /ingest -> ${ANALYSIS_HTTP}`);
    console.log(`Status:    /kh/status`);
    if (SIGNING_SECRET) {
      console.log(`HMAC:      signer :${SIGNER_PORT} -> webhook :${WEBHOOK_PORT}`);
    }
    console.log("");
  });

  const shutdown = () => {
    console.log("\nShutting down...");
    clearInterval(polling);
    if (signerProc) signerProc.kill("SIGTERM");
    for (const svc of services) {
      if (svc.stop) svc.stop();
    }
    server.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Gateway failed:", err);
  process.exit(1);
});
