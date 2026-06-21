import { spawn } from "node:child_process";
import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import http from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MAX_RESTART_DELAY = 30000;
const STABILITY_THRESHOLD = 30000;

function findBinary(name) {
  for (const p of [
    join(__dirname, "bin", name),
    join(process.cwd(), "bin", name),
    `/usr/local/bin/${name}`,
  ]) {
    if (existsSync(p)) return p;
  }
  return name;
}

function createManager() {
  let current = null, stopped = false, delay = 1000;
  let name, cmd, args, opts, logInfo, logWarn;

  function spawnOne() {
    if (stopped || !cmd) return;
    try {
      const proc = spawn(cmd, args, opts);
      current = proc;

      proc.stdout?.on("data", (d) => {
        const m = d.toString().trim();
        if (m) logInfo(`[${name}] ${m}`);
      });
      proc.stderr?.on("data", (d) => {
        const m = d.toString().trim();
        if (m) logWarn(`[${name}] ${m}`);
      });

      const stable = setTimeout(() => { delay = 1000; }, STABILITY_THRESHOLD);

      proc.on("exit", (code) => {
        clearTimeout(stable);
        current = null;
        if (stopped) return;
        logWarn(`${name} exited (code ${code}), restart in ${delay}ms`);
        setTimeout(spawnOne, delay);
        delay = Math.min(delay * 2, MAX_RESTART_DELAY);
      });
      proc.on("error", () => { current = null; });
    } catch (err) {
      logWarn(`Cannot spawn ${name}: ${err.message}`);
    }
  }

  function stop() {
    stopped = true;
    if (current) {
      try { current.kill("SIGTERM"); } catch {}
      setTimeout(() => { try { current?.kill("SIGKILL"); } catch {} }, 5000);
    }
    current = null;
  }

  function configure(n, c, a, o, info, warn) {
    name = n; cmd = c; args = a; opts = o; logInfo = info; logWarn = warn;
  }

  return {
    get current() { return current; },
    get alive() { return current?.exitCode === null; },
    configure, stop,
    start() { stopped = false; delay = 1000; spawnOne(); },
    reset() { stop(); stopped = false; delay = 1000; },
  };
}

const analysisMgr = createManager();
const falcoMgr = createManager();
const sidekickMgr = createManager();
const signerMgr = createManager();
let webhookSrv = null;
let tmpDir = null;

const eventQueue = [];
let draining = false;
let queueWarn = null;

function enqueueEvent(httpAddr, event, apiKey, warnFn) {
  queueWarn = warnFn || console.warn;
  eventQueue.push({ httpAddr, event, apiKey, retries: 0 });
  if (!draining) drainQueue();
}

async function drainQueue() {
  draining = true;
  while (eventQueue.length > 0) {
    const item = eventQueue[0];
    try {
      await postEvent(item.httpAddr, item.event, item.apiKey);
      eventQueue.shift();
    } catch (err) {
      item.retries++;
      if (item.retries >= 5) {
        eventQueue.shift();
        (queueWarn || console.warn)("event dropped after 5 retries: " + (err.message || err));
      } else {
        eventQueue.shift();
        eventQueue.push(item);
      }
    }
    if (eventQueue.length > 0) await new Promise((r) => setTimeout(r, 1000));
  }
  draining = false;
}

function postEvent(httpAddr, event, apiKey) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(event);
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;
    const req = http.request(
      `http://${httpAddr}/ingest`,
      { method: "POST", headers },
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

function verifyHmac(body, signature, secret) {
  if (!secret) return true;
  if (!signature) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  const actual = Buffer.from(signature, "hex");
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

function startAnalysis(api, config) {
  const bin = findBinary("analysis");
  if (!existsSync(bin)) {
    api.logger.warn(`Analysis binary not found at ${bin}`);
    return;
  }
  const addr = config.analysisAddr || "localhost:9090";
  api.logger.info(`Starting analysis: ${bin}`);
  analysisMgr.configure("analysis", bin, [], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, GRPC_ADDRESS: addr, HTTP_ADDRESS: "127.0.0.1:8080", LLM_BACKEND: process.env.KH_LLM_BACKEND || "none" },
  }, (m) => api.logger.info(m), (m) => api.logger.warn(m));
  analysisMgr.start();
}

function startFalcoPipeline(api, config) {
  const rulesPath = config.falcoRulesPath || join(__dirname, "rules", "kernelharbor-rules.yaml");
  if (!existsSync(rulesPath)) {
    api.logger.warn(`Falco rules not found at ${rulesPath}`);
    return;
  }

  const sidekickPort = config.falcoSidekickPort || 2801;
  const webhookPort = config.falcoWebhookPort || 28080;
  const signerPort = config.signerPort || 28079;
  const analysisAddr = config.analysisAddr || "localhost:9090";
  const httpAddr = analysisAddr.replace(":9090", ":8080");
  const analysisApiKey = config.analysisApiKey || "";
  const signingSecret = config.signingSecret || process.env.KH_SIGNING_SECRET || "";
  const useSigner = !!signingSecret;

  tmpDir = mkdtempSync(join(tmpdir(), "kh-falco-"));
  const fsConfigPath = join(tmpDir, "falcosidekick.yaml");

  const webhookTarget = useSigner
    ? `http://127.0.0.1:${signerPort}/falco/event`
    : `http://127.0.0.1:${webhookPort}/falco/event`;

  writeFileSync(fsConfigPath, [
    "debug: false",
    `listenport: ${sidekickPort}`,
    "webhook:",
    `  address: "${webhookTarget}"`,
    "",
  ].join("\n"));

  webhookSrv = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/falco/event") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (useSigner) {
          const sig = req.headers["x-kh-signature-256"];
          if (!sig || !verifyHmac(body, sig, signingSecret)) {
            res.writeHead(401, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ error: "invalid hmac signature" }));
          }
        }
        try {
          const fe = JSON.parse(body);
          if (fe.tags && fe.tags.includes("kernelharbor")) {
            const ev = convertFalcoEvent(fe);
            if (ev) enqueueEvent(httpAddr, ev, analysisApiKey, (m) => api.logger?.warn?.(m));
          }
        } catch (e) { api.logger.warn(`[falco-webhook] ${e.message}`); }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
      });
    } else {
      res.writeHead(404);
      res.end("Not found");
    }
  });

  try {
    webhookSrv.listen(webhookPort);
  } catch (err) {
    api.logger.warn(`Failed to start webhook: ${err.message}`);
    webhookSrv = null;
    rmSync(tmpDir, { recursive: true, force: true }); tmpDir = null;
    return;
  }
  api.logger.info(`Falco webhook receiver on :${webhookPort}`);

  if (useSigner) {
    signerMgr.configure("signer", process.execPath, [join(__dirname, "signer.mjs")], {
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        KH_SIGNING_SECRET: signingSecret,
        KH_SIGNER_PORT: String(signerPort),
        KH_WEBHOOK_TARGET: `http://127.0.0.1:${webhookPort}/falco/event`,
      },
    }, (m) => api.logger.info(m), (m) => api.logger.warn(m));
    signerMgr.start();
    api.logger.info(`HMAC signer on :${signerPort} → webhook :${webhookPort}`);
  }

  sidekickMgr.configure("falcosidekick", "falcosidekick", ["-config", fsConfigPath],
    { stdio: ["ignore", "pipe", "pipe"] },
    (m) => api.logger.info(m), (m) => api.logger.warn(m));
  sidekickMgr.start();

  const falcoArgs = [
    "-r", rulesPath,
    "-o", "json_output=true",
    "-o", "json_include_output_property=false",
    "-o", "json_include_tags_property=true",
    "-o", "stdout_output.enabled=false",
    "-o", "http_output.enabled=true",
    "-o", `http_output.url=http://127.0.0.1:${sidekickPort}/`,
  ];
  if (config.falcoConfigPath) falcoArgs.unshift("-c", config.falcoConfigPath);

  falcoMgr.configure("falco", "falco", falcoArgs, { stdio: ["ignore", "pipe", "pipe"] },
    (m) => api.logger.info(m), (m) => api.logger.warn(m));
  falcoMgr.start();

  const pipelineDesc = useSigner
    ? "Falco → falcosidekick → signer(HMAC) → webhook → analysis"
    : "Falco → falcosidekick → webhook → analysis";
  api.logger.info(`Falco pipeline: ${pipelineDesc}`);
}

function stopServices() {
  analysisMgr.stop();
  falcoMgr.stop();
  signerMgr.stop();
  sidekickMgr.stop();
  if (webhookSrv) { try { webhookSrv.close(); } catch {} webhookSrv = null; }
  if (tmpDir) { try { rmSync(tmpDir, { recursive: true, force: true }); } catch {} tmpDir = null; }
}

async function fetchAlerts(analysisAddr) {
  return new Promise((resolve) => {
    http.get(`http://${analysisAddr.replace(":9090", ":8080")}/api/alerts?since=24h&min_verdict=suspicious&limit=50`, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => { try { resolve(JSON.parse(data).alerts || []); } catch { resolve([]); } });
    }).on("error", () => resolve([]));
  });
}

async function sendToGateway(api, alert) {
  try { await api.registerGatewayMethod?.("kernelharbor.alert", async () => alert); }
  catch (e) { api.logger?.warn?.("sendToGateway failed: " + e.message); }
}

const plugin = {
  id: "kernelharbor",
  name: "KernelHarbor",
  description: "Linux kernel security monitoring — Falco + falcosidekick + heuristic + optional LLM",

  register(api) {
    const config = api.pluginConfig || {};
    api.logger.info("KernelHarbor plugin registering");

    api.registerService({
      id: "kernelharbor.sidecar",
      name: "KernelHarbor Sidecar",
      start: () => {
        if (config.autoStart !== false) {
          startAnalysis(api, config);
          startFalcoPipeline(api, config);
        }
      },
      stop: () => stopServices(),
      health: () => ({
        running: analysisMgr.alive || falcoMgr.alive,
        analysis: analysisMgr.alive,
        falco: falcoMgr.alive,
        falcosidekick: sidekickMgr.alive,
      }),
    });

    api.registerGatewayMethod("kernelharbor.status", async () => {
      const addr = config.analysisAddr || "localhost:9090";
      const alerts = await fetchAlerts(addr);
      return {
        sidecarRunning: analysisMgr.alive,
        falcoRunning: falcoMgr.alive,
        falcosidekickRunning: sidekickMgr.alive,
        alertCount: alerts.length,
        recentAlerts: alerts.slice(0, 10),
      };
    });

    api.registerGatewayMethod("kernelharbor.alert.feedback", async (params) => {
      const { alertId, feedback } = params;
      const addr = config.analysisAddr || "localhost:9090";
      const httpAddr = addr.replace(":9090", ":8080");
      return new Promise((resolve, reject) => {
        const req = http.request(
          `http://${httpAddr}/api/alerts/${alertId}/feedback`,
          { method: "POST", headers: { "Content-Type": "application/json" } },
          (res) => {
            let data = "";
            res.on("data", (c) => (data += c));
            res.on("end", () => resolve(JSON.parse(data)));
          }
        );
        req.on("error", reject);
        req.write(JSON.stringify({ feedback }));
        req.end();
      });
    });

    const pollInterval = setInterval(async () => {
      const addr = config.analysisAddr || "localhost:9090";
      const alerts = await fetchAlerts(addr);
      for (const alert of alerts) await sendToGateway(api, alert);
    }, 10000);

    api.registerService({
      id: "kernelharbor.alert-poller",
      name: "KernelHarbor Alert Poller",
      start: () => {},
      stop: () => clearInterval(pollInterval),
    });
  },

  activate(api) {
    api.logger.info("KernelHarbor plugin activated");
  },
};

export default plugin;
