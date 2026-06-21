import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

const __dirname = dirname(fileURLToPath(import.meta.url));

let sidecarProcess = null;

function findBinary(name) {
  const searchPaths = [
    join(__dirname, "bin", name),
    join(process.cwd(), "bin", name),
    `/usr/local/bin/${name}`,
  ];
  for (const p of searchPaths) {
    if (existsSync(p)) return p;
  }
  // try PATH
  return name;
}

function startSidecar(api, config) {
  const agentBin = findBinary("agent");
  const analysisBin = findBinary("analysis");
  const analysisAddr = config.analysisAddr || "localhost:9090";

  if (!existsSync(analysisBin)) {
    api.logger.warn(`Analysis binary not found at ${analysisBin}, skipping sidecar start`);
    return;
  }

  api.logger.info(`Starting KernelHarbor analysis: ${analysisBin}`);

  const analysis = spawn(analysisBin, [], {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      GRPC_ADDRESS: analysisAddr,
      HTTP_ADDRESS: "127.0.0.1:8080",
      LLM_BACKEND: process.env.KH_LLM_BACKEND || "none",
    },
  });

  analysis.stdout.on("data", (d) => api.logger.info(`[analysis] ${d.toString().trim()}`));
  analysis.stderr.on("data", (d) => api.logger.warn(`[analysis] ${d.toString().trim()}`));
  analysis.on("exit", (code) => api.logger.info(`Analysis exited with code ${code}`));

  if (existsSync(agentBin)) {
    api.logger.info(`Starting KernelHarbor agent: ${agentBin}`);
    const agent = spawn("sudo", [agentBin], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GRPC_ADDRESS: analysisAddr },
    });
    agent.stdout.on("data", (d) => api.logger.info(`[agent] ${d.toString().trim()}`));
    agent.stderr.on("data", (d) => api.logger.warn(`[agent] ${d.toString().trim()}`));
    agent.on("exit", (code) => api.logger.info(`Agent exited with code ${code}`));

    sidecarProcess = { analysis, agent };
  } else {
    api.logger.warn(`Agent binary not found at ${agentBin}, running analysis only`);
    sidecarProcess = { analysis };
  }
}

function stopSidecar() {
  if (!sidecarProcess) return;
  for (const [name, proc] of Object.entries(sidecarProcess)) {
    try {
      proc.kill("SIGTERM");
      setTimeout(() => proc.kill("SIGKILL"), 5000);
    } catch { /* ignore */ }
  }
  sidecarProcess = null;
}

async function fetchAlerts(analysisAddr) {
  return new Promise((resolve, reject) => {
    http.get(`http://${analysisAddr.replace(":9090", ":8080")}/api/alerts?since=24h&min_verdict=suspicious&limit=50`, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data).alerts || []);
        } catch {
          resolve([]);
        }
      });
    }).on("error", () => resolve([]));
  });
}

async function sendAlertToGateway(api, alert) {
  try {
    await api.registerGatewayMethod?.("kernelharbor.alert", async () => alert);
  } catch { /* not critical */ }
}

const plugin = {
  id: "kernelharbor",
  name: "KernelHarbor",
  description: "Linux kernel security monitoring — eBPF + heuristic + optional LLM",

  register(api) {
    const config = api.pluginConfig || {};
    api.logger.info("KernelHarbor plugin registering");

    api.registerService({
      id: "kernelharbor.sidecar",
      name: "KernelHarbor Sidecar",
      start: () => {
        if (config.autoStart !== false) {
          startSidecar(api, config);
        }
      },
      stop: () => stopSidecar(),
      health: () => ({
        running: sidecarProcess !== null,
        analysis: sidecarProcess?.analysis?.exitCode === null,
        agent: sidecarProcess?.agent?.exitCode === null,
      }),
    });

    api.registerGatewayMethod("kernelharbor.status", async () => {
      const addr = config.analysisAddr || "localhost:9090";
      const alerts = await fetchAlerts(addr);
      return {
        sidecarRunning: sidecarProcess !== null,
        alertCount: alerts.length,
        recentAlerts: alerts.slice(0, 10),
      };
    });

    api.registerGatewayMethod("kernelharbor.alert.feedback", async (params) => {
      const { alertId, feedback } = params;
      const addr = config.analysisAddr || "localhost:9090";
      const httpAddr = addr.replace(":9090", ":8080");
      return new Promise((resolve, reject) => {
        const body = JSON.stringify({ feedback });
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
        req.write(body);
        req.end();
      });
    });

    // Poll alerts from analysis and push to gateway
    const pollInterval = setInterval(async () => {
      const addr = config.analysisAddr || "localhost:9090";
      const alerts = await fetchAlerts(addr);
      for (const alert of alerts) {
        await sendAlertToGateway(api, alert);
      }
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
