#!/usr/bin/env node

import http from "node:http";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

function httpGet(url) {
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

async function main() {
  console.log("KernelHarbor — Status");
  console.log("=====================");

  // Check binaries
  const binAnalysis = join(root, "bin", "analysis");
  const binAgent = join(root, "bin", "agent");
  console.log(`\nBinaries:`);
  console.log(`  Analysis:  ${existsSync(binAnalysis) ? "✓" : "✗"} ${binAnalysis}`);
  console.log(`  Agent:     ${existsSync(binAgent) ? "✓" : "✗"} ${binAgent}`);

  // Check HTTP API
  const httpHealth = await httpGet("http://localhost:8080/health");
  if (httpHealth) {
    console.log(`\nAnalysis HTTP API: ✓ (status: ${httpHealth.status})`);
  } else {
    console.log(`\nAnalysis HTTP API: ✗ (not responding on :8080)`);
  }

  // Check gRPC health
  const ready = await httpGet("http://localhost:8080/ready");
  if (ready) {
    console.log(`  Elasticsearch: ${ready.elasticsearch ? "✓" : "✗"}`);
    console.log(`  LLM:           ${ready.llm ? "✓ (" + (ready.llmModel || "configured") + ")" : "✗ (none)"}`);
  }

  // Check alerts
  const alerts = await httpGet("http://localhost:8080/api/alerts?since=24h&min_verdict=suspicious&limit=5");
  if (alerts && alerts.alerts) {
    console.log(`\nRecent alerts: ${alerts.alerts.length}`);
    for (const a of alerts.alerts) {
      console.log(`  [${a.verdict}] ${a.summary} (${(a.confidence * 100).toFixed(0)}%)`);
    }
  }

  // Check stats
  const stats = await httpGet("http://localhost:8080/api/alerts/stats");
  if (stats) {
    console.log(`\nStats (24h):`);
    console.log(`  Total alerts:  ${stats.alerts_24h || 0}`);
    console.log(`  Malicious:     ${stats.malicious || 0}`);
    console.log(`  Suspicious:    ${stats.suspicious || 0}`);
    console.log(`  Confirmed:     ${stats.confirmed || 0}`);
    console.log(`  False +:       ${stats.false_positives || 0}`);
  }

  console.log();
}

main().catch(console.error);
