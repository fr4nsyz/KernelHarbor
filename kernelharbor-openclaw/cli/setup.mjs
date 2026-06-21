#!/usr/bin/env node

import { execSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

function run(cmd, opts = {}) {
  console.log(`$ ${cmd}`);
  execSync(cmd, { stdio: "inherit", ...opts });
}

async function main() {
  console.log("KernelHarbor — Setup");
  console.log("====================");

  console.log("\n1. Checking prerequisites...");
  let goOk = false;
  try {
    execSync("which go", { stdio: "ignore" });
    console.log("   ✓ Go installed");
    goOk = true;
  } catch {
    console.log("   ✗ Go not found. Install Go 1.25+ from https://go.dev/dl/");
  }

  try {
    execSync("which falco", { stdio: "ignore" });
    console.log("   ✓ Falco installed");
  } catch {
    console.log("   ⚠ Falco not found. Install: https://falco.org/docs/install/");
  }

  try {
    execSync("which falcosidekick", { stdio: "ignore" });
    console.log("   ✓ falcosidekick installed");
  } catch {
    console.log("   ⚠ falcosidekick not found. Install: https://github.com/falcosecurity/falcosidekick");
  }

  if (!goOk) {
    process.exit(1);
  }

  console.log("\n2. Building analysis service...");
  const harborDir = join(root, ".kernelharbor");
  if (!existsSync(harborDir)) {
    const repo = process.env.KH_REPO || "https://github.com/fr4nsyz/KernelHarbor.git";
    run(`git clone --depth=1 ${repo} "${harborDir}"`);
  } else {
    console.log("   KernelHarbor repo already cloned, pulling latest...");
    run(`git -C "${harborDir}" pull`, { cwd: harborDir });
  }

  const binDir = join(root, "bin");
  mkdirSync(binDir, { recursive: true });
  console.log("   Building analysis service...");
  run(`go build -o "${join(binDir, "analysis")}" .`, { cwd: join(harborDir, "cmd", "analysis") });

  console.log("\n3. Verifying Falco rules...");
  const rulesPath = join(root, "rules", "kernelharbor-rules.yaml");
  if (existsSync(rulesPath)) {
    console.log(`   ✓ Falco rules found at ${rulesPath}`);
  } else {
    console.log(`   ✗ Falco rules not found at ${rulesPath}`);
  }

  console.log("\n4. Creating config...");
  const configPath = join(root, ".env");
  if (!existsSync(configPath)) {
    writeFileSync(configPath, [
      "# KernelHarbor Configuration",
      "# Uncomment and set LLM backend for AI analysis:",
      '# KH_LLM_BACKEND="ollama"',
      '# OLLAMA_ADDRESS="http://localhost:11434"',
      '# LLM_THRESHOLD="0.6"',
      "",
      "# Analysis service address (gRPC)",
      'GRPC_ADDRESS="localhost:9090"',
      "",
      "# Path to Falco rules file (default: rules/kernelharbor-rules.yaml)",
      '# FALCO_RULES_PATH=""',
      "",
      "# Path to Falco config file (optional)",
      '# FALCO_CONFIG_PATH=""',
      "",
    ].join("\n"));
    console.log(`   Created ${configPath}`);
  }

  console.log("\n✓ Setup complete!");
  console.log("  Make sure Falco and falcosidekick are installed and on PATH.");
  console.log("  Run './cli/status.mjs' to check service status.");
  console.log("  Run './cli/dashboard.mjs' to start the dashboard.");
  console.log("  Or start the sidecar via OpenClaw Gateway.");
}

main().catch(console.error);
