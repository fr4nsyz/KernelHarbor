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

  // 1. Check prerequisites
  console.log("\n1. Checking prerequisites...");
  try {
    execSync("which go", { stdio: "ignore" });
    console.log("   ✓ Go installed");
  } catch {
    console.log("   ✗ Go not found. Install Go 1.25+ from https://go.dev/dl/");
    process.exit(1);
  }

  try {
    execSync("which clang", { stdio: "ignore" });
    console.log("   ✓ clang installed");
  } catch {
    console.log("   ⚠ clang not found. KernelHarbor agent requires clang for eBPF.");
  }

  // 2. Clone/build KernelHarbor
  console.log("\n2. Building KernelHarbor...");
  const harborDir = join(root, ".kernelharbor");
  if (!existsSync(harborDir)) {
    const repo = process.env.KH_REPO || "https://github.com/fr4nsyz/KernelHarbor.git";
    run(`git clone --depth=1 ${repo} "${harborDir}"`);
  } else {
    console.log("   KernelHarbor repo already cloned, pulling latest...");
    run(`git -C "${harborDir}" pull`, { cwd: harborDir });
  }

  // 3. Build binaries
  const binDir = join(root, "bin");
  mkdirSync(binDir, { recursive: true });

  console.log("   Building analysis service...");
  run(`go build -o "${join(binDir, "analysis")}" .`, { cwd: join(harborDir, "cmd", "analysis") });

  console.log("   Building agent...");
  run(`go build -o "${join(binDir, "agent")}" .`, { cwd: join(harborDir, "cmd", "agent") });

  // 4. Create config
  console.log("\n3. Creating config...");
  const configPath = join(root, ".env");
  if (!existsSync(configPath)) {
    writeFileSync(configPath, [
      "# KernelHarbor Configuration",
      "# Uncomment and set LLM backend for AI analysis:",
      '# KH_LLM_BACKEND="ollama"',
      '# OLLAMA_ADDRESS="http://localhost:11434"',
      '# LLM_THRESHOLD="0.6"',
      "",
      "# gRPC address for analysis service",
      'GRPC_ADDRESS="localhost:9090"',
      "",
    ].join("\n"));
    console.log(`   Created ${configPath}`);
  }

  console.log("\n✓ Setup complete!");
  console.log("  Run './cli/status.mjs' to check service status.");
  console.log("  Run './cli/dashboard.mjs' to start the dashboard.");
  console.log("  Or start the sidecar via OpenClaw Gateway.");
}

main().catch(console.error);
