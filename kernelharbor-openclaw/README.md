# KernelHarbor — OpenClaw Extension

Linux kernel security monitoring for [OpenClaw](https://openclose.ai) Gateway —
eBPF tracing, heuristic detection, and optional LLM-powered analysis.

## Features

- **Real-time kernel monitoring** via eBPF (execve, open, openat, connect)
- **Three-tier detection**: heuristic (real-time) → LLM (delayed) → summaries
- **Automatic actions**: KILL_PID, BLOCK_IP via regex heuristics — zero LLM latency
- **Optional LLM analysis**: Ollama, OpenAI, or Anthropic — gated by interestingness scoring
- **Dashboard SPA**: view alerts, stats, submit feedback
- **Feedback loop**: confirmed alerts become RAG incidents for better future analysis
- **OpenClaw integrated**: gateway methods, HTTP routes, sidecar lifecycle management

## Architecture

```mermaid
graph TB
    subgraph "OpenClaw Gateway"
        P[Plugin: plugin.mjs] -->|register| GW[Gateway WS]
        P -->|registerHttpRoute| R["/kh/*"]
    end

    subgraph "Sidecar (managed by plugin)"
        AG[Agent - eBPF] -->|gRPC Ingest| AN[Analysis :9090]
        AN -->|Tier 1| HEUR[Regex Heuristic]
        HEUR -->|KILL_PID/BLOCK_IP| AG
        AN -->|Tier 2| LLM[LLM Backend]
        LLM -->|alerts only| AL[Alert Store :8080]
        AL -->|feedback| INC[Incident Store]
    end

    subgraph "User"
        D[Dashboard SPA :8181] -->|/kh/api/* proxy| AN
        D -->|confirm/fp| AL
    end

    P -->|startSidecar| AG
    P -->|startSidecar| AN
    P -->|polls every 10s| AL
    P -->|kernelharbor.alert| GW
```

## Installation

### From OpenClaw Marketplace

1. Open OpenClaw Gateway admin
2. Browse Extensions → install KernelHarbor
3. Configure settings (optional)
4. The sidecar starts automatically

### Manual

```bash
# Clone and install
git clone https://github.com/fr4nsyz/KernelHarbor.git
cd KernelHarbor/kernelharbor-openclaw
npm install

# Build binaries
./cli/setup.mjs

# Start dashboard
./cli/dashboard.mjs

# Check status
./cli/status.mjs
```

### OpenClaw Plugin Path

```bash
# Link to OpenClaw plugins directory
ln -s $(pwd) /path/to/openclaw/plugins/kernelharbor-openclaw
```

## Plugin API

### Gateway Methods

| Method | Params | Returns |
|--------|--------|---------|
| `kernelharbor.status` | — | `{ sidecarRunning, alertCount, recentAlerts }` |
| `kernelharbor.alert.feedback` | `{ alertId, feedback }` | `{ status }` |

### Pushed Events

| Event | Payload | When |
|-------|---------|------|
| `kernelharbor.alert` | `Alert` | Every 10s poll |

### HTTP Routes

| Route | Proxy To |
|-------|----------|
| `/kh/dashboard` | Serves `dashboard/index.html` |
| `/kh/api/*` | `http://localhost:8080/api/*` |

### Services

| ID | Description |
|----|-------------|
| `kernelharbor.sidecar` | Manages agent + analysis binary lifecycle |
| `kernelharbor.alert-poller` | Polls alerts from analysis, pushes to gateway |

## Configuration

Configure via OpenClaw Gateway plugin settings:

```json
{
  "analysisAddr": "localhost:9090",
  "dashboardPort": 8181,
  "autoStart": true,
  "binaryDir": ""
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KH_LLM_BACKEND` | `none` | LLM backend: `none`, `ollama`, `openai`, `anthropic` |
| `KH_DASHBOARD_PORT` | `8181` | Dashboard server port |
| `KH_REPO` | `https://github.com/fr4nsyz/KernelHarbor.git` | Repo for `kh-setup` |

## Three-Tier Detection

```mermaid
graph LR
    subgraph "Tier 1 — Heuristic"
        T1I[Ingest] --> T1R[Regex Match]
        T1R -->|match| T1A[KILL_PID / BLOCK_IP]
        T1R -->|no match| T1B[Batch]
    end

    subgraph "Tier 2 — LLM Analysis"
        T1B --> T2S[Interestingness Score]
        T2S -->|< 0.6| T2SK[Skip]
        T2S -->|>= 0.6| T2L[LLM]
        T2L -->|alert + evidence| T2A[Alert Store]
    end

    subgraph "Tier 3 — Periodic"
        T3T[Timer] --> T3S[Summary]
        T3S -->|dashboard| T3D[UI]
    end

    T2A -->|confirm| RAG[Incident Store]
    RAG -->|future retrieval| T2L
```

## Commands

```bash
kh-setup      # Clone + build KernelHarbor binaries
kh-status     # Print service status and alert summary
kh-dashboard  # Start dashboard on :8181
```

## Dashboard

Start the dashboard and open http://localhost:8181:

```bash
kh-dashboard
```

The dashboard shows:
- **24h stats**: total alerts, malicious, suspicious, confirmed, false positives
- **Alert list**: filter by verdict, time range, limit — with confirm/false-positive buttons
- **Auto-refresh**: every 15 seconds

## Feedback Loop

Every alert has Confirm / False Positive buttons. Confirmed alerts become labeled incidents
in the RAG incident store, improving future LLM analysis via similarity search.

```mermaid
sequenceDiagram
    participant U as User
    participant D as Dashboard
    participant A as Analysis API
    participant R as Incident Store

    U->>D: Click Confirm
    D->>A: POST /api/alerts/:id/feedback
    A->>A: Set feedback=confirmed
    A->>R: Update incident as verified
    R-->>A: Next LLM query uses better RAG
    A-->>D: { status: ok }
```

## Development

```bash
# Plugin entry
plugin.mjs

# CLI tools
cli/setup.mjs
cli/status.mjs
cli/dashboard.mjs

# Dashboard SPA
dashboard/index.html
dashboard/app.js
dashboard/style.css

# Detection rules (Falco-compatible)
rules/kernelharbor-rules.yaml

# OpenClaw skill definition
skill/SECURE.SKILL.md
```

## Requirements

- Linux kernel 5.4+ (eBPF)
- OpenClaw Gateway >= 2026.3.24-beta.2
- Go 1.25+ (for building from source)
- clang + llvm + libbpf-dev (for eBPF)
- root/sudo for agent

## License

MIT
