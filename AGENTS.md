# AGENTS.md - KernelHarbor

## Build Commands

```bash
# Build analysis service
cd cmd/analysis && go build -o analysis .

# Build to openclaw bin dir (required for e2e/smoke tests)
cd cmd/analysis && go build -o ../../kernelharbor-openclaw/bin/analysis .
```

## Testing

```bash
# Go unit/e2e tests (in cmd/analysis)
cd cmd/analysis && go test -count=1 -timeout 120s ./...

# OpenClaw E2E tests (tests plugin + dashboard + analysis)
cd kernelharbor-openclaw && node test/e2e.mjs

# Pipeline smoke test (Falco webhook → analysis)
cd kernelharbor-openclaw && node test/smoke.mjs
```

## Running

1. **Start analysis service** (terminal 1):
   ```bash
   cd cmd/analysis && ./analysis
   ```

2. **Start Falco + falcosidekick** (terminal 2, requires sudo):
   ```bash
   sudo falco -r ../rules/kernelharbor-rules.yaml \
     -o json_output=true \
     -o http_output.enabled=true \
     -o http_output.url=http://localhost:2801/
   ```
   Then in terminal 3:
   ```bash
   falcosidekick
   ```
   The analysis service receives events via its HTTP API on `:8080`.

## Protocol

gRPC on port 9090 / HTTP on port 8080 (configurable via `GRPC_ADDRESS` / `HTTP_ADDRESS`)

### Proto file
`proto/agent.proto` defines the service:
- `Ingest(Events)` - sends events to analysis
- `Analyze(query)` - queries AI analysis

## Key Environment Variables

| Variable | Default | Component |
|----------|---------|-----------|
| `ES_ADDRESSES` | `http://localhost:9200` | analysis |
| `OLLAMA_ADDRESS` | `http://localhost:11434` | analysis |
| `OLLAMA_MODEL` | `qwen2.5:7b` | analysis |
| `GRPC_ADDRESS` | `:9090` | analysis |
| `HTTP_ADDRESS` | `:8080` | analysis |
| `PROTOCOL` | `both` | analysis (http, grpc, or both) |
| `KH_API_KEY` | `` | analysis API key auth (empty = disabled) |
| `KH_SIGNING_SECRET` | `` | shared secret for HMAC-SHA256 signing (plugin, empty = disabled) |

## Important Constraints

- **CI has no eBPF**: GitHub Actions runners don't support eBPF - integration tests are skipped in CI
- **External services required**: Analysis needs Elasticsearch 8.x and Ollama running
- **Proto generation**: Run `protoc --go_out=. --go-grpc_out=. proto/agent.proto` after editing proto, then fix package names: `sed -i 's/package kernelharborpb/package proto/' cmd/agent/proto/*.go` and `sed -i 's/package kernelharborpb/package pb/' cmd/analysis/pb/*.go`

## Project Structure

```
cmd/analysis/       # AI analysis pipeline (Go + gRPC + HTTP)
proto/                # Protocol Buffer definitions
bpf/                  # eBPF C programs (for reference, not built by default)
kernelharbor-openclaw/  # OpenClaw plugin (Falco-based event collection)
scripts/              # test scripts
```

## Pre-commit

- Run `go fmt` before commits
- Ensure unit tests pass: `make test` (runs analysis tests)

## Falco Integration

The preferred way to collect kernel events is via Falco + falcosidekick:
- `kernelharbor-openclaw/rules/kernelharbor-rules.yaml` — detection rules
- `kernelharbor-openclaw/plugin.mjs` — orchestrates Falco + falcosidekick + analysis
- Events flow: `Falco → http_output → falcosidekick → signer(HMAC) → webhook → plugin → analysis /ingest`
- HMAC signing: when `KH_SIGNING_SECRET` is set, `signer.mjs` computes HMAC-SHA256 of the body and the webhook verifies it

The legacy eBPF agent binaries (`cmd/agent/`, `cmd/execve-tracer/`, etc.) are preserved
in the repo but no longer used by the plugin or CI.
