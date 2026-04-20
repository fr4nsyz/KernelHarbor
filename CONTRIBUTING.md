# Contributing to KernelHarbor

## Development

### Prerequisites

- Go 1.25+
- clang, llvm, libbpf-dev
- bpftool (usually in `linux-tools-$(uname -r)`)
- Elasticsearch 8.x (for integration tests)
- Ollama (for AI analysis tests)

### Building

The top-level `Makefile` is the source of truth for builds. It generates
`bpf/vmlinux.h` from the running kernel's BTF, runs `go generate` (bpf2go) for
each component that uses eBPF, and then compiles the Go binaries.

```bash
# Build everything (tracers + agent + analysis)
make            # alias for `make build`

# Or build individual components
make agent          # consolidated tracer (execve + open + openat + connect)
make analysis       # AI analysis service (gRPC + HTTP)
make execve-tracer  # standalone execve tracer
make open-tracer    # standalone open tracer
make openat-tracer  # standalone openat tracer

# Clean binaries, bpf2go output, and vmlinux.h
make clean
```

Notes:

- `bpf/vmlinux.h` is regenerated via `bpftool btf dump` whenever it is missing.
  It is gitignored.
- Each tracer's `cmd/<tracer>/gen.go` holds the `//go:generate` directive that
  drives bpf2go; the agent's directives live in `cmd/agent/gen.go` and must be
  kept in sync with `AGENT_BPF` / `AGENT_GENGO` in the `Makefile`.
- The eBPF C sources live under `bpf/` and are shared between the standalone
  tracers and the consolidated `agent`.

### Testing

```bash
# Unit tests
make test

# E2E tests (requires ES + Ollama)
./scripts/e2e-test.sh

# Integration tests (requires root + eBPF)
sudo ./scripts/integration-test.sh
```

## CI/CD Limitations

### GitHub Actions

**Important:** GitHub Actions runners (ubuntu-latest) do **not** support eBPF. This means:

- **Integration tests are skipped** in CI - they require a self-hosted runner with eBPF capabilities
- **eBPF tracer builds are tested** for compilation only, not runtime
- **E2E tests run** but without real kernel events

### Local Testing Required

For full test coverage, run tests locally:

```bash
# Full test suite
sudo ./scripts/integration-test.sh
```

### Recommended Local Setup

1. Use a VM or bare metal Linux machine with eBPF support
2. Or use a self-hosted GitHub Actions runner with eBPF

## Code Style

- Run `go fmt` before commits
- Add unit tests for new functionality
- Update README if adding new features

## Pull Requests

1. Ensure unit tests pass
2. Test E2E locally if possible
3. Update documentation as needed
