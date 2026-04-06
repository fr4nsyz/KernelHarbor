# Contributing to KernelHarbor

## Development

### Prerequisites

- Go 1.25+
- clang, llvm, libbpf-dev
- bpftool (usually in `linux-tools-$(uname -r)`)
- Elasticsearch 8.x (for integration tests)
- Ollama (for AI analysis tests)

### Building

```bash
# Generate vmlinux.h (one-time, requires bpftool)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Generate eBPF Go bindings (re-run after changing .bpf.c files)
go generate ./cmd/execve-tracer/
go generate ./cmd/open-tracer/
go generate ./cmd/openat-tracer/

# Build all components
go build -o cmd/analysis/analysis ./cmd/analysis
go build -o cmd/execve-tracer/execve-tracer ./cmd/execve-tracer
go build -o cmd/open-tracer/open-tracer ./cmd/open-tracer
go build -o cmd/openat-tracer/openat-tracer ./cmd/openat-tracer
```

### Testing

```bash
# Unit tests (all platforms)
cd cmd/analysis && go test -v ./...

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
