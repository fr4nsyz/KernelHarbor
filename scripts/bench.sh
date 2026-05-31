#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/bench-results"
mkdir -p "${BENCH_DIR}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ANALYSIS_OUT="${BENCH_DIR}/analysis-${TIMESTAMP}.txt"
AGENT_OUT="${BENCH_DIR}/agent-${TIMESTAMP}.txt"
AGENT_EBPF_OUT="${BENCH_DIR}/agent-ebpf-${TIMESTAMP}.txt"
REPORT_OUT="${BENCH_DIR}/report-${TIMESTAMP}.md"

echo "=== KernelHarbor Benchmark Suite ==="
echo "Timestamp: ${TIMESTAMP}"
echo "Results dir: ${BENCH_DIR}"
echo ""

echo "--- Analysis Service Benchmarks ---"
echo "Running: go test -bench=. -benchmem -count=3 -timeout=30m ./..."

(cd "${REPO_ROOT}/cmd/analysis" && go test -bench=. -benchmem -count=3 -timeout=30m ./... 2>&1) | tee "${ANALYSIS_OUT}" || true

echo ""
echo "--- Agent Synthetic Benchmarks ---"
echo "Running: go test -bench=. -benchmem -count=3 -timeout=10m ./..."

(cd "${REPO_ROOT}/cmd/agent" && go test -bench=. -benchmem -count=3 -timeout=10m ./... 2>&1) | tee "${AGENT_OUT}" || true

echo ""
echo "--- Agent eBPF Benchmarks (requires root + -tags=ebpf) ---"
if [ "$(id -u)" -eq 0 ]; then
    echo "Running as root, enabling eBPF benchmarks..."
    (cd "${REPO_ROOT}/cmd/agent" && go test -tags=ebpf -bench=BenchmarkEbpf -benchmem -count=1 -timeout=10m ./... 2>&1) | tee "${AGENT_EBPF_OUT}" || true
else
    echo "Not running as root, skipping eBPF benchmarks."
    echo "Re-run with: sudo $0"
fi

echo ""
echo "--- Generating Markdown Report ---"

cat > "${REPORT_OUT}" <<'HEADER'
# KernelHarbor Benchmark Report

HEADER

echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${REPORT_OUT}"
echo "" >> "${REPORT_OUT}"
echo "## Analysis Service" >> "${REPORT_OUT}"
echo "" >> "${REPORT_OUT}"
echo '```' >> "${REPORT_OUT}"
grep -E '(Benchmark|ns/op|allocs/op)' "${ANALYSIS_OUT}" >> "${REPORT_OUT}" 2>/dev/null || true
echo '```' >> "${REPORT_OUT}"
echo "" >> "${REPORT_OUT}"
echo "## Agent (Synthetic)" >> "${REPORT_OUT}"
echo "" >> "${REPORT_OUT}"
echo '```' >> "${REPORT_OUT}"
grep -E '(Benchmark|ns/op|allocs/op)' "${AGENT_OUT}" >> "${REPORT_OUT}" 2>/dev/null || true
echo '```' >> "${REPORT_OUT}"

if [ -f "${AGENT_EBPF_OUT}" ] && [ -s "${AGENT_EBPF_OUT}" ]; then
    echo "" >> "${REPORT_OUT}"
    echo "## Agent (eBPF)" >> "${REPORT_OUT}"
    echo "" >> "${REPORT_OUT}"
    echo '```' >> "${REPORT_OUT}"
    grep -E '(Benchmark|ns/op|allocs/op)' "${AGENT_EBPF_OUT}" >> "${REPORT_OUT}" 2>/dev/null || true
    echo '```' >> "${REPORT_OUT}"
fi

echo ""
echo "=== Benchmarks Complete ==="
echo "Report saved to: ${REPORT_OUT}"
echo "Raw results: ${ANALYSIS_OUT} ${AGENT_OUT}"
if [ -f "${AGENT_EBPF_OUT}" ] && [ -s "${AGENT_EBPF_OUT}" ]; then
    echo "eBPF results: ${AGENT_EBPF_OUT}"
fi
