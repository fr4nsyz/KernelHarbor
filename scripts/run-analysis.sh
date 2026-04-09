#!/bin/bash

LOGFILE="analysis.log"
PIDFILE="/tmp/analysis.pid"

echo "=== Analysis Server Log ==="
echo "Logging started at $(date)"

exec > >(tee -a "$LOGFILE") 2>&1

cd cmd/analysis || exit 1

./analysis 2>&1 | while IFS= read -r line; do
    echo "$line"
    
    if echo "$line" | grep -qE 'Analysis result.*:.*(malicious|suspicious).*\(0\.[89]'; then
        exec 1>&1 2>&1
        echo "=== MALICIOUS EVENT DETECTED ==="
        echo "Redirecting all output to terminal"
        echo "=================================="
    fi
done
