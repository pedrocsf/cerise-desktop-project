#!/bin/sh

FLAG_PATH="/etc/cerise/lockdown_modules"
TIMEOUT_SECONDS=120
MIN_BPFTRACE=10
CHANNEL_PATH="/dev/vport0p11"
LOG_TAG="cerise-lockdown"

log() {
    logger -t "$LOG_TAG" "$1"
}

if [ ! -e "$FLAG_PATH" ]; then
    log "lockdown disabled"
    exit 0
fi

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT_SECONDS" ]; do
    if [ -e "$CHANNEL_PATH" ]; then
        count=$(pgrep -c -x bpftrace 2>/dev/null)
        count=${count:-0}
        if [ "$count" -ge "$MIN_BPFTRACE" ]; then
            if output=$(sysctl -w kernel.modules_disabled=1 2>&1); then
                log "lockdown applied: $output"
                exit 0
            fi
            log "lockdown failed: $output"
            exit 1
        fi
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

log "error: sensors not ready after ${TIMEOUT_SECONDS}s, lockdown not applied"
exit 1
