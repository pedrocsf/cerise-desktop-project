#!/bin/sh

FLAG_PATH="/etc/cerise/lockdown_modules"
SMBIOS_TYPE=11
SMBIOS_PATTERN="(^|[[:space:]:])cerisemodlock=1[[:space:]]*$"
TIMEOUT_SECONDS=120
MIN_BPFTRACE=10
CHANNEL_PATH="/dev/vport0p11"
LOG_TAG="cerise-lockdown"

log() {
    logger -t "$LOG_TAG" "$1"
}

flag_enabled() {
    [ -e "$FLAG_PATH" ]
}

smbios_enabled() {
    command -v dmidecode >/dev/null 2>&1 || return 1
    dmidecode -t "$SMBIOS_TYPE" 2>/dev/null | grep -q -E -e "$SMBIOS_PATTERN"
}

sensors_ready() {
    [ -e "$CHANNEL_PATH" ] || return 1
    count=$(pgrep -c -x bpftrace 2>/dev/null)
    count=${count:-0}
    [ "$count" -ge "$MIN_BPFTRACE" ]
}

apply_lockdown() {
    if output=$(sysctl -w kernel.modules_disabled=1 2>&1); then
        log "lockdown applied: $output"
        exit 0
    fi
    log "lockdown failed: $output"
    exit 1
}

wait_and_apply() {
    elapsed=0
    while [ "$elapsed" -lt "$TIMEOUT_SECONDS" ]; do
        if sensors_ready; then
            apply_lockdown
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    log "error: sensors not ready after ${TIMEOUT_SECONDS}s, lockdown not applied"
    exit 1
}

main() {
    if flag_enabled; then
        log "lockdown enabled (flag file)"
    elif smbios_enabled; then
        log "lockdown enabled (smbios)"
    else
        log "lockdown disabled"
        exit 0
    fi
    wait_and_apply
}

main
