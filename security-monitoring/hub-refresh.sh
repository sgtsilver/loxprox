#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — CrowdSec Hub Refresh (daily)
# ═══════════════════════════════════════════════════════════════════════════════
# The AppSec virtual-patching rules are how new CVEs reach this gateway. This
# script is the ONLY unattended hub update. The CrowdSec package ships its own
# crowdsec-hubupdate.timer, which runs `cscli hub update && cscli hub upgrade`
# every night: EVERY installed item, no snapshot, no rollback. deploy.sh masks
# that timer (2026-10), and this script runs daily instead, so the rules stay
# as fresh as the package timer kept them. (A CrowdSec package upgrade runs
# `cscli hub upgrade` in its postinst too; unattended-upgrades does not take
# packages from the CrowdSec repository, so that happens only when an operator
# upgrades CrowdSec.) Daily (04:30, cron):
#   1. snapshot the hub state (index, items, installed-item links) to a dated
#      tarball under /var/lib/loxprox/hub-snapshots/ (the last 7 are kept)
#   2. cscli hub update
#   3. upgrade ONLY crowdsecurity/appsec-virtual-patching — nothing else is
#      upgraded unattended (a parser or scenario change can alter what is banned)
#   4. reload crowdsec only if an installed item's version changed (the
#      collection OR one of its rules), then verify the service is active.
#      If the reload fails or crowdsec is not active: restore the snapshot,
#      restart, re-check, CRITICAL alert. AppSec fails closed — with crowdsec
#      down nginx answers 500 to every request, so this must not wait for a human.
#   5. one Discord alert listing the OTHER outdated hub items for a human —
#      only when that list differs from the one last reported (see
#      report_outdated); the log lists them on every run
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

CONFIG_FILE="${LOXPROX_CONFIG:-/etc/loxprox/config.env}"
if [[ -f "$CONFIG_FILE" ]]; then
    set -a
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    set +a
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISCORD="${DISCORD_ALERT_PATH:-$SCRIPT_DIR/discord-alert.sh}"
LOG_FILE="${LOXPROX_HUB_LOG:-/var/log/loxprox-hub-refresh.log}"
LOCK_FILE="${LOXPROX_HUB_LOCK:-/run/loxprox-hub-refresh.lock}"
PATCH_COLLECTION="crowdsecurity/appsec-virtual-patching"
SETTLE_SECONDS="${HUB_REFRESH_SETTLE:-5}"   # let crowdsec finish reloading before checking
CSCLI_TIMEOUT="${HUB_REFRESH_CSCLI_TIMEOUT:-300}"

# CrowdSec's package layout (config.yaml config_paths): hub_dir holds the hub
# index (.index.json) and the downloaded items; config_dir/<type>/ holds the
# INSTALLED items — symlinks into hub_dir, plus local files such as deploy.sh's
# whitelist parser and the loxprox scenarios. An upgrade changes both.
HUB_DIR="${LOXPROX_CROWDSEC_HUB_DIR:-/var/lib/crowdsec/hub}"
CROWDSEC_DIR="${LOXPROX_CROWDSEC_DIR:-/etc/crowdsec}"
SNAPSHOT_DIR="${LOXPROX_HUB_SNAPSHOT_DIR:-/var/lib/loxprox/hub-snapshots}"
SNAPSHOT_KEEP=7   # a week of daily runs
# The OTHER outdated items last reported on Discord (report_outdated).
OUTDATED_STATE="${LOXPROX_HUB_OUTDATED_STATE:-/var/lib/loxprox/hub-outdated-reported}"
SNAPSHOT_PATHS=("$HUB_DIR")
for _type in collections parsers scenarios postoverflows appsec-rules appsec-configs contexts; do
    SNAPSHOT_PATHS+=("$CROWDSEC_DIR/$_type")
done
SNAPSHOT=""   # this run's tarball (take_snapshot)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE" || true; }

alert() { "$DISCORD" "$1" "$2" "$3" 2>/dev/null || log "WARN: alert '$2' could not be sent"; }

# Installed version of the patch collection ("" when unreadable). The JSON
# shape differs between cscli releases, so find the object by name wherever it is.
collection_version() {
    timeout "$CSCLI_TIMEOUT" cscli collections list -o json 2>/dev/null \
        | jq -r --arg n "$PATCH_COLLECTION" \
            '[.. | objects | select(.name? == $n)] | .[0] | (.local_version // .version // "")' 2>/dev/null \
        || true
}

# "name@installed-version" of every installed hub item, sorted ("" when
# unreadable). The collection's own version is not enough: an updated rule
# under an unchanged collection version is installed by the upgrade too.
installed_versions() {
    timeout "$CSCLI_TIMEOUT" cscli hub list -o json 2>/dev/null \
        | jq -r '[.. | objects | select(has("name") and has("local_version")) | "\(.name)@\(.local_version // "")"] | unique | .[]' 2>/dev/null \
        || true
}

# Names of installed hub items with an update available, one per line, sorted.
# Returns 1 when the list is unreadable — that is not "nothing is outdated".
outdated_items() {
    local json
    json=$(timeout "$CSCLI_TIMEOUT" cscli hub list -o json 2>/dev/null) || true
    [[ -n "$json" ]] || return 1
    jq -r '[.. | objects | select((.status? // "") | tostring | test("update-available")) | .name] | unique | .[]' <<< "$json" 2>/dev/null
}

# One INFO alert listing the OTHER outdated hub items ($1: sorted, one per
# line), sent only when that list differs from the one last reported. The
# script runs daily, and the same backlog re-sent every morning is noise that
# teaches people to ignore the channel; a new item, or one dropping out, is
# news and re-sends the whole current list. An empty list clears the state,
# so a later backlog is reported again. The state is written only after the
# alert went out, so a failed send is retried by the next run.
report_outdated() {
    local others="$1" last=""
    if [[ -z "$others" ]]; then
        rm -f -- "$OUTDATED_STATE" 2>/dev/null || true
        return 0
    fi
    log "Other outdated hub items: $(tr '\n' ' ' <<< "$others")"
    if [[ -f "$OUTDATED_STATE" ]]; then
        last=$(cat -- "$OUTDATED_STATE" 2>/dev/null) || last=""
    fi
    if [[ "$others" == "$last" ]]; then
        log "Same outdated items as already reported — no alert (delete ${OUTDATED_STATE} to re-send)"
        return 0
    fi
    if ! "$DISCORD" "INFO" "CrowdSec Hub Items Outdated" "These installed hub items have updates and were NOT upgraded automatically:\n${others//$'\n'/\\n}\n\nReview, then: sudo cscli hub upgrade && sudo systemctl reload crowdsec" 2>/dev/null; then
        log "WARN: alert 'CrowdSec Hub Items Outdated' could not be sent — the next run tries again"
        return 0
    fi
    if ! { mkdir -p "$(dirname "$OUTDATED_STATE")" \
            && printf '%s\n' "$others" > "$OUTDATED_STATE.tmp" \
            && mv -f "$OUTDATED_STATE.tmp" "$OUTDATED_STATE"; } 2>/dev/null; then
        rm -f -- "$OUTDATED_STATE.tmp" 2>/dev/null || true
        log "WARN: could not record the reported items in ${OUTDATED_STATE} — the next run reports them again"
    fi
    return 0
}

# Tarball of SNAPSHOT_PATHS (those that exist) into SNAPSHOT_DIR; sets SNAPSHOT.
# Symlinks are stored as symlinks. Keeps the newest SNAPSHOT_KEEP.
take_snapshot() {
    local p rels=() snap err
    for p in "${SNAPSHOT_PATHS[@]}"; do
        [[ "$p" == /?* ]] || { log "Refusing to snapshot a non-absolute path: '$p'"; return 1; }
        [[ -e "$p" ]] && rels+=("${p#/}")
    done
    (( ${#rels[@]} )) || { log "Nothing to snapshot (no ${HUB_DIR}, no ${CROWDSEC_DIR}/<type>)"; return 1; }
    mkdir -p "$SNAPSHOT_DIR" 2>/dev/null && chmod 700 "$SNAPSHOT_DIR" 2>/dev/null \
        || { log "Cannot create ${SNAPSHOT_DIR}"; return 1; }
    snap="$SNAPSHOT_DIR/hub-$(date +%Y%m%d-%H%M%S).tar.gz"
    if ! err=$( (umask 077; tar -czf "$snap.tmp" -C / "${rels[@]}") 2>&1 ); then
        rm -f "$snap.tmp"
        log "Snapshot failed: ${err:0:300}"
        return 1
    fi
    mv -f "$snap.tmp" "$snap" || return 1
    SNAPSHOT="$snap"
    log "Hub state snapshotted to $snap"

    local snaps=("$SNAPSHOT_DIR"/hub-[0-9]*.tar.gz) i   # names sort by date
    [[ -e "${snaps[0]}" ]] || snaps=()
    for (( i = 0; i < ${#snaps[@]} - SNAPSHOT_KEEP; i++ )); do
        rm -f -- "${snaps[i]}"
    done
    return 0
}

# Put SNAPSHOT_PATHS back exactly as in the tarball: extracted to a staging
# dir first (a damaged tarball changes nothing), then each path is replaced
# whole, so items the upgrade ADDED are gone too. The live copy is moved aside
# before the swap and moved back if the swap fails — never left deleted.
restore_snapshot() {
    local snap="$1" stage p rel old
    [[ -f "$snap" ]] || return 1
    stage=$(mktemp -d "$SNAPSHOT_DIR/.restore.XXXXXXXX") || return 1
    if ! tar -xzf "$snap" -C "$stage" 2>/dev/null; then
        rm -rf -- "$stage"
        return 1
    fi
    for p in "${SNAPSHOT_PATHS[@]}"; do
        rel="${p#/}"
        [[ -e "$stage/$rel" ]] || continue
        old="$p.loxprox-pre-restore"
        rm -rf -- "$old"
        if [[ -e "$p" || -L "$p" ]] && ! mv -- "$p" "$old"; then
            rm -rf -- "$stage"
            return 1
        fi
        if ! mv -- "$stage/$rel" "$p"; then
            [[ -e "$old" ]] && mv -- "$old" "$p"
            rm -rf -- "$stage"
            return 1
        fi
        rm -rf -- "$old"
    done
    rm -rf -- "$stage"
    return 0
}

# The upgrade broke crowdsec ($1 = how). Restore, restart, re-check, alert; exits 1.
rollback() {
    local why="$1" before="$2" after="$3" changed="$4" restored=0 now_version
    log "${why} — restoring ${SNAPSHOT}"
    if restore_snapshot "$SNAPSHOT"; then
        restored=1
        log "Hub state restored from ${SNAPSHOT}"
    else
        log "Restoring ${SNAPSHOT} FAILED"
    fi
    systemctl restart crowdsec >/dev/null 2>&1 || log "systemctl restart crowdsec returned non-zero"
    sleep "$SETTLE_SECONDS"

    local changed_msg="" lines
    if [[ -n "$changed" ]]; then
        lines=$(head -n 15 <<< "$changed" | sed 's/^/  /')
        changed_msg="Items the upgrade changed (name@version):\n${lines//$'\n'/\\n}\n"
    fi
    if systemctl is-active --quiet crowdsec; then
        now_version=$(collection_version)
        if (( restored )); then
            log "crowdsec is active again on the previous rules (${PATCH_COLLECTION} ${now_version:-?})"
            alert "CRITICAL" "CrowdSec Rule Update Rolled Back" "Upgrading ${PATCH_COLLECTION} (${before:-?} -> ${after:-?}) broke crowdsec: ${why}.\nThe hub state from before the upgrade was restored and crowdsec restarted; it is active again with ${PATCH_COLLECTION} ${now_version:-?}. The virtual patches of this update are NOT active.\n${changed_msg}\nCheck: sudo journalctl -u crowdsec -n 80 --no-pager\nThe next daily run (04:30) tries the upgrade again."
        else
            log "crowdsec is active, but the snapshot could not be restored — running the upgraded rules"
            alert "CRITICAL" "CrowdSec Rule Rollback Failed" "Upgrading ${PATCH_COLLECTION} (${before:-?} -> ${after:-?}) broke crowdsec: ${why}.\nRestoring ${SNAPSHOT} failed; crowdsec came back after a restart and runs the UPGRADED rules.\n${changed_msg}\nCheck: sudo journalctl -u crowdsec -n 80 --no-pager; sudo cscli hub list"
        fi
        exit 1
    fi

    log "crowdsec is still NOT active after the restore and a restart"
    local restore_line="The previous rules were restored from ${SNAPSHOT}."
    (( restored )) || restore_line="Restoring ${SNAPSHOT} FAILED — restore it by hand:\n  sudo tar -xzf ${SNAPSHOT} -C / && sudo systemctl restart crowdsec"
    alert "CRITICAL" "CrowdSec Down — Gateway Serving Errors" "crowdsec is not running. Upgrading ${PATCH_COLLECTION} (${before:-?} -> ${after:-?}) broke it (${why}), and it did not come back after a restore and a restart.\nAppSec fails closed: nginx answers 500 to every request and the Loxone apps cannot connect.\n${restore_line}\n\nRecover:\n  sudo journalctl -u crowdsec -n 80 --no-pager\n  sudo systemctl restart crowdsec\n  systemctl is-active crowdsec\nSnapshots: ${SNAPSHOT_DIR}"
    exit 1
}

main() {
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$LOCK_FILE" || true
        flock -n 9 || { log "Another hub refresh is running — exiting"; exit 0; }
    fi

    log "Hub refresh started"
    # Before anything on disk changes — `hub update` rewrites the index — so a
    # rollback returns exactly the state crowdsec last started with. No
    # snapshot, no upgrade: there would be nothing to roll back to.
    if ! take_snapshot; then
        alert "WARNING" "CrowdSec Hub Snapshot Failed" "The hub state could not be snapshotted to ${SNAPSHOT_DIR}, so the AppSec virtual-patching upgrade was skipped (without a snapshot there is no rollback). Check: df -h /var/lib; tail ${LOG_FILE}"
        exit 1
    fi

    if ! timeout "$CSCLI_TIMEOUT" cscli hub update >/dev/null 2>&1; then
        log "cscli hub update failed"
        alert "WARNING" "CrowdSec Hub Update Failed" "cscli hub update failed; the AppSec virtual-patching rules were not refreshed. Check: sudo cscli hub update"
        exit 1
    fi

    local before after before_items after_items
    before=$(collection_version)
    before_items=$(installed_versions)
    if ! timeout "$CSCLI_TIMEOUT" cscli collections upgrade "$PATCH_COLLECTION" >/dev/null 2>&1; then
        log "cscli collections upgrade $PATCH_COLLECTION failed"
        # A half-done upgrade on disk would surface at the next restart; put the
        # files back to what the running crowdsec has loaded.
        local restored_note="The hub files were put back from the pre-upgrade snapshot; crowdsec keeps running the rules it has loaded."
        if restore_snapshot "$SNAPSHOT"; then
            log "Hub state restored from ${SNAPSHOT}"
        else
            log "Restoring ${SNAPSHOT} FAILED"
            restored_note="Restoring the pre-upgrade snapshot ${SNAPSHOT} FAILED — the files on disk may be half-upgraded; check sudo cscli hub list before restarting crowdsec."
        fi
        alert "WARNING" "AppSec Rules Upgrade Failed" "Upgrading ${PATCH_COLLECTION} failed. ${restored_note}\nCheck: sudo cscli collections upgrade ${PATCH_COLLECTION}"
        exit 1
    fi
    after=$(collection_version)
    after_items=$(installed_versions)

    local reload=0 changed=""
    if [[ -z "$before_items" || -z "$after_items" ]]; then
        log "Installed hub item versions unreadable — reloading so an upgrade cannot stay unloaded"
        reload=1
    elif [[ "$before_items" != "$after_items" ]]; then
        changed=$(grep -vxF -f <(printf '%s\n' "$before_items") <<< "$after_items" || true)
        reload=1
    fi
    if [[ -n "$after" && "$before" != "$after" ]]; then
        reload=1
    fi

    if (( reload )); then
        log "${PATCH_COLLECTION}: ${before:-?} -> ${after:-?}${changed:+; changed: $(tr '\n' ' ' <<< "$changed")}; reloading crowdsec"
        if ! systemctl reload crowdsec >/dev/null 2>&1; then
            rollback "systemctl reload crowdsec failed" "$before" "$after" "$changed"
        fi
        sleep "$SETTLE_SECONDS"
        if ! systemctl is-active --quiet crowdsec; then
            rollback "crowdsec was not active ${SETTLE_SECONDS}s after the reload" "$before" "$after" "$changed"
        fi
        log "crowdsec is active after the reload"
    else
        log "${PATCH_COLLECTION} unchanged (${after:-unknown}), no installed item changed; no reload"
    fi

    local others
    if others=$(outdated_items); then
        report_outdated "$(grep -vxF "$PATCH_COLLECTION" <<< "$others" || true)"
    else
        log "Outdated hub items unreadable (cscli hub list) — not reported this run"
    fi
    log "Hub refresh finished"
}

# Only run when executed, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
