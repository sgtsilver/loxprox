#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — CrowdSec Hub Refresh (daily)
# ═══════════════════════════════════════════════════════════════════════════════
# CrowdSec's hub items (scenarios, parsers, collections, AppSec virtual
# patches) are how new attack patterns and CVEs reach this gateway. This
# script is the ONLY unattended hub update. It replaces the CrowdSec package's
# crowdsec-hubupdate.timer, which ran `cscli hub update && cscli hub upgrade`
# every night with no snapshot and no rollback; deploy.sh masks that timer
# (2026-10). Same freshness — every installed item, daily, so new ban
# scenarios and virtual patches keep arriving — but behind a verified
# snapshot and an automatic rollback. The maintainer accepted (2026-10-19)
# that an upstream parser or scenario change can alter what is banned
# without a review. (A CrowdSec package upgrade runs `cscli hub upgrade` in its postinst
# too; unattended-upgrades does not take packages from the CrowdSec
# repository, so that happens only when an operator upgrades CrowdSec.)
# Daily (04:30, cron):
#   1. ask CrowdSec where its hub is (resolve_layout) and snapshot the hub
#      index, the hub's item files and the installed-item links to a dated
#      tarball under /var/lib/loxprox/hub-snapshots/ (the last 7 are kept).
#      The tarball is checked before anything changes; no usable snapshot →
#      no upgrade, WARNING.
#   2. cscli hub update
#   3. cscli hub upgrade — every installed item, never --force: tainted
#      (locally modified) items and local files (deploy.sh's whitelist, the
#      loxprox scenarios) stay as they are
#   4. reload crowdsec only if an installed item's version changed, then
#      verify the service is active. If the reload fails or crowdsec is not
#      active: restore the snapshot, restart, re-check, CRITICAL alert naming
#      the changed items. AppSec fails closed — with crowdsec down nginx
#      answers 500 to every request, so this must not wait for a human.
#      The changed items are logged; a successful upgrade sends no alert.
#   5. one Discord alert listing the installed items that are still not up
#      to date after the upgrade (tainted, or still update-available) — only
#      when that list differs from the one last reported (report_not_upgraded)
# Not in the snapshot: the data files `cscli hub upgrade` refreshes under
# data_dir (lists, GeoIP databases). data_dir also holds the LAPI database,
# which a restore must never roll back.
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
SETTLE_SECONDS="${HUB_REFRESH_SETTLE:-5}"   # let crowdsec finish reloading before checking
CSCLI_TIMEOUT="${HUB_REFRESH_CSCLI_TIMEOUT:-300}"

# CrowdSec's config: config_paths names hub_dir (the hub index and the
# downloaded item files) and config_dir, whose <type>/ dirs hold the
# INSTALLED items — links into hub_dir, plus local files such as deploy.sh's
# whitelist parser and the loxprox scenarios. An upgrade changes both.
CROWDSEC_CONFIG="${LOXPROX_CROWDSEC_CONFIG:-/etc/crowdsec/config.yaml}"
ITEM_TYPES=(collections parsers scenarios postoverflows appsec-rules appsec-configs contexts)
SNAPSHOT_DIR="${LOXPROX_HUB_SNAPSHOT_DIR:-/var/lib/loxprox/hub-snapshots}"
SNAPSHOT_KEEP=7   # a week of daily runs
# The not-upgraded items last reported on Discord (report_not_upgraded).
OUTDATED_STATE="${LOXPROX_HUB_OUTDATED_STATE:-/var/lib/loxprox/hub-outdated-reported}"
HUB_DIR="" HUB_INDEX="" CROWDSEC_DIR=""   # resolve_layout
SNAPSHOT_PATHS=()                          # resolve_layout
SNAPSHOT=""                                # this run's tarball (take_snapshot)
SNAPSHOT_ERROR=""                          # why there is no usable snapshot

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE" || true; }

alert() { "$DISCORD" "$1" "$2" "$3" 2>/dev/null || log "WARN: alert '$2' could not be sent"; }

# One of CrowdSec's config_paths as CrowdSec itself resolves it: `cscli config
# show` first, then config.yaml.local and config.yaml. $1 = the field under
# Config.ConfigPaths, $2 = its config.yaml key. Prints an absolute path
# without a trailing slash, or nothing.
crowdsec_path() {
    local v f
    v=$(timeout "$CSCLI_TIMEOUT" cscli config show --key "Config.ConfigPaths.$1" 2>/dev/null) || v=""
    if [[ "$v" != /?* || "$v" == *[[:space:]]* ]]; then
        v=""
        for f in "$CROWDSEC_CONFIG.local" "$CROWDSEC_CONFIG"; do
            [[ -r "$f" ]] || continue
            v=$(sed -nE -e "/^[[:space:]]+$2:/{" -e "s/^[[:space:]]+$2:[[:space:]]*[\"']?([^\"'#[:space:]]*).*/\\1/p" -e "q" -e "}" "$f" 2>/dev/null) || v=""
            [[ "$v" == /?* ]] && break
            v=""
        done
    fi
    printf '%s' "${v%/}"
}

# Where CrowdSec keeps its hub — never assumed. The Debian package keeps it in
# /etc/crowdsec/hub (production, 2026-10). The first version of this script
# assumed /var/lib/crowdsec/hub, which does not exist there: its snapshot held
# only the installed-item links, and a rollback would have put back links to
# the UPGRADED files. LOXPROX_CROWDSEC_HUB_DIR / _HUB_INDEX / _DIR override
# (tests). The paths are made canonical, because tar stores a symlinked
# directory as the link, not its content. Sets SNAPSHOT_ERROR on failure.
resolve_layout() {
    local hub index cfg t
    hub="${LOXPROX_CROWDSEC_HUB_DIR:-}"
    if [[ -n "$hub" ]]; then
        index="${LOXPROX_CROWDSEC_HUB_INDEX:-$hub/.index.json}"
    else
        hub=$(crowdsec_path HubDir hub_dir)
        hub="${hub:-/etc/crowdsec/hub}"
        index=$(crowdsec_path HubIndexFile index_path)
        index="${index:-$hub/.index.json}"
    fi
    cfg="${LOXPROX_CROWDSEC_DIR:-$(crowdsec_path ConfigDir config_dir)}"
    cfg="${cfg:-/etc/crowdsec}"
    log "CrowdSec layout: hub_dir=${hub} index=${index} config_dir=${cfg}"
    [[ -d "$hub" ]] || { SNAPSHOT_ERROR="hub_dir ${hub} does not exist"; return 1; }
    [[ -s "$index" ]] || { SNAPSHOT_ERROR="hub index ${index} is missing or empty"; return 1; }
    [[ -d "$cfg" ]] || { SNAPSHOT_ERROR="config_dir ${cfg} does not exist"; return 1; }
    if ! HUB_DIR=$(readlink -f -- "$hub") || ! HUB_INDEX=$(readlink -f -- "$index") \
            || ! CROWDSEC_DIR=$(readlink -f -- "$cfg"); then
        SNAPSHOT_ERROR="cannot resolve ${hub}, ${index} or ${cfg}"
        return 1
    fi
    if [[ "$HUB_DIR" == / || "$CROWDSEC_DIR" == / || "$HUB_DIR" == "$CROWDSEC_DIR" \
            || "$CROWDSEC_DIR/" == "$HUB_DIR"/* ]]; then
        SNAPSHOT_ERROR="hub_dir ${HUB_DIR} and config_dir ${CROWDSEC_DIR} overlap"
        return 1
    fi
    SNAPSHOT_PATHS=("$HUB_DIR")
    [[ "$HUB_INDEX" == "$HUB_DIR"/* ]] || SNAPSHOT_PATHS+=("$HUB_INDEX")
    for t in "${ITEM_TYPES[@]}"; do
        SNAPSHOT_PATHS+=("$CROWDSEC_DIR/$t")
    done
    return 0
}

# Proves that the tarball $1 can undo an upgrade. Extracted to a staging dir,
# it must hold the hub index, and for every installed item linked into the hub
# the link plus the item's file as a REGULAR file (a link in the tarball would
# restore a pointer to the upgraded file). An installed link that resolves
# outside hub_dir cannot be restored, so it fails the check too; a dangling
# one has nothing to restore and is skipped. Prints the number of items
# checked, or (returning 1) why the snapshot is not usable.
verify_snapshot() {
    local stage link target t n=0 bad=""
    local -a dirs=()
    stage=$(mktemp -d "$SNAPSHOT_DIR/.verify.XXXXXXXX") || { echo "no staging dir"; return 1; }
    if ! tar -xzf "$1" -C "$stage" 2>/dev/null; then
        rm -rf -- "$stage"
        echo "the tarball does not extract"
        return 1
    fi
    if [[ ! -f "$stage$HUB_INDEX" || -L "$stage$HUB_INDEX" || ! -s "$stage$HUB_INDEX" ]]; then
        rm -rf -- "$stage"
        echo "the hub index ${HUB_INDEX} is not in it"
        return 1
    fi
    for t in "${ITEM_TYPES[@]}"; do
        [[ -d "$CROWDSEC_DIR/$t" ]] && dirs+=("$CROWDSEC_DIR/$t")
    done
    if (( ${#dirs[@]} )); then
        while IFS= read -r -d '' link; do
            target=$(readlink -f -- "$link" 2>/dev/null) || target=""
            [[ -n "$target" && -e "$target" ]] || continue
            n=$((n + 1))
            if [[ "$target" != "$HUB_DIR"/* ]]; then
                bad+=" ${link} (points outside ${HUB_DIR})"
            elif [[ ! -L "$stage$link" || ! -f "$stage$target" || -L "$stage$target" ]]; then
                bad+=" ${target}"
            fi
        done < <(find "${dirs[@]}" -type l -print0 2>/dev/null)
    fi
    rm -rf -- "$stage"
    if [[ -n "$bad" ]]; then
        echo "not restorable:${bad:0:300}"
        return 1
    fi
    (( n > 0 )) || { echo "no installed item links into ${HUB_DIR}"; return 1; }
    echo "$n"
}

# "type/name@version" of every installed hub item of every type, sorted (""
# when unreadable). Any version change — an item or one of its dependencies —
# means crowdsec must reload.
installed_versions() {
    local json
    json=$(timeout "$CSCLI_TIMEOUT" cscli hub list -o json 2>/dev/null) || true
    [[ -n "$json" ]] || return 0
    jq -r '[paths(objects | has("name") and has("local_version")) as $p | getpath($p) as $o
            | "\($p[0])/\($o.name)@\($o.local_version // "")"] | unique | .[]' <<< "$json" 2>/dev/null || true
}

# "type/name: before -> after" for every item whose version differs between
# $1 and $2 (installed_versions output), sorted; "(none)" = newly installed.
diff_versions() {
    local line key
    local -A old=() new=()
    while IFS= read -r line; do
        [[ -z "$line" ]] || old["${line%@*}"]="${line##*@}"
    done <<< "$1"
    while IFS= read -r line; do
        [[ -z "$line" ]] || new["${line%@*}"]="${line##*@}"
    done <<< "$2"
    {
        for key in "${!new[@]}"; do
            if [[ ! -v "old[$key]" ]]; then
                printf '%s: (none) -> %s\n' "$key" "${new[$key]}"
            elif [[ "${old[$key]}" != "${new[$key]}" ]]; then
                printf '%s: %s -> %s\n' "$key" "${old[$key]}" "${new[$key]}"
            fi
        done
        for key in "${!old[@]}"; do
            [[ -v "new[$key]" ]] || printf '%s: %s -> (removed)\n' "$key" "${old[$key]}"
        done
    } | sort
}

# Installed items still not up to date, one per line, sorted:
# "<type> <name> (<status>)". cscli marks a locally modified item "tainted",
# never also "update-available", and `hub upgrade` without --force leaves it
# alone. Returns 1 when the list is unreadable — that is not "all up to date".
not_upgraded_items() {
    local json
    json=$(timeout "$CSCLI_TIMEOUT" cscli hub list -o json 2>/dev/null) || true
    [[ -n "$json" ]] || return 1
    jq -r '[paths(objects | has("name") and has("status")) as $p | getpath($p) as $o
            | select($o.status | tostring | test("update-available|tainted"))
            | "\($p[0]) \($o.name) (\($o.status))"] | unique | .[]' <<< "$json" 2>/dev/null
}

# One INFO alert listing the items the upgrade left behind ($1: sorted, one
# per line), sent only when that list differs from the one last reported. The
# script runs daily, and the same list re-sent every morning is noise that
# teaches people to ignore the channel; a new item, or one dropping out, is
# news and re-sends the whole current list. An empty list clears the state,
# so a later list is reported again. The state is written only after the
# alert went out, so a failed send is retried by the next run.
report_not_upgraded() {
    local items="$1" last=""
    if [[ -z "$items" ]]; then
        rm -f -- "$OUTDATED_STATE" 2>/dev/null || true
        return 0
    fi
    log "Hub items not upgraded: $(tr '\n' ';' <<< "$items")"
    if [[ -f "$OUTDATED_STATE" ]]; then
        last=$(cat -- "$OUTDATED_STATE" 2>/dev/null) || last=""
    fi
    if [[ "$items" == "$last" ]]; then
        log "Same not-upgraded items as already reported — no alert (delete ${OUTDATED_STATE} to re-send)"
        return 0
    fi
    local lines
    lines=$(sed 's/^/  /' <<< "$items")
    if ! "$DISCORD" "INFO" "CrowdSec Hub Items Not Upgraded" "The daily hub upgrade left these installed items as they are:\n${lines//$'\n'/\\n}\n\ntainted = changed locally. cscli upgrades such an item only with --force, so a local change is never overwritten unattended. update-available = cscli could not upgrade it; see ${LOG_FILE}.\nReview: sudo cscli <type> inspect <name> --diff\nThen keep the local change, or take the hub version: sudo cscli <type> upgrade --force <name> && sudo systemctl reload crowdsec" 2>/dev/null; then
        log "WARN: alert 'CrowdSec Hub Items Not Upgraded' could not be sent — the next run tries again"
        return 0
    fi
    if ! { mkdir -p "$(dirname "$OUTDATED_STATE")" \
            && printf '%s\n' "$items" > "$OUTDATED_STATE.tmp" \
            && mv -f "$OUTDATED_STATE.tmp" "$OUTDATED_STATE"; } 2>/dev/null; then
        rm -f -- "$OUTDATED_STATE.tmp" 2>/dev/null || true
        log "WARN: could not record the reported items in ${OUTDATED_STATE} — the next run reports them again"
    fi
    return 0
}

# Tarball of SNAPSHOT_PATHS (those that exist) into SNAPSHOT_DIR; sets
# SNAPSHOT, or SNAPSHOT_ERROR and returns 1. Symlinks are stored as symlinks.
# A tarball that verify_snapshot rejects is deleted. Keeps the newest
# SNAPSHOT_KEEP, pruning only after this run's snapshot proved usable.
take_snapshot() {
    local p rels=() snap err checked
    for p in "${SNAPSHOT_PATHS[@]}"; do
        [[ "$p" == /?* ]] || { SNAPSHOT_ERROR="refusing to snapshot a non-absolute path '$p'"; return 1; }
        [[ -e "$p" ]] && rels+=("${p#/}")
    done
    mkdir -p "$SNAPSHOT_DIR" 2>/dev/null && chmod 700 "$SNAPSHOT_DIR" 2>/dev/null \
        || { SNAPSHOT_ERROR="cannot create ${SNAPSHOT_DIR}"; return 1; }
    snap="$SNAPSHOT_DIR/hub-$(date +%Y%m%d-%H%M%S).tar.gz"
    if ! err=$( (umask 077; tar -czf "$snap.tmp" -C / "${rels[@]}") 2>&1 ); then
        rm -f "$snap.tmp"
        SNAPSHOT_ERROR="tar failed: ${err:0:300}"
        return 1
    fi
    if ! checked=$(verify_snapshot "$snap.tmp"); then
        rm -f "$snap.tmp"
        SNAPSHOT_ERROR="the snapshot could not undo an upgrade: ${checked}"
        return 1
    fi
    mv -f "$snap.tmp" "$snap" || { SNAPSHOT_ERROR="cannot move the snapshot into place"; return 1; }
    SNAPSHOT="$snap"
    log "Hub state snapshotted to $snap (index + ${checked} installed hub items verified)"

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

# The upgrade broke crowdsec ($1 = how, $2 = diff_versions output).
# Restore, restart, re-check, alert; exits 1.
rollback() {
    local why="$1" changed="$2" restored=0
    log "${why} — restoring ${SNAPSHOT}"
    if restore_snapshot "$SNAPSHOT"; then
        restored=1
        log "Hub state restored from ${SNAPSHOT}"
    else
        log "Restoring ${SNAPSHOT} FAILED"
    fi
    systemctl restart crowdsec >/dev/null 2>&1 || log "systemctl restart crowdsec returned non-zero"
    sleep "$SETTLE_SECONDS"

    local changed_msg="Items the upgrade changed: unknown (cscli hub list unreadable)\n" lines
    if [[ -n "$changed" ]]; then
        lines=$(head -n 15 <<< "$changed" | sed 's/^/  /')
        changed_msg="Items the upgrade changed (before -> after):\n${lines//$'\n'/\\n}\n"
        (( $(grep -c '' <<< "$changed") <= 15 )) || changed_msg+="  …\n"
    fi
    if systemctl is-active --quiet crowdsec; then
        if (( restored )); then
            log "crowdsec is active again on the previous hub state"
            alert "CRITICAL" "CrowdSec Rule Update Rolled Back" "The daily CrowdSec hub upgrade broke crowdsec: ${why}.\n${changed_msg}The hub state from before the upgrade was restored and crowdsec restarted; it is active again on the previous rules. The updates of this run are NOT active.\nCheck: sudo journalctl -u crowdsec -n 80 --no-pager\nThe next daily run (04:30) tries the upgrade again."
        else
            log "crowdsec is active, but the snapshot could not be restored — running the upgraded hub items"
            alert "CRITICAL" "CrowdSec Rule Rollback Failed" "The daily CrowdSec hub upgrade broke crowdsec: ${why}.\n${changed_msg}Restoring ${SNAPSHOT} failed; crowdsec came back after a restart and runs the UPGRADED items.\nCheck: sudo journalctl -u crowdsec -n 80 --no-pager; sudo cscli hub list"
        fi
        exit 1
    fi

    log "crowdsec is still NOT active after the restore and a restart"
    local restore_line="The previous hub state was restored from ${SNAPSHOT}."
    (( restored )) || restore_line="Restoring ${SNAPSHOT} FAILED — restore it by hand:\n  sudo tar -xzf ${SNAPSHOT} -C / && sudo systemctl restart crowdsec"
    alert "CRITICAL" "CrowdSec Down — Gateway Serving Errors" "crowdsec is not running. The daily hub upgrade broke it (${why}), and it did not come back after a restore and a restart.\n${changed_msg}AppSec fails closed: nginx answers 500 to every request and the Loxone apps cannot connect.\n${restore_line}\n\nRecover:\n  sudo journalctl -u crowdsec -n 80 --no-pager\n  sudo systemctl restart crowdsec\n  systemctl is-active crowdsec\nSnapshots: ${SNAPSHOT_DIR}"
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
    # verified snapshot, no upgrade: there would be nothing to roll back to.
    if ! resolve_layout || ! take_snapshot; then
        log "No usable snapshot (${SNAPSHOT_ERROR}) — upgrade skipped"
        alert "WARNING" "CrowdSec Hub Snapshot Failed" "No usable snapshot of the CrowdSec hub: ${SNAPSHOT_ERROR}.\nThe hub upgrade was skipped (without a snapshot there is no rollback), so the rules are not refreshed until this is fixed.\nCheck: sudo cscli config show --key Config.ConfigPaths.HubDir; df -h /var/lib; tail ${LOG_FILE}"
        exit 1
    fi

    if ! timeout "$CSCLI_TIMEOUT" cscli hub update >/dev/null 2>&1; then
        log "cscli hub update failed"
        alert "WARNING" "CrowdSec Hub Update Failed" "cscli hub update failed; the hub items were not upgraded. Check: sudo cscli hub update"
        exit 1
    fi

    local before after out changed=""
    before=$(installed_versions)
    # Never --force: that would overwrite tainted (locally modified) items.
    if ! out=$(timeout "$CSCLI_TIMEOUT" cscli hub upgrade 2>&1); then
        log "cscli hub upgrade failed: $(tail -n 3 <<< "$out" | tr '\n' ' ')"
        # A half-done upgrade on disk would surface at the next restart; put the
        # files back to what the running crowdsec has loaded.
        local restored_note="The hub files were put back from the pre-upgrade snapshot; crowdsec keeps running the items it has loaded."
        if restore_snapshot "$SNAPSHOT"; then
            log "Hub state restored from ${SNAPSHOT}"
        else
            log "Restoring ${SNAPSHOT} FAILED"
            restored_note="Restoring the pre-upgrade snapshot ${SNAPSHOT} FAILED — the files on disk may be half-upgraded; check sudo cscli hub list before restarting crowdsec."
        fi
        alert "WARNING" "CrowdSec Hub Upgrade Failed" "cscli hub upgrade failed. ${restored_note}\nCheck: sudo cscli hub upgrade --dry-run"
        exit 1
    fi
    [[ -z "$out" ]] || sed -n '1,60s/^/    /p' <<< "$out" >> "$LOG_FILE" || true
    after=$(installed_versions)

    local reload=0
    if [[ -z "$before" || -z "$after" ]]; then
        log "Installed hub item versions unreadable — reloading so an upgrade cannot stay unloaded"
        reload=1
    else
        changed=$(diff_versions "$before" "$after")
        [[ -z "$changed" ]] || reload=1
    fi

    if (( reload )); then
        [[ -z "$changed" ]] || log "Upgraded: $(tr '\n' ';' <<< "$changed")"
        log "Reloading crowdsec"
        if ! systemctl reload crowdsec >/dev/null 2>&1; then
            rollback "systemctl reload crowdsec failed" "$changed"
        fi
        sleep "$SETTLE_SECONDS"
        if ! systemctl is-active --quiet crowdsec; then
            rollback "crowdsec was not active ${SETTLE_SECONDS}s after the reload" "$changed"
        fi
        log "crowdsec is active after the reload"
    else
        log "No installed hub item changed; no reload"
    fi

    local items
    if items=$(not_upgraded_items); then
        report_not_upgraded "$items"
    else
        log "Hub item states unreadable (cscli hub list) — not-upgraded items not reported this run"
    fi
    log "Hub refresh finished"
}

# Only run when executed, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
