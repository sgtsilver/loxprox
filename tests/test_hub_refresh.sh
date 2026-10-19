#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# LoxProx — hub-refresh.sh (2026-10)
# ═══════════════════════════════════════════════════════════════════════════════
# The daily CrowdSec hub refresh runs end to end against a fake `cscli`,
# `systemctl` and Discord sender on PATH, over a fake hub on disk (index, item
# files, installed-item symlinks) in the CrowdSec layout; nothing touches the
# host. The snapshot and the rollback use the real tar. Needs jq.
#
# Run: bash tests/test_hub_refresh.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
TESTS_PASSED=0
TESTS_FAILED=0
pass() { echo -e "  ${GREEN}✓${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not installed"
    exit 0
fi

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$TEST_DIR")"
HUB="$PROJECT_DIR/security-monitoring/hub-refresh.sh"
WORK="$(mktemp -d /tmp/loxprox-test-hub.XXXXXXXXXX)"
trap 'rm -rf "${WORK:?}"' EXIT

FAKEBIN="$WORK/bin"
mkdir -p "$FAKEBIN"

# Records every send; FAKE_DISCORD_RC makes the send fail (webhook down).
cat > "$WORK/discord.sh" <<'EOF'
#!/bin/bash
printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$FAKE_DISCORD_LOG"
exit "${FAKE_DISCORD_RC:-0}"
EOF
# cscli over the fake hub: versions are the item files' contents, so what it
# reports follows the files (and a restore of them).
#   $FAKE_HUB/collections/crowdsecurity/appsec-virtual-patching.yaml  the collection
#   $FAKE_HUB/appsec-rules/crowdsecurity/<rule>.yaml                   its rules
#   $FAKE_CS/appsec-rules/<rule>.yaml                                  installed = symlink
#   FAKE_UPGRADE_TO          collection version the upgrade writes
#   FAKE_UPGRADE_MEMBER_TO   version the upgrade writes into rule vpatch-a ("broken" = crowdsec won't run)
#   FAKE_UPGRADE_NEW_MEMBER  the upgrade installs a NEW rule vpatch-new with this version
#   FAKE_UPDATE_RC / FAKE_UPGRADE_RC   exit codes of `hub update` / `collections upgrade`
#   FAKE_HUBLIST             the other hub items (JSON) that `hub list -o json` adds
#   FAKE_HUBLIST_BROKEN      `hub list` prints nothing and fails (unreadable)
cat > "$FAKEBIN/cscli" <<'EOF'
#!/bin/bash
echo "$*" >> "$FAKE_CSCLI_LOG"
coll="$FAKE_HUB/collections/crowdsecurity/appsec-virtual-patching.yaml"
case "$1 $2" in
    "hub update")
        echo "index-new" > "$FAKE_HUB/.index.json"
        exit "${FAKE_UPDATE_RC:-0}" ;;
    "collections upgrade")
        [[ -z "${FAKE_UPGRADE_TO:-}" ]] || echo "$FAKE_UPGRADE_TO" > "$coll"
        [[ -z "${FAKE_UPGRADE_MEMBER_TO:-}" ]] || echo "$FAKE_UPGRADE_MEMBER_TO" > "$FAKE_HUB/appsec-rules/crowdsecurity/vpatch-a.yaml"
        if [[ -n "${FAKE_UPGRADE_NEW_MEMBER:-}" ]]; then
            echo "$FAKE_UPGRADE_NEW_MEMBER" > "$FAKE_HUB/appsec-rules/crowdsecurity/vpatch-new.yaml"
            ln -sf "$FAKE_HUB/appsec-rules/crowdsecurity/vpatch-new.yaml" "$FAKE_CS/appsec-rules/vpatch-new.yaml"
        fi
        exit "${FAKE_UPGRADE_RC:-0}" ;;
    "collections list")
        printf '{"collections":[{"name":"crowdsecurity/nginx","local_version":"0.2"},{"name":"crowdsecurity/appsec-virtual-patching","status":"enabled","local_version":"%s"}]}\n' "$(cat "$coll")" ;;
    "hub list")
        [[ -z "${FAKE_HUBLIST_BROKEN:-}" ]] || exit 1
        members=$(for f in "$FAKE_CS"/appsec-rules/*.yaml; do
                      [[ -e "$f" ]] || continue
                      printf '{"name":"crowdsecurity/%s","status":"enabled","local_version":"%s"}\n' "$(basename "$f" .yaml)" "$(cat "$f")"
                  done | jq -s .)
        jq --arg cv "$(cat "$coll")" --argjson m "$members" \
            '.collections = [(.collections // [])[] | if .name == "crowdsecurity/appsec-virtual-patching" then .local_version = $cv else . end]
             | .["appsec-rules"] = $m' "$FAKE_HUBLIST" ;;
    *) exit 0 ;;
esac
EOF
# systemctl: crowdsec refuses to run while an installed rule is "broken", or
# when FAKE_ACTIVE_RC says it is down; FAKE_RELOAD_RC fails the reload.
cat > "$FAKEBIN/systemctl" <<'EOF'
#!/bin/bash
echo "$*" >> "$FAKE_SYSTEMCTL_LOG"
case "$1" in
    reload) exit "${FAKE_RELOAD_RC:-0}" ;;
    is-active)
        grep -qsx broken "$FAKE_CS"/appsec-rules/*.yaml && exit 3
        exit "${FAKE_ACTIVE_RC:-0}" ;;
    *) exit 0 ;;
esac
EOF
chmod +x "$WORK/discord.sh" "$FAKEBIN"/*

HUBLIST_CLEAN='{"parsers":[{"name":"crowdsecurity/nginx-logs","status":"enabled","local_version":"1.6"}],"collections":[{"name":"crowdsecurity/appsec-virtual-patching","status":"enabled"}]}'
HUBLIST_OUTDATED='{"parsers":[{"name":"crowdsecurity/nginx-logs","status":"enabled,update-available","local_version":"1.6"},{"name":"crowdsecurity/syslog-logs","status":"enabled","local_version":"0.8"}],"scenarios":[{"name":"crowdsecurity/http-probing","status":"enabled,update-available","local_version":"0.4"}],"collections":[{"name":"crowdsecurity/appsec-virtual-patching","status":"enabled,update-available"}]}'
# HUBLIST_OUTDATED plus syslog-logs outdated as well.
HUBLIST_MORE='{"parsers":[{"name":"crowdsecurity/nginx-logs","status":"enabled,update-available","local_version":"1.6"},{"name":"crowdsecurity/syslog-logs","status":"enabled,update-available","local_version":"0.8"}],"scenarios":[{"name":"crowdsecurity/http-probing","status":"enabled,update-available","local_version":"0.4"}],"collections":[{"name":"crowdsecurity/appsec-virtual-patching","status":"enabled,update-available"}]}'

# A hub as CrowdSec lays it out: index + item files under the hub dir, the
# installed items as symlinks under the config dir, plus deploy.sh's local
# files. postoverflows/ is left out on purpose (a type with nothing installed).
seed_hub() {
    local c="$1"
    rm -rf "${c:?}/hub" "${c:?}/etc"
    mkdir -p "$c/hub/collections/crowdsecurity" "$c/hub/appsec-rules/crowdsecurity" \
             "$c/etc/collections" "$c/etc/appsec-rules" "$c/etc/parsers/s02-enrich" "$c/etc/scenarios" \
             "$c/etc/appsec-configs" "$c/etc/contexts"
    echo "index-old" > "$c/hub/.index.json"
    echo "0.4" > "$c/hub/collections/crowdsecurity/appsec-virtual-patching.yaml"
    echo "0.1" > "$c/hub/appsec-rules/crowdsecurity/vpatch-a.yaml"
    ln -s "$c/hub/collections/crowdsecurity/appsec-virtual-patching.yaml" "$c/etc/collections/appsec-virtual-patching.yaml"
    ln -s "$c/hub/appsec-rules/crowdsecurity/vpatch-a.yaml" "$c/etc/appsec-rules/vpatch-a.yaml"
    echo "deploy-managed whitelist" > "$c/etc/parsers/s02-enrich/whitelist-loxone.yaml"
    echo "local scenario" > "$c/etc/scenarios/loxprox-scanner-trap.yaml"
}

# run_hub <case> [VAR=value ...]; prints nothing, sets HUB_RC.
HUB_RC=0
run_hub() {
    local c="$WORK/$1"; shift
    mkdir -p "$c"
    : > "$c/cscli.log"; : > "$c/systemctl.log"; : > "$c/discord.log"
    [[ -d "$c/hub" ]] || seed_hub "$c"
    [[ -f "$c/hublist.json" ]] || echo "$HUBLIST_CLEAN" > "$c/hublist.json"
    HUB_RC=0
    ( export PATH="$FAKEBIN:$PATH" LOXPROX_CONFIG="$WORK/none.env" DISCORD_ALERT_PATH="$WORK/discord.sh" \
             LOXPROX_HUB_LOG="$c/hub.log" LOXPROX_HUB_LOCK="$c/lock" HUB_REFRESH_SETTLE=0 \
             LOXPROX_CROWDSEC_HUB_DIR="$c/hub" LOXPROX_CROWDSEC_DIR="$c/etc" LOXPROX_HUB_SNAPSHOT_DIR="$c/snapshots" \
             LOXPROX_HUB_OUTDATED_STATE="$c/outdated-state" \
             FAKE_HUB="$c/hub" FAKE_CS="$c/etc" FAKE_HUBLIST="$c/hublist.json" \
             FAKE_DISCORD_LOG="$c/discord.log" FAKE_CSCLI_LOG="$c/cscli.log" FAKE_SYSTEMCTL_LOG="$c/systemctl.log"
      for kv in "$@"; do export "${kv?}"; done
      bash "$HUB" ) > "$c/out.log" 2>&1 || HUB_RC=$?
}

# The hub as it was seeded: versions, index, links, local files, nothing added.
hub_is_pristine() {
    local c="$1"
    [[ "$(cat "$c/hub/collections/crowdsecurity/appsec-virtual-patching.yaml")" == "0.4" ]] \
        && [[ "$(cat "$c/hub/appsec-rules/crowdsecurity/vpatch-a.yaml")" == "0.1" ]] \
        && [[ "$(cat "$c/hub/.index.json")" == "index-old" ]] \
        && [[ -L "$c/etc/appsec-rules/vpatch-a.yaml" && -L "$c/etc/collections/appsec-virtual-patching.yaml" ]] \
        && [[ ! -e "$c/etc/appsec-rules/vpatch-new.yaml" && ! -L "$c/etc/appsec-rules/vpatch-new.yaml" ]] \
        && [[ ! -e "$c/hub/appsec-rules/crowdsecurity/vpatch-new.yaml" ]] \
        && [[ "$(cat "$c/etc/parsers/s02-enrich/whitelist-loxone.yaml")" == "deploy-managed whitelist" ]] \
        && [[ "$(cat "$c/etc/scenarios/loxprox-scanner-trap.yaml")" == "local scenario" ]]
}

echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  LoxProx — hub-refresh.sh tests"
echo "═══════════════════════════════════════════════════════════════════════════════"

echo ""; echo "━━━ collection upgraded → reload + verify ━━━"
c="$WORK/upgraded"
run_hub upgraded FAKE_UPGRADE_TO=0.5
[[ $HUB_RC -eq 0 ]] && pass "exit 0" || fail "exit $HUB_RC: $(tail -3 "$c/out.log")"
grep -qx 'hub update' "$c/cscli.log" && pass "cscli hub update runs" || fail "no hub update: $(cat "$c/cscli.log")"
grep -qx 'collections upgrade crowdsecurity/appsec-virtual-patching' "$c/cscli.log" && pass "the virtual-patching collection is upgraded" || fail "no upgrade: $(cat "$c/cscli.log")"
n=$(grep -c 'upgrade' "$c/cscli.log")
[[ "$n" == "1" ]] && ! grep -qE '^(hub upgrade|parsers upgrade|scenarios upgrade|appsec-rules upgrade)' "$c/cscli.log" \
    && pass "nothing else is upgraded (exactly one upgrade call)" || fail "extra upgrades: $(cat "$c/cscli.log")"
grep -q '^reload crowdsec' "$c/systemctl.log" && grep -q '^is-active --quiet crowdsec' "$c/systemctl.log" \
    && ! grep -q '^restart' "$c/systemctl.log" \
    && pass "version changed 0.4 → 0.5: crowdsec reloaded, then verified active (no restart)" || fail "systemctl: $(cat "$c/systemctl.log")"
[[ ! -s "$c/discord.log" ]] && pass "no alert on a clean upgrade with nothing else outdated" || fail "unexpected alert: $(cat "$c/discord.log")"

echo ""; echo "━━━ snapshot ━━━"
snaps=("$c"/snapshots/hub-*.tar.gz)
if [[ ${#snaps[@]} -eq 1 && -f "${snaps[0]}" && "$(basename "${snaps[0]}")" =~ ^hub-[0-9]{8}-[0-9]{6}\.tar\.gz$ ]]; then
    pass "one dated tarball under the snapshot dir"
else
    fail "snapshots: $(ls -la "$c/snapshots" 2>&1)"
fi
x="$WORK/extract"; mkdir -p "$x"; tar -xzf "${snaps[0]}" -C "$x" 2>/dev/null
r="$x${c}"
if [[ "$(cat "$r/hub/.index.json" 2>/dev/null)" == "index-old" ]] \
        && [[ "$(cat "$r/hub/appsec-rules/crowdsecurity/vpatch-a.yaml" 2>/dev/null)" == "0.1" ]]; then
    pass "it holds the hub index and items as they were BEFORE hub update and the upgrade"
else
    fail "snapshot content: index=$(cat "$r/hub/.index.json" 2>&1)"
fi
if [[ -L "$r/etc/appsec-rules/vpatch-a.yaml" && -f "$r/etc/parsers/s02-enrich/whitelist-loxone.yaml" && -f "$r/etc/scenarios/loxprox-scanner-trap.yaml" ]]; then
    pass "…and the installed-item symlinks (kept as symlinks) plus local files under the config dir"
else
    fail "config dir in snapshot: $(find "$r/etc" 2>&1 | head)"
fi
[[ "$(stat -c %a "$c/snapshots" 2>/dev/null)" == "700" ]] && pass "snapshot dir is 0700" || fail "snapshot dir mode: $(stat -c %a "$c/snapshots" 2>&1)"

c="$WORK/retention"; mkdir -p "$c/snapshots"
for i in 1 2 3 4 5 6 7 8; do echo old > "$c/snapshots/hub-2026010${i}-030000.tar.gz"; done
run_hub retention
kept=("$c"/snapshots/hub-*.tar.gz) left="" fresh=0
for f in "${kept[@]}"; do
    [[ -e "$f" ]] || continue
    left+="$(basename "$f") "
    [[ "$(basename "$f")" == hub-2026010* ]] || fresh=$((fresh + 1))
done
if [[ $(wc -w <<<"$left") -eq 7 && "$fresh" == "1" && "$left" != *20260101* && "$left" != *20260102* \
        && "$left" == *20260103* && "$left" == *20260108* ]]; then
    pass "retention: a week of daily runs — the newest 7 kept (this run's + 6 older), the 2 oldest removed"
else
    fail "retention left: $left"
fi

c="$WORK/snapfail"; mkdir -p "$c"; echo "not a directory" > "$c/afile"
run_hub snapfail LOXPROX_HUB_SNAPSHOT_DIR="$c/afile/snapshots"
if grep -q '^WARNING|CrowdSec Hub Snapshot Failed' "$c/discord.log" && [[ $HUB_RC -eq 1 ]] \
        && ! grep -q 'upgrade' "$c/cscli.log" && [[ ! -s "$c/systemctl.log" ]]; then
    pass "no snapshot possible → WARNING, exit 1, nothing upgraded (no rollback without a snapshot)"
else
    fail "rc=$HUB_RC discord: $(cat "$c/discord.log") cscli: $(cat "$c/cscli.log")"
fi

echo ""; echo "━━━ reload decision covers every installed item (F5) ━━━"
run_hub member FAKE_UPGRADE_MEMBER_TO=0.2
c="$WORK/member"
if [[ $HUB_RC -eq 0 ]] && grep -q '^reload crowdsec' "$c/systemctl.log"; then
    pass "a rule updated under an unchanged collection version (0.4) → reloaded"
else
    fail "rc=$HUB_RC systemctl: $(cat "$c/systemctl.log") log: $(cat "$c/hub.log")"
fi
grep -q 'crowdsecurity/vpatch-a@0.2' "$c/hub.log" && pass "the changed item is logged with its new version" || fail "log: $(cat "$c/hub.log")"
run_hub newmember FAKE_UPGRADE_NEW_MEMBER=0.1
c="$WORK/newmember"
grep -q '^reload crowdsec' "$c/systemctl.log" && pass "a rule newly installed by the upgrade → reloaded" || fail "systemctl: $(cat "$c/systemctl.log")"

echo ""; echo "━━━ collection unchanged → no reload ━━━"
run_hub unchanged
c="$WORK/unchanged"
if [[ $HUB_RC -eq 0 && ! -s "$c/systemctl.log" ]]; then pass "no reload when no installed item changed"; else fail "rc=$HUB_RC systemctl: $(cat "$c/systemctl.log")"; fi
grep -q 'unchanged' "$c/hub.log" && pass "logged as unchanged" || fail "log: $(cat "$c/hub.log")"

echo ""; echo "━━━ crowdsec inactive after the reload → rollback (F2) ━━━"
run_hub rollback FAKE_UPGRADE_TO=0.5 FAKE_UPGRADE_MEMBER_TO=broken FAKE_UPGRADE_NEW_MEMBER=0.1
c="$WORK/rollback"
line=$(grep '^CRITICAL|CrowdSec Rule Update Rolled Back' "$c/discord.log" || true)
if [[ -n "$line" && $HUB_RC -eq 1 ]] && grep -q '0.4 -> 0.5' <<<"$line" && grep -q 'active again with crowdsecurity/appsec-virtual-patching 0.4' <<<"$line"; then
    pass "CRITICAL 'CrowdSec Rule Update Rolled Back' with before → after (0.4 -> 0.5) and the restored version, exit 1"
else
    fail "rc=$HUB_RC discord: $(cat "$c/discord.log")"
fi
grep -q 'vpatch-a@broken' <<<"$line" && grep -q 'vpatch-new@0.1' <<<"$line" && pass "…naming the items the upgrade changed" || fail "changed items missing: $line"
hub_is_pristine "$c" && pass "files restored: versions, index, symlinks and local files back; the added rule removed" \
    || fail "hub after rollback: $(find "$c/hub" "$c/etc" -exec ls -ld {} + 2>&1 | head -20)"
if [[ "$(grep -oE '^(reload|restart|is-active)' "$c/systemctl.log" | tr '\n' ' ')" == "reload is-active restart is-active " ]]; then
    pass "order: reload, check, (restore,) restart, re-check"
else
    fail "systemctl order: $(cat "$c/systemctl.log")"
fi
! grep -q 'CrowdSec Down' "$c/discord.log" && pass "no 'down' alert once crowdsec is back" || fail "down alert after a good rollback"
[[ -z "$(find "$c" -name '*.loxprox-pre-restore' -o -name '.restore.*')" ]] && pass "no staging or moved-aside copies left behind" || fail "leftovers: $(find "$c" -name '*.loxprox-pre-restore' -o -name '.restore.*')"

run_hub reloadfail FAKE_UPGRADE_TO=0.5 FAKE_RELOAD_RC=1
c="$WORK/reloadfail"
line=$(grep '^CRITICAL|CrowdSec Rule Update Rolled Back' "$c/discord.log" || true)
if [[ -n "$line" && $HUB_RC -eq 1 ]] && grep -q 'systemctl reload crowdsec failed' <<<"$line" && grep -q '^restart crowdsec' "$c/systemctl.log" && hub_is_pristine "$c"; then
    pass "reload itself fails → restored, restarted, CRITICAL 'Rolled Back' naming the failed reload"
else
    fail "rc=$HUB_RC discord: $(cat "$c/discord.log") systemctl: $(cat "$c/systemctl.log")"
fi

echo ""; echo "━━━ still down after the restore ━━━"
run_hub down FAKE_UPGRADE_TO=0.5 FAKE_ACTIVE_RC=3
c="$WORK/down"
line=$(grep '^CRITICAL|CrowdSec Down — Gateway Serving Errors' "$c/discord.log" || true)
if [[ -n "$line" && $HUB_RC -eq 1 ]]; then
    pass "inactive after reload AND after restore + restart → CRITICAL 'CrowdSec Down — Gateway Serving Errors', exit 1"
else
    fail "rc=$HUB_RC discord: $(cat "$c/discord.log")"
fi
if grep -q 'sudo journalctl -u crowdsec' <<<"$line" && grep -q 'sudo systemctl restart crowdsec' <<<"$line" \
        && grep -q '500' <<<"$line" && grep -q "$c/snapshots" <<<"$line"; then
    pass "…with the recovery commands, the 500 consequence and the snapshot location"
else
    fail "message: $line"
fi
! grep -q 'Rolled Back' "$c/discord.log" && pass "…and no 'Rolled Back' alert" || fail "rolled-back alert while still down"
hub_is_pristine "$c" && pass "the restore still happened" || fail "hub not restored"
[[ $(grep -c '^restart crowdsec' "$c/systemctl.log") -eq 1 ]] && pass "exactly one restart attempt" || fail "restarts: $(grep -c restart "$c/systemctl.log")"

echo ""; echo "━━━ other outdated items are reported, never upgraded ━━━"
c="$WORK/outdated"; mkdir -p "$c"; echo "$HUBLIST_OUTDATED" > "$c/hublist.json"
run_hub outdated
line=$(grep '^INFO|CrowdSec Hub Items Outdated' "$c/discord.log" || true)
if grep -q 'crowdsecurity/nginx-logs' <<<"$line" && grep -q 'crowdsecurity/http-probing' <<<"$line"; then
    pass "one INFO alert lists the outdated parser and scenario"
else
    fail "alert: $line"
fi
if grep -q 'syslog-logs' <<<"$line" || grep -q 'appsec-virtual-patching' <<<"$line"; then
    fail "alert lists an up-to-date item or the auto-upgraded collection: $line"
else
    pass "up-to-date items and the auto-upgraded collection are not listed"
fi
[[ "$(grep -c '' "$c/discord.log")" == "1" ]] && pass "exactly one alert" || fail "alerts: $(cat "$c/discord.log")"
! grep -qE '^(hub upgrade|parsers upgrade|scenarios upgrade)' "$c/cscli.log" && pass "the outdated items were not upgraded" || fail "upgraded something: $(cat "$c/cscli.log")"

echo ""; echo "━━━ the outdated-items alert is not repeated every day ━━━"
# Same case as above, run again day after day: the state file carries over.
st="$c/outdated-state"
[[ "$(cat "$st" 2>/dev/null)" == $'crowdsecurity/http-probing\ncrowdsecurity/nginx-logs' ]] \
    && pass "the reported list is recorded (sorted names, auto-upgraded collection excluded)" || fail "state after the first report: $(cat "$st" 2>&1)"
run_hub outdated
if [[ $HUB_RC -eq 0 && ! -s "$c/discord.log" ]] && grep -q 'Same outdated items as already reported' "$c/hub.log" \
        && [[ $(grep -c 'Other outdated hub items: .*nginx-logs' "$c/hub.log") -eq 2 ]]; then   # hub.log spans both runs
    pass "next day, same outdated items → no alert; the log still lists them"
else
    fail "rc=$HUB_RC repeat run: discord=$(cat "$c/discord.log") log=$(tail -3 "$c/hub.log")"
fi
echo "$HUBLIST_MORE" > "$c/hublist.json"
run_hub outdated
line=$(grep '^INFO|CrowdSec Hub Items Outdated' "$c/discord.log" || true)
if grep -q 'syslog-logs' <<<"$line" && grep -q 'nginx-logs' <<<"$line" && grep -q 'http-probing' <<<"$line"; then
    pass "one more item outdated → alert again, with the whole current list"
else
    fail "after a new outdated item: $(cat "$c/discord.log")"
fi
grep -qx 'crowdsecurity/syslog-logs' "$st" && pass "…and the recorded list follows" || fail "state: $(cat "$st" 2>&1)"
echo "$HUBLIST_OUTDATED" > "$c/hublist.json"
run_hub outdated
line=$(grep '^INFO|CrowdSec Hub Items Outdated' "$c/discord.log" || true)
[[ -n "$line" ]] && ! grep -q 'syslog-logs' <<<"$line" \
    && pass "an item dropping out (upgraded by hand) → one alert with the rest" || fail "after an item dropped out: $(cat "$c/discord.log")"
echo "$HUBLIST_CLEAN" > "$c/hublist.json"
run_hub outdated
[[ $HUB_RC -eq 0 && ! -s "$c/discord.log" && ! -e "$st" ]] \
    && pass "nothing outdated → no alert, the recorded list is cleared" || fail "rc=$HUB_RC discord=$(cat "$c/discord.log") state=$(cat "$st" 2>&1)"
echo "$HUBLIST_OUTDATED" > "$c/hublist.json"
run_hub outdated
grep -q '^INFO|CrowdSec Hub Items Outdated' "$c/discord.log" \
    && pass "the same items outdated again later → reported again" || fail "not reported after the list had been cleared"

c="$WORK/sendfail"; mkdir -p "$c"; echo "$HUBLIST_OUTDATED" > "$c/hublist.json"
run_hub sendfail FAKE_DISCORD_RC=1
if [[ $HUB_RC -eq 0 && ! -e "$c/outdated-state" ]] && grep -q '^INFO|CrowdSec Hub Items Outdated' "$c/discord.log" \
        && grep -q 'could not be sent' "$c/hub.log"; then
    pass "the send fails → nothing recorded, exit 0"
else
    fail "rc=$HUB_RC state=$(cat "$c/outdated-state" 2>&1) log=$(tail -3 "$c/hub.log")"
fi
run_hub sendfail
grep -q '^INFO|CrowdSec Hub Items Outdated' "$c/discord.log" && [[ -s "$c/outdated-state" ]] \
    && pass "…so the next run sends it and records it" || fail "not retried: discord=$(cat "$c/discord.log")"
run_hub sendfail FAKE_HUBLIST_BROKEN=1
if [[ $HUB_RC -eq 0 && ! -s "$c/discord.log" && -s "$c/outdated-state" ]] && grep -q 'Outdated hub items unreadable' "$c/hub.log"; then
    pass "hub list unreadable → no alert, the recorded list kept (unreadable is not 'nothing outdated')"
else
    fail "rc=$HUB_RC discord=$(cat "$c/discord.log") state=$(cat "$c/outdated-state" 2>&1) log=$(tail -3 "$c/hub.log")"
fi

echo ""; echo "━━━ failures ━━━"
run_hub updfail FAKE_UPDATE_RC=1
c="$WORK/updfail"
if grep -q '^WARNING|CrowdSec Hub Update Failed' "$c/discord.log" && [[ $HUB_RC -eq 1 ]] && ! grep -q 'collections upgrade' "$c/cscli.log"; then
    pass "hub update failure → WARNING, exit 1, no upgrade attempted"
else
    fail "rc=$HUB_RC discord: $(cat "$c/discord.log")"
fi
run_hub upgfail FAKE_UPGRADE_RC=1 FAKE_UPGRADE_MEMBER_TO=0.2
c="$WORK/upgfail"
if grep -q '^WARNING|AppSec Rules Upgrade Failed' "$c/discord.log" && [[ $HUB_RC -eq 1 && ! -s "$c/systemctl.log" ]]; then
    pass "collection upgrade failure → WARNING, exit 1, no reload"
else
    fail "rc=$HUB_RC discord: $(cat "$c/discord.log") systemctl: $(cat "$c/systemctl.log")"
fi
hub_is_pristine "$c" && pass "…and the half-done upgrade on disk is put back from the snapshot" || fail "partial upgrade left on disk: vpatch-a=$(cat "$c/hub/appsec-rules/crowdsecurity/vpatch-a.yaml")"

echo ""; echo "━━━ wiring ━━━"
grep -q 'set -euo pipefail' "$HUB" && pass "uses set -euo pipefail" || fail "no strict mode"
bash -n "$HUB" && pass "syntax ok" || fail "syntax error"

echo ""
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$TESTS_PASSED passed${NC}, ${RED}$TESTS_FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"
[[ $TESTS_FAILED -eq 0 ]] && exit 0 || exit 1
