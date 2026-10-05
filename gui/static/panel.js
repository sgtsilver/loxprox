/* LoxProx Panel — calm ops console.
   Talks only to the panel's own /api endpoints (CSP connect-src 'self').
   No third-party code; DOM is built with safe APIs (never HTML strings).
   Status first: the overview answers "is everything OK, and if not, what
   should I do?" — then details, then 24h trends. */

import { I18N } from "/static/i18n.js";
import { createChart } from "/static/charts.js";

const $ = (id) => document.getElementById(id);

// ─── storage (every access guarded: private mode / blocked storage) ─────

function storageGet(kind, key) {
    try { return window[kind].getItem(key); } catch (e) { return null; }
}
function storageSet(kind, key, value) {
    try {
        if (value === null) window[kind].removeItem(key);
        else window[kind].setItem(key, value);
    } catch (e) { /* storage unavailable — keep the in-memory value */ }
}

// ─── i18n & formatting ──────────────────────────────────────────────────

let lang = storageGet("localStorage", "lp-lang") === "en" ? "en" : "de";

function t(key, vars) {
    const dict = I18N[lang] || I18N.de;
    let s = key in dict ? dict[key] : (key in I18N.de ? I18N.de[key] : key);
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
    return s;
}
function tn(key, n, vars) {
    return t(key + (n === 1 ? "_one" : "_other"), Object.assign({ n }, vars));
}

const locale = () => (lang === "de" ? "de-DE" : "en-GB");
const nfCache = new Map();
function num(value, decimals = 0) {
    if (value === null || value === undefined || !Number.isFinite(value)) return t("no_value");
    const key = locale() + decimals;
    if (!nfCache.has(key)) {
        nfCache.set(key, new Intl.NumberFormat(locale(), {
            minimumFractionDigits: decimals, maximumFractionDigits: decimals }));
    }
    return nfCache.get(key).format(value);
}
function pct(value) {
    if (value === null || value === undefined || !Number.isFinite(value)) return t("no_value");
    return new Intl.NumberFormat(locale(), { style: "percent", maximumFractionDigits: 0 }).format(value / 100);
}
function clock(epochSec, seconds) {
    const opts = { hour: "2-digit", minute: "2-digit", hourCycle: "h23" };
    if (seconds) opts.second = "2-digit";
    return new Date(epochSec * 1000).toLocaleTimeString(locale(), opts);
}
function duration(sec) {
    const s = Math.max(0, Math.floor(sec));
    const m = Math.floor(s / 60);
    return m + ":" + String(s % 60).padStart(2, "0");
}

// ─── small DOM helpers ──────────────────────────────────────────────────

function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
}
function icon(name, extra) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon" + (extra ? " " + extra : ""));
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "#i-" + name);
    svg.append(use);
    return svg;
}
const LEVEL_ICON = { ok: "ok", warn: "warn", bad: "bad", info: "info", neutral: "neutral" };

function setResult(node, level, message) {
    if (!message) { node.replaceChildren(); delete node.dataset.state; return; }
    node.dataset.state = level;
    node.replaceChildren(icon(LEVEL_ICON[level] || "info"), el("span", "", message));
}

/* A cancelled password prompt is not a failure: say so neutrally. */
function reportError(node, key, err, vars) {
    if (err instanceof ApiError && err.kind === "cancelled") setResult(node, "info", t("auth_cancelled"));
    else setResult(node, "bad", t(key, Object.assign({ err: errText(err) }, vars)));
}

function announce(message) {
    const live = $("srLive");
    live.textContent = "";
    window.setTimeout(() => { live.textContent = message; }, 60);
}

function setBusy(btn, busy) {
    if (busy) { btn.setAttribute("aria-disabled", "true"); btn.dataset.busy = "1"; }
    else { btn.removeAttribute("aria-disabled"); delete btn.dataset.busy; }
}
const isBusy = (btn) => btn.dataset.busy === "1";

// ─── API ────────────────────────────────────────────────────────────────

class ApiError extends Error {
    constructor(kind, status, detail) {
        super(kind);
        this.kind = kind;          // network | timeout | bad_json | http | cancelled
        this.status = status || 0;
        this.detail = detail || "";
    }
}

// Server messages are English; translate the ones the UI can expect.
const SERVER_ERRORS = {
    "a job is already running": "err_job_running",
    "deploy.sh path unknown — re-run deploy once via SSH": "err_deploy_path",
    "service not allowed": "err_service",
    "qrencode failed": "err_qrencode",
    "host not allowed": "err_host_forbidden",
    "invalid IP": "unban_invalid",
    "invalid host": "inv_invalid",
};
function serverMsg(msg) {
    if (!msg) return "";
    return SERVER_ERRORS[msg] ? t(SERVER_ERRORS[msg]) : String(msg).slice(0, 300);
}
function errText(err) {
    if (!(err instanceof ApiError)) return t("err_bad_json");
    if (err.kind === "network") return t("err_network");
    if (err.kind === "timeout") return t("err_timeout");
    if (err.kind === "cancelled") return t("auth_cancelled");
    if (err.kind === "bad_json") return t("err_bad_json");
    if (err.detail) return serverMsg(err.detail);
    return t("err_http", { code: err.status });
}

// Password for mutations (GUI_PASSWORD). Kept for this tab only, as before.
let authRequired = false;
let password = storageGet("sessionStorage", "lp-pw") || "";
function setPassword(pw) {
    password = pw || "";
    storageSet("sessionStorage", "lp-pw", password || null);
}

async function request(method, url, body, timeout) {
    const ctrl = new AbortController();
    const timer = window.setTimeout(() => ctrl.abort(), timeout || 20000);
    const headers = { Accept: "application/json" };
    if (method === "POST") {
        headers["Content-Type"] = "application/json";
        headers["X-LoxProx-Gui"] = "1";            // CSRF guard, required by the server
        if (password) headers["X-LoxProx-Auth"] = password;
    }
    let res;
    try {
        res = await fetch(url, {
            method, headers, cache: "no-store", credentials: "same-origin", signal: ctrl.signal,
            body: body === undefined ? undefined : JSON.stringify(body),
        });
    } catch (e) {
        throw new ApiError(e && e.name === "AbortError" ? "timeout" : "network");
    } finally {
        window.clearTimeout(timer);
    }
    let data;
    try { data = await res.json(); } catch (e) { throw new ApiError("bad_json", res.status); }
    return { status: res.status, data: data || {} };
}

async function getJSON(url, timeout) {
    const { status, data } = await request("GET", url, undefined, timeout);
    if (status !== 200 || data.ok !== true) throw new ApiError("http", status, data.error);
    return data;
}

/* POST with the CSRF header; on 401 ask for the password and retry.
   Resolves to { status, data }; throws ApiError (incl. "cancelled"). */
async function post(url, body, timeout) {
    let wrong = false;
    for (;;) {
        if (authRequired && !password) {
            if (!(await askPassword(wrong))) throw new ApiError("cancelled");
        }
        const sent = Boolean(password);
        const res = await request("POST", url, body || {}, timeout);
        if (res.status !== 401) return res;
        authRequired = true;
        wrong = sent;
        setPassword("");
        if (!(await askPassword(wrong))) throw new ApiError("cancelled");
    }
}

// ─── dialogs ────────────────────────────────────────────────────────────

function openDialog(dlg, initialFocus) {
    const opener = document.activeElement;
    dlg.showModal();
    if (initialFocus) initialFocus.focus();
    return () => {
        if (dlg.open) dlg.close();
        if (opener && opener.isConnected && typeof opener.focus === "function") opener.focus();
    };
}

function confirmDialog({ title, text, extra, okLabel, danger }) {
    return new Promise((resolve) => {
        const dlg = $("confirmDlg");
        $("confirmTitle").textContent = title;
        $("confirmText").textContent = text;
        $("confirmExtra").textContent = extra || "";
        $("confirmExtra").hidden = !extra;
        const ok = $("confirmOk");
        ok.textContent = okLabel;
        ok.className = "btn " + (danger ? "btn-danger" : "btn-primary");
        const close = openDialog(dlg, $("confirmCancel"));
        const finish = (value) => {
            ok.removeEventListener("click", onOk);
            $("confirmCancel").removeEventListener("click", onCancel);
            dlg.removeEventListener("cancel", onEsc);
            close();
            resolve(value);
        };
        const onOk = () => finish(true);
        const onCancel = () => finish(false);
        const onEsc = (e) => { e.preventDefault(); finish(false); };
        ok.addEventListener("click", onOk);
        $("confirmCancel").addEventListener("click", onCancel);
        dlg.addEventListener("cancel", onEsc);
    });
}

function askPassword(wrong) {
    return new Promise((resolve) => {
        const dlg = $("authDlg");
        const input = $("authPw");
        const err = $("authError");
        input.value = "";
        const showErr = (msg) => {
            err.hidden = !msg;
            err.replaceChildren(...(msg ? [icon("bad"), el("span", "", msg)] : []));
            if (msg) input.setAttribute("aria-invalid", "true");
            else input.removeAttribute("aria-invalid");
        };
        showErr(wrong ? t("auth_wrong") : "");
        const close = openDialog(dlg, input);
        const finish = (value) => {
            $("authForm").removeEventListener("submit", onSubmit);
            $("authCancel").removeEventListener("click", onCancel);
            dlg.removeEventListener("cancel", onEsc);
            close();
            resolve(value);
        };
        const onSubmit = (e) => {
            e.preventDefault();
            if (!input.value) { showErr(t("auth_empty")); input.focus(); return; }
            setPassword(input.value);
            finish(true);
        };
        const onCancel = () => finish(false);
        const onEsc = (e) => { e.preventDefault(); finish(false); };
        $("authForm").addEventListener("submit", onSubmit);
        $("authCancel").addEventListener("click", onCancel);
        dlg.addEventListener("cancel", onEsc);
    });
}

// ─── theme ──────────────────────────────────────────────────────────────

const THEMES = ["auto", "light", "dark"];
const THEME_BG = { light: "#f5f5f7", dark: "#111113" };

function currentTheme() {
    return document.documentElement.getAttribute("data-theme") || "auto";
}
function setTheme(mode, speak) {
    if (mode === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", mode);
    storageSet("localStorage", "lp-theme", mode === "auto" ? null : mode);
    document.querySelectorAll('meta[name="theme-color"]').forEach((m) => {
        const media = m.getAttribute("media") || "";
        const scheme = media.includes("dark") ? "dark" : "light";
        m.setAttribute("content", THEME_BG[mode === "auto" ? scheme : mode]);
    });
    $("themeBtnLabel").textContent = t("theme_btn", { mode: t("theme_" + mode) });
    if (speak) announce(t("theme_changed", { mode: t("theme_" + mode) }));
}
$("themeBtn").addEventListener("click", () => {
    const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
    setTheme(next, true);
});

// ─── navigation (hash routes, focus moves to the view heading) ──────────

const VIEWS = ["overview", "security", "config", "logs"];
const VIEW_TITLE = { overview: "nav_overview", security: "nav_security", config: "nav_config", logs: "nav_logs" };
let view = null;
let pendingFocus = null;

function viewFromHash() {
    const h = location.hash.replace(/^#/, "");
    return VIEWS.includes(h) ? h : null;
}

function showView(name, focus) {
    view = name;
    document.querySelectorAll("section.view").forEach((s) => { s.hidden = s.dataset.view !== name; });
    document.querySelectorAll(".nav-link").forEach((a) => {
        if (a.dataset.view === name) a.setAttribute("aria-current", "page");
        else a.removeAttribute("aria-current");
    });
    document.title = t(VIEW_TITLE[name]) + " · LoxProx Panel";
    if (name === "logs") { if (logText === null && !logLoading) loadLog(true); }
    if (focus) {
        window.scrollTo(0, 0);
        const target = pendingFocus && $(pendingFocus);
        pendingFocus = null;
        (target || $("h-" + name)).focus();
    }
}

window.addEventListener("hashchange", () => {
    const next = viewFromHash();
    if (next) showView(next, true);
});

function goTo(name, focusId) {
    pendingFocus = focusId || null;
    if (view === name) showView(name, true);
    else location.hash = "#" + name;
}

document.querySelector(".skip-link").addEventListener("click", (e) => {
    e.preventDefault();
    $("h-" + (view || "overview")).focus();
});

// ─── service metadata ───────────────────────────────────────────────────

const SERVICES = {
    "nginx": { name: "svc_nginx", impact: "imp_nginx", desc: "desc_nginx", restart: true },
    "crowdsec": { name: "svc_crowdsec", impact: "imp_crowdsec", desc: "desc_crowdsec", restart: true },
    "crowdsec-firewall-bouncer": { name: "svc_bouncer", impact: "imp_bouncer", desc: "desc_bouncer", restart: true },
    "frpc": { name: "svc_frpc", impact: "imp_frpc", desc: "desc_frpc", restart: true },
    "loxprox-monitor.timer": { name: "svc_monitor", impact: "imp_monitor" },
    "network-watchdog.timer": { name: "svc_watchdog", impact: "imp_watchdog" },
    "tunnel-watchdog.timer": { name: "svc_tunnelwd", impact: "imp_tunnelwd" },
    "loxprox-gui": { name: "svc_gui" },
};
const RESTARTABLE = ["nginx", "crowdsec", "crowdsec-firewall-bouncer", "frpc"];
const TRANSIENT = ["activating", "reloading", "deactivating"];

const svcName = (unit) => (SERVICES[unit] ? t(SERVICES[unit].name) : unit);
function stateWord(state) {
    const key = "st_" + state;
    return key in I18N.de ? t(key) : String(state || t("st_unknown"));
}
function svcLevel(unit, state) {
    if (state === "active") return "ok";
    if (TRANSIENT.includes(state)) return "warn";
    return SERVICES[unit] && SERVICES[unit].restart ? "bad" : "warn";
}

// ─── status: evaluation ─────────────────────────────────────────────────

let statusData = null;
let statusAt = 0;
let statusErr = null;
let statusInFlight = false;
let lastLevel = null;

function dismissedJobs() {
    return (storageGet("sessionStorage", "lp-dismissed-jobs") || "").split(",").filter(Boolean);
}

function evaluate(s) {
    const items = [];
    const services = s.services || {};
    for (const [unit, state] of Object.entries(services)) {
        if (state === "active") continue;
        const meta = SERVICES[unit] || {};
        const busy = TRANSIENT.includes(state);
        items.push({
            id: "svc:" + unit,
            level: svcLevel(unit, state),
            title: t(busy ? "att_svc_busy_title" : "att_svc_title", { name: svcName(unit) }),
            text: t("att_svc_text", { state: stateWord(state), impact: meta.impact ? t(meta.impact) : "" }).trim(),
            action: meta.restart ? { type: "restart", unit } : { type: "ssh", cmd: "systemctl status " + unit },
        });
    }
    if (s.miniserver === false) {
        items.push({ id: "ms", level: "bad", title: t("att_ms_title"), text: t("att_ms_text"),
            action: { type: "goto", view: "config", focus: "cfg-LOXONE_IP", label: "act_check_ms" } });
    } else if (s.miniserver === null) {
        items.push({ id: "ms-unset", level: "warn", title: t("att_ms_unset_title"), text: t("att_ms_unset_text"),
            action: { type: "goto", view: "config", focus: "cfg-LOXONE_IP", label: "act_check_ms" } });
    }
    const d = s.cert_days;
    if (typeof d === "number") {
        if (d < 0) {
            items.push({ id: "cert", level: "bad", title: t("att_cert_expired_title"), text: t("att_cert_expired_text"),
                action: { type: "renew" } });
        } else if (d < 21) {
            items.push({ id: "cert", level: d < 7 ? "bad" : "warn",
                title: d === 0 ? t("att_cert_today_title") : tn("att_cert_soon_title", d),
                text: t("att_cert_soon_text"), action: { type: "renew" } });
        }
    } else if (s.mode === "tls") {
        items.push({ id: "cert", level: "warn", title: t("att_cert_missing_title"), text: t("att_cert_missing_text"),
            action: { type: "renew" } });
    }
    if (!s.backup) {
        items.push({ id: "backup", level: "warn", title: t("att_backup_none_title"), text: t("att_backup_none_text") });
    } else if (s.backup.age_hours >= 26) {
        items.push({ id: "backup", level: "warn", title: t("att_backup_old_title", { h: num(Math.round(s.backup.age_hours)) }),
            text: t("att_backup_old_text") });
    }
    const sys = s.system || {};
    if (sys.disk_pct > 85) {
        items.push({ id: "disk", level: sys.disk_pct > 90 ? "bad" : "warn",
            title: t("att_disk_title", { p: num(sys.disk_pct) }), text: t("att_disk_text") });
    }
    if (sys.mem_pct > 90) {
        items.push({ id: "mem", level: "warn", title: t("att_mem_title", { p: num(sys.mem_pct) }), text: t("att_mem_text") });
    }
    if (s.decisions && s.decisions.error && services.crowdsec === "active") {
        items.push({ id: "decisions", level: "warn", title: t("att_dec_error_title"),
            text: t("att_dec_error_text", { err: s.decisions.error }) });
    }
    const j = s.job;
    if (j && !j.running && !dismissedJobs().includes(j.id)) {
        const st = jobStatus(j);
        if (st === "failed") {
            items.push({ id: "job", level: "bad",
                title: t(j.name === "renew-tls" ? "att_job_failed_renew" : "att_job_failed_apply", { rc: j.rc }),
                text: t("att_job_failed_text"), action: { type: "log" } });
        } else if (st === "degraded") {
            items.push({ id: "job", level: "warn", title: t("att_job_degraded_title"),
                text: t("att_job_degraded_text"), action: { type: "log" } });
        }
    }
    items.sort((a, b) => (a.level === b.level ? 0 : a.level === "bad" ? -1 : b.level === "bad" ? 1 : 0));
    const level = items.some((i) => i.level === "bad") ? "bad" : items.length ? "warn" : "ok";
    return { level, items };
}

// ─── status: rendering ──────────────────────────────────────────────────

function renderStatus() {
    const s = statusData;
    const failing = Boolean(statusErr);
    const chip = $("statusChip");
    const summary = $("summary");
    let chipState, chipText, summaryState, sIcon, title, text;
    let evaluation = null;

    if (!s) {
        if (failing) {
            chipState = "offline"; chipText = t("chip_offline");
            summaryState = "offline"; sIcon = "offline";
            title = t("sum_fail_title"); text = t("sum_fail_text", { err: errText(statusErr) });
        } else {
            chipState = "loading"; chipText = t("chip_loading");
            summaryState = "loading"; sIcon = "spinner";
            title = t("sum_loading_title"); text = "";
        }
    } else {
        evaluation = evaluate(s);
        const lv = evaluation.level;
        summaryState = lv;
        sIcon = lv;
        if (lv === "ok") { title = t("sum_ok_title"); text = t("sum_ok_text"); }
        else if (lv === "warn") { title = tn("sum_warn_title", evaluation.items.length); text = t("sum_warn_text"); }
        else { title = t("sum_bad_title"); text = t("sum_bad_text"); }
        chipState = failing ? "offline" : lv;
        chipText = failing ? t("chip_offline") : t("chip_" + lv);
    }

    chip.dataset.state = chipState;
    $("statusChipIcon").setAttribute("href", "#i-" + (chipState === "loading" ? "spinner" : chipState === "offline" ? "offline" : LEVEL_ICON[chipState]));
    $("statusChipText").textContent = chipText;
    chip.setAttribute("aria-label", t("chip_label", { state: chipText }));
    chip.querySelector(".icon").classList.toggle("is-spinning", chipState === "loading");

    summary.dataset.state = summaryState;
    $("summaryIcon").setAttribute("href", "#i-" + sIcon);
    summary.querySelector(".summary-icon").classList.toggle("is-spinning", sIcon === "spinner");
    $("summaryTitle").textContent = title;
    $("summaryText").textContent = text;
    $("summaryText").hidden = !text;
    $("retryBtn").hidden = !failing;
    const stale = $("summaryStale");
    stale.hidden = !(s && failing);
    stale.textContent = s && failing ? t("sum_stale", { time: clock(statusAt / 1000, true) }) : "";
    $("summaryMode").textContent = s ? t("sum_mode", { mode: t("mode_" + s.mode) }) : "";
    $("summaryUpdated").textContent = s && s.time ? t("sum_updated", { time: s.time.slice(11) }) : "";
    $("summarySep").hidden = !(s && s.time);

    // Announce real changes of the overall state (not every poll).
    const spoken = s ? (failing ? "offline" : evaluation.level) : (failing ? "offline" : null);
    if (spoken && lastLevel !== null && spoken !== lastLevel) {
        announce(t("chip_label", { state: chipText }) + " — " + (s && failing ? stale.textContent : title));
    }
    if (spoken) lastLevel = spoken;

    renderAttention(evaluation ? evaluation.items : []);
    renderTiles(s);
    renderDecisions(s);
    renderRestartStates(s);
    renderRenewVisibility();
}

let attentionSig = "";
function renderAttention(items) {
    const box = $("attention");
    box.hidden = items.length === 0;
    const sig = lang + "|" + items.map((i) => i.id + i.level + i.title + i.text).join("|");
    if (sig === attentionSig) return;
    attentionSig = sig;
    const list = $("attentionList");
    const active = document.activeElement;
    const focusedId = active && list.contains(active) ? active.closest("[data-item]").dataset.item : null;
    list.replaceChildren(...items.map(attentionItem));
    if (focusedId) {
        const again = list.querySelector(`[data-item="${CSS.escape(focusedId)}"] button, [data-item="${CSS.escape(focusedId)}"] a`);
        (again || (items.length ? $("attentionTitle") : $("summaryTitle"))).focus();
    }
}

function attentionItem(item) {
    const li = el("li", "att-item");
    li.dataset.item = item.id;
    li.dataset.level = item.level;
    li.append(icon(item.level, "att-icon"));
    const titleEl = el("p", "att-title");
    titleEl.append(el("span", "sr-only", t("badge_" + item.level) + ": "), document.createTextNode(item.title));
    li.append(titleEl);
    if (item.text) li.append(el("p", "att-text", item.text));
    const a = item.action;
    if (a) {
        const row = el("div", "att-actions");
        if (a.type === "restart") {
            const b = el("button", "btn btn-sm", t("act_restart"));
            b.type = "button";
            b.setAttribute("aria-label", t("restart_aria", { name: svcName(a.unit) }));
            b.addEventListener("click", () => restartService(a.unit, b, $("overviewResult")));
            row.append(b);
        } else if (a.type === "renew") {
            const b = el("button", "btn btn-sm", t("act_renew"));
            b.type = "button";
            b.addEventListener("click", () => startRenew(b, $("overviewResult")));
            row.append(b);
        } else if (a.type === "goto") {
            const link = el("a", "btn btn-sm", t(a.label));
            link.href = "#" + a.view;
            link.addEventListener("click", (e) => { e.preventDefault(); goTo(a.view, a.focus); });
            row.append(link);
        } else if (a.type === "log") {
            const b = el("button", "btn btn-sm", t("act_show_log"));
            b.type = "button";
            b.addEventListener("click", openJobLog);
            row.append(b);
        } else if (a.type === "ssh") {
            row.append(el("span", "hint", t("att_svc_ssh")), el("code", "", a.cmd));
        }
        li.append(row);
    }
    return li;
}

function setTile(id, level, value, sub) {
    const tile = $(id);
    tile.dataset.state = level;
    const badge = tile.querySelector("[data-badge]");
    badge.dataset.level = level;
    if (level === "neutral") badge.replaceChildren();
    else badge.replaceChildren(icon(level), el("span", "badge-text", t("badge_" + level)));
    const v = tile.querySelector("[data-value]");
    if (v && value !== undefined) v.textContent = value;
    const subEl = tile.querySelector("[data-sub]");
    if (subEl && sub !== undefined) { subEl.textContent = sub; subEl.hidden = !sub; }
}

function setMeter(id, level, text, fraction) {
    const m = $(id);
    m.dataset.level = level;
    m.querySelector("[data-meter-val]").textContent = text;
    m.querySelector("[data-meter-fill]").style.width = Math.round(Math.max(0, Math.min(1, fraction || 0)) * 100) + "%";
}

function renderTiles(s) {
    if (!s) return;
    // services
    const entries = Object.entries(s.services || {});
    const active = entries.filter(([, st]) => st === "active").length;
    let svcLv = "ok";
    entries.forEach(([u, st]) => {
        const lv = svcLevel(u, st);
        if (lv === "bad" || (lv === "warn" && svcLv === "ok")) svcLv = lv;
    });
    setTile("tile-services", svcLv, t("svc_count", { a: active, n: entries.length }));
    $("svcList").replaceChildren(...entries.map(([unit, st]) => {
        const li = el("li", "svc-row");
        li.append(el("span", "svc-name", svcName(unit)));
        const state = el("span", "svc-state");
        const lv = svcLevel(unit, st);
        state.dataset.level = lv;
        state.append(icon(lv), el("span", "", stateWord(st)));
        li.append(state);
        return li;
    }));

    // Miniserver
    if (s.miniserver === true) setTile("tile-ms", "ok", t("ms_yes"), t("ms_sub"));
    else if (s.miniserver === false) setTile("tile-ms", "bad", t("ms_no"), t("ms_sub"));
    else setTile("tile-ms", "warn", t("ms_unset"), t("ms_sub"));

    // certificate (hidden when the gateway doesn't terminate TLS itself)
    const d = s.cert_days;
    $("tile-cert").hidden = typeof d !== "number" && s.mode !== "tls";
    if (typeof d === "number") {
        const lv = d < 7 ? "bad" : d < 21 ? "warn" : "ok";
        const txt = d < 0 ? t("cert_expired") : d === 0 ? t("cert_today") : tn("cert_days", d);
        setTile("tile-cert", lv, txt, t("cert_sub"));
    } else if (s.mode === "tls") {
        setTile("tile-cert", "warn", t("cert_none"), t("cert_sub"));
    } else {
        setTile("tile-cert", "neutral", t("cert_unused"), t("cert_sub_unused"));
    }

    // CrowdSec decisions (informational: bans mean protection works)
    const dec = s.decisions || {};
    if (dec.error) setTile("tile-bans", "warn", t("bans_error"), dec.error);
    else setTile("tile-bans", "neutral", num(dec.count || 0), t(dec.count ? "bans_sub" : "bans_none_sub"));

    // AppSec today
    const ap = s.appsec || { hits: 0, ips: 0 };
    setTile("tile-appsec", "neutral", num(ap.hits), ap.hits ? tn("appsec_sub", ap.ips) : t("appsec_none_sub"));

    // backup
    const b = s.backup;
    if (!b) setTile("tile-backup", "warn", t("backup_none"), t("backup_none_sub"));
    else {
        const h = b.age_hours;
        const txt = h < 1 ? t("backup_recent") : h < 48 ? t("backup_hours", { h: num(Math.round(h)) }) : tn("backup_days", Math.floor(h / 24));
        setTile("tile-backup", h >= 26 ? "warn" : "ok", txt, t("backup_sub", { size: num(b.size_mb, 1) }));
    }

    // system
    const sys = s.system || {};
    const diskLv = sys.disk_pct > 90 ? "bad" : sys.disk_pct > 85 ? "warn" : "neutral";
    const memLv = sys.mem_pct > 90 ? "warn" : "neutral";
    const load = typeof sys.load === "number" ? sys.load : null;
    const loadWord = load === null ? "" : load > 2 ? t("load_high") : load >= 1 ? t("load_mid") : t("load_low");
    setMeter("meter-disk", diskLv, pct(sys.disk_pct), (sys.disk_pct || 0) / 100);
    setMeter("meter-mem", memLv, pct(sys.mem_pct), (sys.mem_pct || 0) / 100);
    setMeter("meter-load", load !== null && load > 2 ? "warn" : "neutral",
        load === null ? t("no_value") : num(load, 2) + " · " + loadWord, load === null ? 0 : load / 4);
    const sysLv = diskLv === "bad" ? "bad" : (diskLv === "warn" || memLv === "warn") ? "warn" : "ok";
    setTile("tile-system", sysLv);

    // connection mode: TLS is already named in the summary line; the tile
    // matters for the tunnel (frpc state) and for unencrypted direct mode.
    $("tile-conn").hidden = s.mode === "tls";
    if (s.mode === "tunnel") {
        const st = (s.services || {}).frpc;
        setTile("tile-conn", st && st !== "active" ? "bad" : "neutral", t("mode_tunnel"),
            t("conn_sub_tunnel", { state: stateWord(st || "unknown") }));
    } else {
        setTile("tile-conn", "neutral", t("mode_" + s.mode), t("conn_sub"));
    }
}

// ─── security view ──────────────────────────────────────────────────────

let decSig = "";
function renderDecisions(s) {
    const stateMsg = $("decState");
    const wrap = $("decWrap");
    if (!s) {
        stateMsg.hidden = false;
        stateMsg.dataset.state = statusErr ? "error" : "";
        stateMsg.textContent = statusErr ? t("dec_error", { err: errText(statusErr) }) : t("dec_loading");
        wrap.hidden = true;
        $("decCount").textContent = "";
        return;
    }
    const dec = s.decisions || { count: 0, items: [] };
    if (dec.error) {
        stateMsg.hidden = false;
        stateMsg.dataset.state = "error";
        stateMsg.textContent = t("dec_error", { err: dec.error });
        wrap.hidden = true;
        $("decCount").textContent = "";
        decSig = "";
        return;
    }
    const items = dec.items || [];
    $("decCount").textContent = tn("dec_count", dec.count || 0) +
        ((dec.count || 0) > items.length ? " " + t("dec_showing", { k: items.length }) : "");
    if (!items.length) {
        stateMsg.hidden = false;
        stateMsg.dataset.state = "";
        stateMsg.textContent = t("dec_empty");
        wrap.hidden = true;
        decSig = "";
        return;
    }
    stateMsg.hidden = true;
    wrap.hidden = false;
    const sig = lang + JSON.stringify(items);
    if (sig === decSig) return;
    decSig = sig;
    const body = $("decBody");
    const active = document.activeElement;
    const focusedIp = active && body.contains(active) ? active.dataset.ip : null;
    body.replaceChildren(...items.map((d) => {
        const tr = el("tr");
        tr.append(el("td", "ip", d.ip), el("td", "", d.scenario), el("td", "", d.origin), el("td", "", d.duration));
        const td = el("td", "act");
        const b = el("button", "btn btn-sm", t("unban"));
        b.type = "button";
        b.dataset.ip = d.ip;
        b.setAttribute("aria-label", t("unban_aria", { ip: d.ip }));
        b.addEventListener("click", () => unban(d.ip, b));
        td.append(b);
        tr.append(td);
        return tr;
    }));
    if (focusedIp) {
        const again = body.querySelector(`button[data-ip="${CSS.escape(focusedIp)}"]`);
        (again || $("decTitle")).focus();
    }
}

async function unban(ip, btn) {
    if (btn && isBusy(btn)) return false;
    const ok = await confirmDialog({
        title: t("confirm_unban_title", { ip }), text: t("confirm_unban_text"), okLabel: t("unban"), danger: true });
    if (!ok) return false;
    if (btn) setBusy(btn, true);
    const result = $("decResult");
    try {
        const r = await post("/api/unban", { ip });
        if (r.status === 200 && r.data.ok) {
            setResult(result, "ok", t("unban_ok", { ip }));
            refreshStatus();
            return true;
        }
        setResult(result, "bad", t("unban_fail", { err: serverMsg(r.data.error) || r.data.output || t("err_http", { code: r.status }) }));
    } catch (e) {
        reportError(result, "unban_fail", e);
    } finally {
        if (btn) setBusy(btn, false);
    }
    return false;
}

function isIPv4(v) {
    const parts = v.split(".");
    return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}
function isIPv6(v) {
    if (!/^[0-9A-Fa-f:.]+$/.test(v) || !v.includes(":")) return false;
    if ((v.match(/::/g) || []).length > 1) return false;
    let groups = v.split(":");
    const last = groups[groups.length - 1];
    if (last.includes(".")) { if (!isIPv4(last)) return false; groups = groups.slice(0, -1).concat(["0", "0"]); }
    const filled = groups.filter((g) => g !== "");
    if (!filled.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
    return v.includes("::") ? filled.length < 8 : groups.length === 8;
}
const isIP = (v) => isIPv4(v) || isIPv6(v);
function isHost(v) {
    const i = v.indexOf(":");
    const host = i < 0 ? v : v.slice(0, i);
    const port = i < 0 ? "" : v.slice(i + 1);
    if (i >= 0 && !(/^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) return false;
    if (isIP(host)) return true;
    return /^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$/.test(host);
}
function isCidr(v) {
    const [ip, prefix, extra] = v.split("/");
    if (extra !== undefined || !isIP(ip)) return false;
    if (prefix === undefined) return true;
    const max = isIPv4(ip) ? 32 : 128;
    return /^\d{1,3}$/.test(prefix) && Number(prefix) <= max;
}

function fieldError(input, errNode, message) {
    if (message) {
        input.setAttribute("aria-invalid", "true");
        errNode.replaceChildren(icon("bad"), el("span", "", message));
        errNode.hidden = false;
    } else {
        input.removeAttribute("aria-invalid");
        errNode.replaceChildren();
        errNode.hidden = true;
    }
}

$("unbanForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("unbanIp");
    const ip = input.value.trim();
    const msg = !ip ? t("unban_empty") : !isIP(ip) ? t("unban_invalid") : "";
    fieldError(input, $("unbanError"), msg);
    if (msg) { input.focus(); return; }
    if (await unban(ip, e.submitter || null)) input.value = "";
});
$("unbanIp").addEventListener("input", () => fieldError($("unbanIp"), $("unbanError"), ""));

function buildRestartList() {
    $("restartList").replaceChildren(...RESTARTABLE.map((unit) => {
        const li = el("li", "action-row");
        li.dataset.unit = unit;
        const info = el("div", "action-info");
        info.append(el("p", "action-name", svcName(unit)), el("p", "action-desc", t(SERVICES[unit].desc)));
        const state = el("span", "svc-state");
        state.dataset.stateFor = unit;
        const b = el("button", "btn", t("restart"));
        b.type = "button";
        b.setAttribute("aria-label", t("restart_aria", { name: svcName(unit) }));
        b.addEventListener("click", () => restartService(unit, b, $("svcResult")));
        li.append(info, state, b);
        return li;
    }));
    renderRestartStates(statusData);
}

function renderRestartStates(s) {
    document.querySelectorAll("#restartList .action-row").forEach((row) => {
        const unit = row.dataset.unit;
        const st = s && s.services ? s.services[unit] : undefined;
        row.hidden = unit === "frpc" && !(s && s.mode === "tunnel") && st === undefined;
        const cell = row.querySelector("[data-state-for]");
        if (st === undefined) { cell.replaceChildren(); return; }
        const lv = svcLevel(unit, st);
        cell.dataset.level = lv;
        cell.replaceChildren(icon(lv), el("span", "", stateWord(st)));
    });
}

async function restartService(unit, btn, resultEl) {
    if (isBusy(btn)) return;
    const name = svcName(unit);
    const ok = await confirmDialog({
        title: t("confirm_restart_title", { name }), text: t("confirm_restart_text"), okLabel: t("restart"), danger: true });
    if (!ok) return;
    setBusy(btn, true);
    try {
        const r = await post("/api/restart", { service: unit }, 40000);
        if (r.status === 200 && r.data.ok) {
            setResult(resultEl, r.data.state === "active" ? "ok" : "warn", t("restart_ok", { name, state: stateWord(r.data.state) }));
        } else {
            setResult(resultEl, "bad", t("restart_fail", { name, err: serverMsg(r.data.error) || r.data.output || t("err_http", { code: r.status }) }));
        }
    } catch (e) {
        reportError(resultEl, "restart_fail", e, { name });
    } finally {
        setBusy(btn, false);
        refreshStatus();
    }
}

$("alertBtn").addEventListener("click", async () => {
    const btn = $("alertBtn");
    if (isBusy(btn)) return;
    setBusy(btn, true);
    try {
        const r = await post("/api/test-alert", {}, 30000);
        if (r.status === 200 && r.data.ok) setResult($("alertResult"), "ok", t("alert_ok"));
        else setResult($("alertResult"), "bad", t("alert_fail", { err: serverMsg(r.data.error) || r.data.output || t("err_http", { code: r.status }) }));
    } catch (e) {
        reportError($("alertResult"), "alert_fail", e);
    } finally {
        setBusy(btn, false);
    }
});

async function startRenew(btn, resultEl) {
    if (isBusy(btn)) return;
    const ok = await confirmDialog({
        title: t("confirm_renew_title"), text: t("confirm_renew_text"), okLabel: t("renew_btn"), danger: false });
    if (!ok) return;
    setBusy(btn, true);
    try {
        const r = await post("/api/renew-tls");
        if (r.status === 200 && r.data.ok) { setResult(resultEl, "", ""); startJob(r.data.job_id, "renew-tls", true); }
        else setResult(resultEl, "bad", t("renew_fail", { err: serverMsg(r.data.error) || t("err_http", { code: r.status }) }));
    } catch (e) {
        reportError(resultEl, "renew_fail", e);
    } finally {
        setBusy(btn, false);
    }
}
$("renewBtn").addEventListener("click", () => startRenew($("renewBtn"), $("renewResult")));

function renderRenewVisibility() {
    const tlsOn = cfg && cfg.config ? String(cfg.config.ENABLE_TLS).toLowerCase() === "true" : null;
    const hasCert = statusData && typeof statusData.cert_days === "number";
    $("renewItem").hidden = tlsOn === false && !hasCert;
}

function renderAuthNote() {
    if (!cfg) { $("authNote").hidden = true; return; }
    $("authNote").hidden = false;
    $("authNoteText").textContent = t(cfg.auth_required ? "auth_note_on" : "auth_note_off");
}

// ─── background job (apply / renew-TLS) ─────────────────────────────────

let job = null;           // { id, name, state, elapsed, rc, log, waiting, revealed }
let jobTimer = null;
let jobFails = 0;

function jobStatus(j) {
    if (j.status) return j.status;
    if (j.running) return "running";
    return j.rc === 0 ? "ok" : j.rc === 3 ? "degraded" : "failed";
}
const jobKind = () => (job && job.name === "renew-tls" ? "renew" : "apply");

function jobTitle() {
    if (!job) return "";
    switch (job.state) {
        case "running": return t("job_running_" + jobKind());
        case "ok": return t("job_ok_" + jobKind());
        case "degraded": return t("att_job_degraded_title");
        case "failed": return t(job.name === "renew-tls" ? "att_job_failed_renew" : "att_job_failed_apply", { rc: job.rc });
        default: return t("job_lost");
    }
}

function renderJob() {
    const panel = $("jobPanel");
    if (!job || !job.revealed || dismissedJobs().includes(job.id)) { panel.hidden = true; return; }
    panel.hidden = false;
    panel.dataset.state = job.state;
    const iconName = { running: "spinner", ok: "ok", degraded: "warn", failed: "bad", lost: "warn" }[job.state];
    $("jobIcon").setAttribute("href", "#i-" + iconName);
    panel.querySelector(".job-icon").classList.toggle("is-spinning", job.state === "running");
    $("jobTitle").textContent = jobTitle();
    let meta;
    if (job.state === "running") meta = job.waiting ? t("job_waiting") : t("job_elapsed", { t: duration(job.elapsed) });
    else if (job.state === "degraded") meta = t("att_job_degraded_text");
    else if (job.state === "failed") meta = t("att_job_failed_text");
    else if (job.state === "lost") meta = t("job_lost_text");
    else meta = t("job_meta_done", { id: job.id });
    $("jobMeta").textContent = meta;
    $("jobClose").hidden = job.state === "running";
    const pre = $("jobLog");
    const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
    if (pre.textContent !== job.log) {
        pre.textContent = job.log || "";
        if (atEnd) pre.scrollTop = pre.scrollHeight;
    }
    $("jobDetails").hidden = !job.log;
}

function scheduleJobPoll(ms) {
    window.clearTimeout(jobTimer);
    jobTimer = window.setTimeout(pollJob, ms);
}

function startJob(id, name, speak) {
    if (job && job.id === id && job.state === "running") return;
    job = { id, name, state: "running", elapsed: 0, rc: null, log: job && job.id === id ? job.log : "", waiting: false, revealed: true };
    jobFails = 0;
    renderJob();
    if (speak) announce(t("job_started", { title: jobTitle() }));
    scheduleJobPoll(speak ? 800 : 0);
}

function finishJob(state) {
    const wasRunning = job.state === "running";
    job.state = state;
    job.waiting = false;
    window.clearTimeout(jobTimer);
    renderJob();
    if (wasRunning) announce(jobTitle() + ". " + $("jobMeta").textContent);
    refreshStatus();
    if (job.name === "apply") loadConfig();
}

async function pollJob() {
    if (!job) return;
    try {
        const d = await getJSON("/api/job/" + encodeURIComponent(job.id), 10000);
        jobFails = 0;
        job.waiting = false;
        job.name = d.job.name;
        job.elapsed = d.job.elapsed;
        job.rc = d.job.rc;
        job.log = d.log || "";
        const st = jobStatus(d.job);
        if (st === "running") { renderJob(); scheduleJobPoll(2000); }
        else finishJob(st);
    } catch (e) {
        if (e.kind === "http" && e.status === 404) { finishJob("lost"); return; }
        jobFails += 1;
        job.waiting = true;
        renderJob();
        if (jobFails > 60) { finishJob("lost"); return; }   // ~10 minutes without an answer
        scheduleJobPoll(Math.min(2000 * Math.pow(2, Math.min(jobFails, 3)), 10000));
    }
}

/* The status poll also reports the current job — e.g. one started from
   another browser, or a finished one after a page reload. */
function syncJobFromStatus(j) {
    if (!j) return;
    if (j.running) { startJob(j.id, j.name, false); return; }
    if (job && job.id === j.id) return;
    const st = jobStatus(j);
    if ((st === "failed" || st === "degraded") && !dismissedJobs().includes(j.id)) {
        // Shown in "what to do"; the panel itself opens via "show log".
        job = { id: j.id, name: j.name, state: st, elapsed: j.elapsed, rc: j.rc, log: "", waiting: false, revealed: false };
        renderJob();
        getJSON("/api/job/" + encodeURIComponent(j.id), 10000)
            .then((d) => { if (job && job.id === j.id) { job.log = d.log || ""; renderJob(); } })
            .catch(() => { /* log tail is optional here */ });
    }
}

$("jobClose").addEventListener("click", () => {
    if (!job) return;
    storageSet("sessionStorage", "lp-dismissed-jobs", dismissedJobs().concat(job.id).slice(-20).join(","));
    renderJob();
    renderStatus();
    $("h-" + (view || "overview")).focus();
});

function openJobLog() {
    if (!job) return;
    job.revealed = true;
    renderJob();
    $("jobDetails").open = true;
    $("jobPanel").scrollIntoView({ block: "start" });
    $("jobDetails").querySelector("summary").focus();
}

// ─── configuration: invite / QR ─────────────────────────────────────────

let cfg = null;
let cfgErr = null;
let cfgLoading = false;

function renderInvite() {
    const box = $("qrBox");
    if (!cfg) {
        const msg = el("p", "state-msg", cfgErr ? t("cfg_load_fail", { err: cfgErr }) : t("cfg_loading"));
        box.replaceChildren(msg);
        return;
    }
    const host = cfg.qr_host || "";
    const link = host ? "loxone://ms?host=" + host : "";
    $("qrHostValue").textContent = host || t("no_value");
    $("qrSource").textContent = t("inv_source_" + (cfg.qr_mode || "unset"));
    $("qrLink").value = link;
    if (link) $("qrCopy").removeAttribute("aria-disabled");
    else $("qrCopy").setAttribute("aria-disabled", "true");
    $("qrPrint").href = "/invite?lang=" + lang;
    if (host) {
        const current = box.querySelector("img");
        if (!current || current.dataset.host !== host) {
            const img = el("img");
            img.alt = t("inv_qr_alt", { link });
            img.dataset.host = host;
            img.width = 176;
            img.height = 176;
            img.addEventListener("error", () => box.replaceChildren(el("p", "state-msg", t("inv_qr_failed"))));
            img.src = "/qr.svg?host=" + encodeURIComponent(host);
            box.replaceChildren(img);
        } else {
            current.alt = t("inv_qr_alt", { link });
        }
    } else {
        box.replaceChildren(el("p", "state-msg", t("inv_qr_none")));
    }
    if (document.activeElement !== $("qrManual") && !$("qrManual").dataset.edited) {
        $("qrManual").value = cfg.qr_mode === "manual" ? host : "";
    }
}

$("qrManual").addEventListener("input", () => {
    $("qrManual").dataset.edited = "1";
    fieldError($("qrManual"), $("qrManualError"), "");
});

$("qrForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("qrManual");
    const host = input.value.trim();
    if (host && !isHost(host)) {
        fieldError(input, $("qrManualError"), t("inv_invalid"));
        input.focus();
        return;
    }
    fieldError(input, $("qrManualError"), "");
    try {
        const r = await post("/api/qr-host", { host });
        if (r.status === 200 && r.data.ok) {
            delete input.dataset.edited;
            setResult($("qrResult"), "ok", t(host ? "inv_saved" : "inv_cleared"));
            loadConfig();
        } else if (r.data.error === "invalid host") {
            fieldError(input, $("qrManualError"), t("inv_invalid"));
            input.focus();
        } else {
            setResult($("qrResult"), "bad", t("inv_save_fail", { err: serverMsg(r.data.error) || t("err_http", { code: r.status }) }));
        }
    } catch (err) {
        reportError($("qrResult"), "inv_save_fail", err);
    }
});

$("qrCopy").addEventListener("click", async () => {
    const input = $("qrLink");
    const link = input.value;
    if (!link) return;
    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(link);
            setResult($("qrResult"), "ok", t("inv_copied"));
            return;
        }
    } catch (e) { /* fall through to the selection fallback */ }
    input.focus();
    input.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch (e) { copied = false; }
    setResult($("qrResult"), copied ? "ok" : "info", t(copied ? "inv_copied" : "inv_copy_fail"));
});

// ─── configuration: typed editor driven by the server's EDITABLE_KEYS ───

const CFG_GROUPS = [
    ["grp_backend", ["LOXONE_IP", "LOXONE_PORT"]],
    ["grp_rate", ["RATE_LIMIT_REQ_PER_SEC", "RATE_LIMIT_BURST", "RATE_LIMIT_CONN_PER_IP"]],
    ["grp_timeouts", ["PROXY_CONNECT_TIMEOUT", "PROXY_SEND_TIMEOUT", "PROXY_READ_TIMEOUT",
        "CLIENT_BODY_TIMEOUT", "CLIENT_HEADER_TIMEOUT"]],
    ["grp_appsec", ["ENABLE_APPSEC", "APPSEC_MODE", "CROWDSEC_WHITELIST_IPS"]],
    ["grp_alert", ["DISCORD_WEBHOOK_URL", "ALERT_EMAIL", "AUTOREBOOT_TIME"]],
    ["grp_tls", ["ENABLE_TLS", "TLS_DOMAIN", "TLS_EMAIL"]],
    ["grp_tunnel", ["ENABLE_TUNNEL", "TUNNEL_SERVER_ADDR", "TUNNEL_SERVER_PORT", "TUNNEL_PROTOCOL",
        "TUNNEL_TOKEN", "TUNNEL_PROXY_NAME", "TUNNEL_REMOTE_PORT", "TUNNEL_PUBLIC_HOST"]],
    ["grp_gui", ["ENABLE_GUI", "GUI_PORT", "GUI_PASSWORD"]],
];
const ENUMS = { appsec_mode: ["enforce", "monitor"], tunnel_proto: ["quic", "tcp"] };
const MASK = "•••";
const KEY_HINTS = { GUI_PASSWORD: "h_gui_password", ENABLE_GUI: "h_enable_gui" };

const VALIDATORS = {
    ip: isIP,
    port: (v) => /^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 65535,
    int: (v) => /^\d+$/.test(v) && Number(v) > 0 && Number(v) < 100000,
    bool: () => true,
    appsec_mode: (v) => ENUMS.appsec_mode.includes(v),
    tunnel_proto: (v) => ENUMS.tunnel_proto.includes(v),
    hhmm: (v) => /^([01]\d|2[0-3]):[0-5]\d$/.test(v),
    url_or_empty: (v) => v === "" || v.startsWith("https://"),
    email_or_empty: (v) => v === "" || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v),
    host_or_empty: (v) => v === "" || isHost(v),
    name: (v) => /^[A-Za-z0-9_-]{1,64}$/.test(v),
    secret: (v) => v.length <= 256 && !v.includes("\n") && !v.includes('"'),
    cidr_array: (v) => v.split(/[\s,]+/).filter(Boolean).every(isCidr),
};

const fields = new Map();   // key -> { kind, input, clear, original, masked, err, changed }

function displayValue(kind, value) {
    let v = Array.isArray(value) ? value.join(" ") : String(value === undefined || value === null ? "" : value);
    if (kind === "cidr_array" && /^\(.*\)$/.test(v)) {
        v = v.slice(1, -1).replace(/"/g, " ").trim().replace(/\s+/g, " ");
    }
    return v;
}

function hintKey(key, kind) {
    return KEY_HINTS[key] || "h_" + kind;
}

function buildField(key, kind, value) {
    const id = "cfg-" + key;
    const wrap = el("div", "field");
    wrap.dataset.key = key;
    const masked = value === MASK;
    const fk = "f_" + key;
    const labelText = el("span", "", fk in I18N.de ? t(fk) : key);
    if (fk in I18N.de) labelText.dataset.i18n = fk;
    const changed = el("span", "field-changed", t("field_changed"));
    changed.dataset.i18n = "field_changed";
    changed.hidden = true;
    const keyEl = el("span", "key", key);
    keyEl.setAttribute("lang", "en");

    const hint = el("p", "hint");
    hint.id = id + "-hint";
    const hk = hintKey(key, kind);
    if (masked) {
        hint.textContent = t("masked_hint") + (hk in I18N.de && kind !== "bool" ? " " + t(hk) : "");
    } else if (hk in I18N.de) {
        hint.textContent = t(hk);
        hint.dataset.i18n = hk;
    }
    const err = el("p", "field-error");
    err.id = id + "-err";
    err.hidden = true;

    let input;
    let original;
    let clear = null;
    if (kind === "bool") {
        const labelId = id + "-label";
        const label = el("span", "field-label");
        label.id = labelId;
        label.append(labelText, changed, keyEl);
        const sw = el("label", "switch");
        input = el("input");
        input.type = "checkbox";
        input.id = id;
        input.setAttribute("role", "switch");
        input.setAttribute("aria-labelledby", labelId);
        input.checked = String(value).toLowerCase() === "true";
        const stateText = el("span", "switch-state");
        stateText.setAttribute("aria-hidden", "true");
        const sync = () => { stateText.textContent = t(input.checked ? "sw_on" : "sw_off"); };
        input.addEventListener("change", sync);
        sync();
        sw.append(input, el("span", "switch-track"), stateText);
        sw.querySelector(".switch-track").setAttribute("aria-hidden", "true");
        wrap.append(label);
        if (hint.textContent) wrap.append(hint);
        wrap.append(sw, err);
        original = input.checked ? "true" : "false";
    } else {
        const label = el("label", "field-label");
        label.htmlFor = id;
        label.append(labelText, changed, keyEl);
        if (ENUMS[kind]) {
            input = el("select", "select");
            const opts = ENUMS[kind].slice();
            if (value && !opts.includes(value)) opts.push(value);
            input.append(...opts.map((o) => { const op = el("option", "", o); op.value = o; return op; }));
            input.value = value && opts.includes(value) ? value : opts[0];
            original = input.value;
        } else {
            input = el("input", "input");
            input.type = masked || kind === "secret" ? "password" : "text";
            input.autocomplete = masked || kind === "secret" ? "new-password" : "off";
            input.spellcheck = false;
            input.setAttribute("autocapitalize", "off");
            if (["ip", "port", "int", "hhmm", "cidr_array", "host_or_empty", "name"].includes(kind)) input.classList.add("mono");
            if (kind === "port" || kind === "int") input.inputMode = "numeric";
            if (kind === "email_or_empty") input.type = "email";
            if (kind === "url_or_empty" && !masked) input.type = "url";
            original = masked ? "" : displayValue(kind, value);
            input.value = original;
        }
        input.id = id;
        input.name = key;
        wrap.append(label);
        if (hint.textContent) wrap.append(hint);
        wrap.append(input);
        if (masked) {
            clear = el("input");
            clear.type = "checkbox";
            clear.id = id + "-clear";
            const cl = el("label", "check masked-clear");
            const span = el("span", "", t("masked_clear"));
            span.dataset.i18n = "masked_clear";
            cl.append(clear, span);
            clear.addEventListener("change", () => {
                input.disabled = clear.checked;
                if (clear.checked) input.value = "";
                updateDirty();
            });
            wrap.append(cl);
        }
        wrap.append(err);
    }
    const described = [hint.textContent ? hint.id : "", err.id].filter(Boolean).join(" ");
    input.setAttribute("aria-describedby", described);
    input.addEventListener(input.type === "checkbox" || input.tagName === "SELECT" ? "change" : "input", () => {
        fieldError(input, err, "");
        updateDirty();
    });
    fields.set(key, { kind, input, clear, original, masked, err, changed, labelText });
    return wrap;
}

function currentValue(f) {
    if (f.clear && f.clear.checked) return "";
    if (f.kind === "bool") return f.input.checked ? "true" : "false";
    return f.kind === "secret" || f.masked ? f.input.value : f.input.value.trim();
}

function fieldChanged(f) {
    if (f.masked) return Boolean(f.clear && f.clear.checked) || f.input.value !== "";
    return currentValue(f) !== f.original;
}

function updateDirty() {
    let n = 0;
    fields.forEach((f) => {
        const c = fieldChanged(f);
        f.changed.hidden = !c;
        if (c) n += 1;
    });
    const note = $("cfgDirty");
    note.textContent = n ? tn("cfg_dirty", n) : t("cfg_clean");
    note.dataset.dirty = n ? "true" : "false";
    $("cfgReset").hidden = !n;
    return n;
}
const isDirty = () => fields.size > 0 && [...fields.values()].some(fieldChanged);

function buildForm() {
    const form = $("cfgForm");
    fields.clear();
    const config = cfg.config || {};
    const schema = cfg.schema || {};
    const groups = CFG_GROUPS.map(([g, keys]) => [g, keys.filter((k) => k in config)])
        .filter(([, keys]) => keys.length);
    const rest = Object.keys(config).filter((k) => !CFG_GROUPS.some(([, keys]) => keys.includes(k)));
    if (rest.length) groups.push(["grp_other", rest]);
    form.replaceChildren(...groups.map(([g, keys]) => {
        const fs = el("fieldset", "cfg-group");
        const legend = el("legend", "", t(g));
        legend.dataset.i18n = g;
        const grid = el("div", "cfg-fields");
        keys.forEach((k) => grid.append(buildField(k, schema[k] || "secret", config[k])));
        fs.append(legend, grid);
        return fs;
    }));
    form.hidden = false;
    $("cfgActions").hidden = false;
    $("cfgState").hidden = true;
    clearErrors();
    updateDirty();
}

function renderCfgState() {
    const node = $("cfgState");
    if (cfg) { node.hidden = true; return; }
    node.hidden = false;
    node.dataset.state = cfgErr ? "error" : "";
    node.textContent = cfgErr ? t("cfg_load_fail", { err: cfgErr }) : t("cfg_loading");
}

async function loadConfig() {
    if (cfgLoading) return;
    cfgLoading = true;
    try {
        cfg = await getJSON("/api/config");
        cfgErr = null;
        authRequired = Boolean(cfg.auth_required);
        if (!isDirty()) buildForm();
    } catch (e) {
        cfgErr = errText(e);
    } finally {
        cfgLoading = false;
    }
    renderCfgState();
    renderInvite();
    renderAuthNote();
    renderRenewVisibility();
}

function clearErrors() {
    $("cfgErrors").hidden = true;
    $("cfgErrorsList").replaceChildren();
    fields.forEach((f) => fieldError(f.input, f.err, ""));
}

function showErrors(errors) {
    const keys = Object.keys(errors);
    fields.forEach((f, k) => fieldError(f.input, f.err, errors[k] || ""));
    const box = $("cfgErrors");
    $("cfgErrorsTitle").replaceChildren(icon("bad"), el("span", "", tn("cfg_err_summary", keys.length)));
    $("cfgErrorsList").replaceChildren(...keys.map((k) => {
        const li = el("li");
        const f = fields.get(k);
        const a = el("a", "", (f ? f.labelText.textContent : k) + ": " + errors[k]);
        a.href = "#cfg-" + k;
        a.addEventListener("click", (e) => { e.preventDefault(); if (f) f.input.focus(); });
        li.append(a);
        return li;
    }));
    box.hidden = false;
    box.focus();
}

function collectChanges() {
    const changes = {};
    const errors = {};
    fields.forEach((f, key) => {
        if (!fieldChanged(f)) return;
        const v = currentValue(f);
        const check = VALIDATORS[f.kind] || VALIDATORS.secret;
        if (!check(v)) errors[key] = t("err_field", { hint: t(hintKey(key, f.kind)) });
        else changes[key] = v;
    });
    return { changes, errors };
}

async function saveConfig() {
    const result = $("cfgResult");
    clearErrors();
    const { changes, errors } = collectChanges();
    if (Object.keys(errors).length) { showErrors(errors); return false; }
    const keys = Object.keys(changes);
    if (!keys.length) { setResult(result, "info", t("cfg_nochange")); return true; }
    setResult(result, "info", t("cfg_saving"));
    try {
        const r = await post("/api/config", { changes });
        if (r.status === 200 && r.data.ok) {
            if ("GUI_PASSWORD" in changes) {
                setPassword(changes.GUI_PASSWORD);
                authRequired = Boolean(changes.GUI_PASSWORD);
            }
            fields.clear();                // everything is saved: allow a clean rebuild
            setResult(result, "ok", t("cfg_saved", { keys: (r.data.changed || keys).join(", ") }));
            await loadConfig();
            return true;
        }
        if (r.data.errors) {
            const mapped = {};
            for (const [k, msg] of Object.entries(r.data.errors)) {
                const f = fields.get(k);
                mapped[k] = msg === "not editable" ? t("err_not_editable")
                    : t("err_field", { hint: t(hintKey(k, f ? f.kind : "secret")) });
            }
            setResult(result, "", "");
            showErrors(mapped);
            return false;
        }
        setResult(result, "bad", t("cfg_save_fail", { err: serverMsg(r.data.error) || t("err_http", { code: r.status }) }));
    } catch (e) {
        reportError(result, "cfg_save_fail", e);
    }
    return false;
}

$("cfgForm").addEventListener("submit", (e) => { e.preventDefault(); saveConfig(); });

$("cfgReset").addEventListener("click", () => {
    if (!cfg) return;
    fields.clear();
    buildForm();
    setResult($("cfgResult"), "info", t("cfg_discarded"));
    $("cfgSave").focus();
});

$("applyBtn").addEventListener("click", async () => {
    const btn = $("applyBtn");
    if (isBusy(btn)) return;
    const dirty = isDirty();
    const ok = await confirmDialog({
        title: t("confirm_apply_title"), text: t("confirm_apply_text"),
        extra: dirty ? t("confirm_apply_dirty") : "",
        okLabel: dirty ? t("save_apply_btn") : t("apply_btn"), danger: false });
    if (!ok) return;
    setBusy(btn, true);
    try {
        if (dirty && !(await saveConfig())) return;
        const r = await post("/api/apply");
        if (r.status === 200 && r.data.ok) startJob(r.data.job_id, "apply", true);
        else setResult($("cfgResult"), "bad", t("apply_fail", { err: serverMsg(r.data.error) || t("err_http", { code: r.status }) }));
    } catch (e) {
        reportError($("cfgResult"), "apply_fail", e);
    } finally {
        setBusy(btn, false);
    }
});

window.addEventListener("beforeunload", (e) => {
    if (isDirty()) { e.preventDefault(); e.returnValue = t("leave_warning"); }
});

// ─── logs ───────────────────────────────────────────────────────────────

const LOGS = ["nginx-error", "nginx-access", "appsec", "watchdog", "tunnel-watchdog", "monitor", "deploy", "gui"];
const logKey = (name) => "log_" + name.replace(/-/g, "_");
let logName = LOGS.includes(storageGet("sessionStorage", "lp-log")) ? storageGet("sessionStorage", "lp-log") : LOGS[0];
let logText = null;
let logErr = null;
let logAt = 0;
let logLoading = false;
let followTimer = null;
let filterTimer = null;

function buildLogChoice() {
    $("logChoiceList").replaceChildren(...LOGS.map((name) => {
        const item = el("label", "seg-item");
        const input = el("input");
        input.type = "radio";
        input.name = "log";
        input.value = name;
        input.checked = name === logName;
        input.addEventListener("change", () => {
            logName = name;
            storageSet("sessionStorage", "lp-log", name);
            logText = null;
            loadLog(true);
        });
        const span = el("span", "", t(logKey(name)));
        span.dataset.i18n = logKey(name);
        item.append(input, span);
        return item;
    }));
}

async function loadLog(scrollEnd) {
    if (logLoading) return;
    logLoading = true;
    if (logText === null) $("logMeta").textContent = t("log_loading");
    const name = logName;
    try {
        const d = await getJSON("/api/log/" + encodeURIComponent(name));
        if (name !== logName) return;
        logText = d.lines || "";
        logErr = null;
        logAt = Date.now() / 1000;
    } catch (e) {
        if (logErr === null) announce(t("log_fail", { err: errText(e) }));
        logErr = errText(e);
    } finally {
        logLoading = false;
    }
    renderLog(scrollEnd);
}

function renderLog(scrollEnd) {
    const pre = $("logView");
    const meta = $("logMeta");
    pre.setAttribute("aria-label", t("log_region", { name: t(logKey(logName)) }));
    if (logErr && logText === null) {
        meta.textContent = t("log_fail", { err: logErr });
        pre.textContent = "";
        return;
    }
    if (logText === null) return;
    const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 24;
    const all = logText ? logText.split("\n") : [];
    const q = $("logFilter").value.trim().toLowerCase();
    const shown = q ? all.filter((l) => l.toLowerCase().includes(q)) : all;
    const time = clock(logAt, true);
    if (logText.startsWith("(not readable:")) {
        meta.textContent = t("log_unreadable");
        pre.textContent = logText;
    } else if (!all.length) {
        meta.textContent = t("log_empty");
        pre.textContent = "";
    } else if (!shown.length) {
        meta.textContent = t("log_nomatch");
        pre.textContent = "";
    } else {
        meta.textContent = q ? t("log_meta_filtered", { m: num(shown.length), n: num(all.length), time })
            : t("log_meta", { n: num(all.length), time });
        if (logErr) meta.textContent += " · " + t("log_fail", { err: logErr });
        const text = shown.join("\n");
        if (pre.textContent !== text) {
            pre.textContent = text;
            if (scrollEnd || atEnd) pre.scrollTop = pre.scrollHeight;
        }
    }
}

$("logReload").addEventListener("click", () => loadLog(true));
$("logFilter").addEventListener("input", () => {
    window.clearTimeout(filterTimer);
    filterTimer = window.setTimeout(() => renderLog(true), 150);
});
$("logFollow").addEventListener("change", () => {
    window.clearInterval(followTimer);
    followTimer = null;
    if ($("logFollow").checked) {
        loadLog(true);
        followTimer = window.setInterval(() => {
            if (view === "logs" && !document.hidden) loadLog(false);
        }, 5000);
    }
});

// ─── history charts ─────────────────────────────────────────────────────

let history = null;
let historyErr = null;
const chartCtx = { t, num, time: (s) => clock(s, false), announce };
const charts = [
    ["chart-req", { kind: "line", titleKey: "ch_req", noteKey: "ch_note_avg", key: "req", agg: "avg", decimals: 0, floor: 5 }],
    ["chart-load", { kind: "line", titleKey: "ch_load", noteKey: "ch_note_avg", key: "load", agg: "avg", decimals: 2, floor: 1 }],
    ["chart-bans", { kind: "line", titleKey: "ch_bans", noteKey: "ch_note_max", key: "bans", agg: "max", decimals: 0, floor: 4 }],
    ["chart-appsec", { kind: "bars", titleKey: "ch_appsec", key: "sec", agg: "sum", decimals: 0, floor: 4 }],
].map(([id, spec]) => createChart($(id), spec, chartCtx));

function renderCharts() {
    charts.forEach((c) => c.render(history, history ? null : historyErr));
}

async function refreshHistory() {
    try {
        history = await getJSON("/api/history", 20000);
        historyErr = null;
    } catch (e) {
        historyErr = errText(e);
    }
    renderCharts();
}

// ─── status polling ─────────────────────────────────────────────────────

async function refreshStatus() {
    if (statusInFlight) return;
    statusInFlight = true;
    try {
        const d = await getJSON("/api/status", 30000);
        statusData = d.status;
        statusAt = Date.now();
        statusErr = null;
    } catch (e) {
        statusErr = e;
    } finally {
        statusInFlight = false;
    }
    renderStatus();
    if (statusData && !statusErr) syncJobFromStatus(statusData.job);
}

$("retryBtn").addEventListener("click", () => {
    refreshStatus();
    if (!history) refreshHistory();
    if (!cfg) loadConfig();
});

// ─── language ───────────────────────────────────────────────────────────

function applyLang() {
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-i18n]").forEach((node) => { node.textContent = t(node.dataset.i18n); });
    document.querySelectorAll("[data-i18n-aria]").forEach((node) => { node.setAttribute("aria-label", t(node.dataset.i18nAria)); });
    $("langBtnShort").textContent = t("lang_short");
    $("langBtnLabel").textContent = t("lang_btn");
    $("langBtn").setAttribute("lang", lang === "de" ? "en" : "de");
    $("inviteLink").href = "/invite?lang=" + lang;
    $("themeBtnLabel").textContent = t("theme_btn", { mode: t("theme_" + currentTheme()) });
    if (view) document.title = t(VIEW_TITLE[view]) + " · LoxProx Panel";
}

$("langBtn").addEventListener("click", () => {
    lang = lang === "de" ? "en" : "de";
    storageSet("localStorage", "lp-lang", lang);
    applyLang();
    buildRestartList();
    fields.forEach((f, key) => {
        const hk = hintKey(key, f.kind);
        const hint = $("cfg-" + key + "-hint");
        if (hint && f.masked) hint.textContent = t("masked_hint") + (hk in I18N.de && f.kind !== "bool" ? " " + t(hk) : "");
        if (f.kind === "bool") f.input.dispatchEvent(new Event("change"));
    });
    updateDirty();
    renderStatus();
    renderJob();
    renderInvite();
    renderCfgState();
    renderAuthNote();
    renderCharts();
    if (logText !== null || logErr) renderLog(false);
});

// ─── boot ───────────────────────────────────────────────────────────────

applyLang();
setTheme(currentTheme(), false);
buildRestartList();
buildLogChoice();
showView(viewFromHash() || "overview", false);
renderStatus();
renderCharts();
renderInvite();
renderCfgState();
loadConfig();
refreshStatus();
refreshHistory();

window.setInterval(() => { if (!document.hidden) refreshStatus(); }, 10000);
window.setInterval(() => { if (!document.hidden) refreshHistory(); }, 60000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });
