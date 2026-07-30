/* LoxProx Panel v2.2 — dashboard app.
   Vendored three.js (background scene) + anime.js (transitions, counters,
   chart draw-ins). Talks only to the panel's own /api endpoints. */

import * as THREE from "/static/vendor/three.module.min.js";
import { animate, stagger } from "/static/vendor/anime.esm.min.js";

// ─── i18n ────────────────────────────────────────────────────────────────

const I18N = {
    de: {
        invite: "Einladung öffnen",
        tab_overview: "Übersicht", tab_security: "Sicherheit",
        tab_config: "Konfiguration", tab_logs: "Logs",
        hero_kicker: "Loxone Security Gateway",
        hero_ok: "Alles im grünen Bereich",
        hero_warn: "Beobachtung aktiv",
        hero_bad: "Eingriff erforderlich",
        hs_req: "Anfragen/Min", hs_bans: "Blockierte Zugriffe",
        hs_appsec: "Abgewehrte Angriffe", hs_cert: "Zertifikat (Tage)",
        ch_req: "Anfragen pro Minute", ch_load: "Systemlast",
        ch_res: "Ressourcen", ch_bans: "Aktive Sperren (24h)",
        ch_appsec: "AppSec-Treffer (24h)", ch_24h: "vor 24h", ch_now: "jetzt",
        no_data: "Sammle Daten … erste Punkte erscheinen in wenigen Minuten.",
        h_qr: "Familien-Einladung", qr_none: "Kein QR verfügbar",
        qr_host: "Öffentliche Adresse (Host[:Port])",
        save: "Speichern", copy_link: "Link kopieren",
        qr_note: "Der QR-Code enthält nur die Adresse — nie Zugangsdaten. Jedes Familienmitglied nutzt eigenen Miniserver-Benutzer.",
        h_bans: "Aktive Sperren (CrowdSec)", t_origin: "Quelle",
        t_scenario: "Szenario", t_duration: "Dauer", unban: "IP entsperren",
        h_actions: "Aktionen", renew: "TLS-Zertifikat erneuern",
        test_alert: "Discord-Testalarm",
        actions_note: "Neustarts unterbrechen aktive Verbindungen kurz.",
        h_config: "Konfiguration", save_cfg: "Konfiguration speichern",
        apply: "Anwenden (deploy.sh)",
        cfg_note: "Speichern schreibt /etc/loxprox/deploy.conf (mit Backup). Erst 'Anwenden' aktiviert Änderungen. Netz-Grundwerte (GATEWAY_IP, LAN_SUBNET, SSH) nur per SSH.",
        h_logs: "Logs", follow: "Folgen",
        grp_backend: "Miniserver", grp_rate: "Rate-Limits",
        grp_timeouts: "Timeouts", grp_appsec: "AppSec & CrowdSec",
        grp_alert: "Alarme & Wartung", grp_tls: "TLS", grp_tunnel: "Tunnel",
        grp_gui: "Panel", grp_other: "Weitere",
        svc: "Dienste", cert: "TLS-Zertifikat", days: "Tage übrig",
        ms: "Miniserver", reach: "erreichbar", unreach: "NICHT erreichbar",
        bans: "Blockierte Zugriffe", appsec: "Abgewehrte Angriffe (heute)", backup: "Letztes Backup",
        hours_ago: "h alt", sys: "System", mode: "Verbindungsart", no_cert: "kein Zertifikat",
        svc_sub: "Die Schutzsoftware im Hintergrund",
        cert_sub: "Erneuert sich automatisch",
        ms_sub: "Die Loxone-Zentrale im Haus",
        bans_sub: "Ausgesperrte Absender-Adressen",
        appsec_sub: "Schädliche Anfragen, von der Firewall gestoppt",
        backup_sub: "Sicherung der Gateway-Konfiguration",
        sys_sub: "Zustand des Gateway-Rechners",
        mode_sub: "Wie deine Verbindung von außen geschützt ist",
        mode_tls: "Verschlüsselt (TLS)", mode_tunnel: "Tunnel", mode_plain: "Direkt (HTTP)",
        appsec_ips: "Adressen",
        sys_disk: "Speicherplatz", sys_mem: "Arbeitsspeicher", sys_load: "Auslastung",
        load_low: "niedrig", load_mid: "normal", load_high: "hoch",
        confirm_restart: "Dienst wirklich neu starten: ",
        confirm_unban: "IP entsperren: ", confirm_apply: "deploy.sh jetzt ausführen?",
        need_pw: "Passwort (X-LoxProx-Auth)",
        done: "Fertig", failed: "Fehlgeschlagen",
        degraded: "Fertig, mit Einschränkungen — Protokoll unten prüfen",
        theme_auto: "Design: automatisch", theme_light: "Design: hell",
        theme_dark: "Design: dunkel", updated: "aktualisiert",
    },
    en: {
        invite: "Open invitation",
        tab_overview: "Overview", tab_security: "Security",
        tab_config: "Configuration", tab_logs: "Logs",
        hero_kicker: "Loxone Security Gateway",
        hero_ok: "All systems secure",
        hero_warn: "Watching closely",
        hero_bad: "Attention required",
        hs_req: "Requests/min", hs_bans: "Blocked visitors",
        hs_appsec: "Attacks blocked", hs_cert: "Certificate (days)",
        ch_req: "Requests per minute", ch_load: "System load",
        ch_res: "Resources", ch_bans: "Active bans (24h)",
        ch_appsec: "AppSec hits (24h)", ch_24h: "24h ago", ch_now: "now",
        no_data: "Collecting data … first points appear within minutes.",
        h_qr: "Family invitation", qr_none: "No QR available",
        qr_host: "Public address (host[:port])",
        save: "Save", copy_link: "Copy link",
        qr_note: "The QR encodes only the address — never credentials. Give each family member their own Miniserver user.",
        h_bans: "Active bans (CrowdSec)", t_origin: "Origin",
        t_scenario: "Scenario", t_duration: "Duration", unban: "Unban IP",
        h_actions: "Actions", renew: "Renew TLS certificate",
        test_alert: "Discord test alert",
        actions_note: "Restarts briefly interrupt active connections.",
        h_config: "Configuration", save_cfg: "Save configuration",
        apply: "Apply (deploy.sh)",
        cfg_note: "Save writes /etc/loxprox/deploy.conf (backed up first). Only 'Apply' activates changes. Core network keys (GATEWAY_IP, LAN_SUBNET, SSH) are SSH-only.",
        h_logs: "Logs", follow: "Follow",
        grp_backend: "Miniserver", grp_rate: "Rate limits",
        grp_timeouts: "Timeouts", grp_appsec: "AppSec & CrowdSec",
        grp_alert: "Alerts & maintenance", grp_tls: "TLS", grp_tunnel: "Tunnel",
        grp_gui: "Panel", grp_other: "Other",
        svc: "Services", cert: "TLS certificate", days: "days left",
        ms: "Miniserver", reach: "reachable", unreach: "NOT reachable",
        bans: "Blocked visitors", appsec: "Attacks blocked (today)", backup: "Last backup",
        hours_ago: "h old", sys: "System", mode: "Connection type", no_cert: "no certificate",
        svc_sub: "The protection software running in the background",
        cert_sub: "Renews automatically",
        ms_sub: "The Loxone hub in your home",
        bans_sub: "Addresses currently locked out",
        appsec_sub: "Malicious requests stopped by the firewall",
        backup_sub: "Backup of the gateway configuration",
        sys_sub: "Health of the gateway computer",
        mode_sub: "How your remote connection is secured",
        mode_tls: "Encrypted (TLS)", mode_tunnel: "Tunnel", mode_plain: "Direct (HTTP)",
        appsec_ips: "addresses",
        sys_disk: "Storage", sys_mem: "Memory", sys_load: "Load",
        load_low: "low", load_mid: "normal", load_high: "high",
        confirm_restart: "Really restart service: ",
        confirm_unban: "Unban IP: ", confirm_apply: "Run deploy.sh now?",
        need_pw: "Password (X-LoxProx-Auth)",
        done: "Done", failed: "Failed",
        degraded: "Done, with degraded steps — check the log below",
        theme_auto: "Theme: automatic", theme_light: "Theme: light",
        theme_dark: "Theme: dark", updated: "updated",
    },
};

let lang = localStorage.getItem("lp-lang") || "de";
let authRequired = false;

const $ = (id) => document.getElementById(id);
const t = (k) => (I18N[lang][k] || k);
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const SMALL = matchMedia("(max-width: 720px)").matches;

function esc(s) {
    const d = document.createElement("div");
    d.textContent = String(s);
    return d.innerHTML;
}

function applyLang() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
        el.textContent = t(el.dataset.i18n);
    });
    $("langBtn").textContent = lang === "de" ? "EN" : "DE";
    document.documentElement.lang = lang;
}

$("langBtn").onclick = () => {
    lang = lang === "de" ? "en" : "de";
    localStorage.setItem("lp-lang", lang);
    applyLang();
    refresh();
    loadConfig();
    renderHistory();
};

// ─── theme ───────────────────────────────────────────────────────────────

function currentTheme() {
    return document.documentElement.getAttribute("data-theme") || "auto";
}

function setTheme(mode) {
    if (mode === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", mode);
    try {
        if (mode === "auto") localStorage.removeItem("lp-theme");
        else localStorage.setItem("lp-theme", mode);
    } catch (e) { /* storage disabled */ }
    const bg = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim();
    document.querySelector('meta[name="theme-color"]').setAttribute("content", bg);
    scene.recolor();
}

$("themeBtn").onclick = () => {
    const order = ["auto", "light", "dark"];
    const next = order[(order.indexOf(currentTheme()) + 1) % 3];
    setTheme(next);
    toast(t("theme_" + next));
};

matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => scene.recolor());

// ─── toast ───────────────────────────────────────────────────────────────

let toastTimer = null;

function toast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}

// ─── API helpers ─────────────────────────────────────────────────────────

function hdrs() {
    const h = { "Content-Type": "application/json", "X-LoxProx-Gui": "1" };
    if (authRequired) {
        let pw = sessionStorage.getItem("lp-pw");
        if (!pw) {
            pw = prompt(t("need_pw")) || "";
            sessionStorage.setItem("lp-pw", pw);
        }
        h["X-LoxProx-Auth"] = pw;
    }
    return h;
}

async function post(url, body) {
    const res = await fetch(url, { method: "POST", headers: hdrs(), body: JSON.stringify(body || {}) });
    if (res.status === 401) { sessionStorage.removeItem("lp-pw"); toast("401"); }
    return res.json();
}

// ─── tabs ────────────────────────────────────────────────────────────────

let activeTab = "overview";

function switchTab(name) {
    if (name === activeTab) return;
    activeTab = name;
    document.querySelectorAll(".tab").forEach((b) => {
        const on = b.dataset.tab === name;
        b.classList.toggle("is-active", on);
        b.setAttribute("aria-selected", on);
    });
    document.querySelectorAll(".panel-tab").forEach((s) => {
        s.hidden = s.id !== "tab-" + name;
    });
    const section = $("tab-" + name);
    if (!REDUCED) {
        animate([...section.children], {
            translateY: [16, 0], opacity: [0, 1],
            duration: 500, ease: "outCubic", delay: stagger(60),
        });
    }
    if (name === "overview" || name === "security") replayCharts(name);
    if (name === "logs" && !$("logView").textContent) loadLog();
}

document.querySelectorAll(".tab").forEach((b) => {
    b.onclick = () => switchTab(b.dataset.tab);
});

// ─── animated counters ───────────────────────────────────────────────────

const counterState = {};

function setCounter(id, value, fmt) {
    const el = $(id);
    const target = Number.isFinite(value) ? value : null;
    if (target === null) { el.textContent = "–"; counterState[id] = null; return; }
    const from = counterState[id];
    counterState[id] = target;
    const format = fmt || ((v) => Math.round(v));
    if (REDUCED || from === null || from === undefined || from === target) {
        el.textContent = format(target);
        return;
    }
    const obj = { v: from };
    animate(obj, {
        v: target, duration: 700, ease: "outExpo",
        onUpdate: () => { el.textContent = format(obj.v); },
    });
}

// ─── charts (custom SVG, anime.js draw-in) ───────────────────────────────

const W = 600, H = 150, PAD = 6;
const chartDrawn = {};   // chart id -> already draw-animated
let gradSeq = 0;

function bucketize(values, n, mode) {
    if (values.length <= n) return values.slice();
    const out = [];
    const step = values.length / n;
    for (let i = 0; i < n; i++) {
        const slice = values.slice(Math.floor(i * step), Math.max(Math.floor((i + 1) * step), Math.floor(i * step) + 1));
        if (mode === "sum") out.push(slice.reduce((a, b) => a + b, 0));
        else if (mode === "max") out.push(Math.max(...slice));
        else out.push(slice.reduce((a, b) => a + b, 0) / slice.length);
    }
    return out;
}

function linePath(vals, max) {
    const n = vals.length;
    const sx = (W - 2 * PAD) / Math.max(n - 1, 1);
    let d = "";
    for (let i = 0; i < n; i++) {
        const x = PAD + i * sx;
        const y = H - PAD - (vals[i] / max) * (H - 2 * PAD);
        d += (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }
    return d;
}

function renderChart(svgId, vals, opts) {
    const svg = $(svgId);
    if (!vals.length) {
        svg.innerHTML = `<text x="8" y="24" class="chart-empty" fill="currentColor"
            font-size="12" opacity="0.6">${esc(t("no_data"))}</text>`;
        return;
    }
    const max = Math.max(...vals, opts.minMax || 1);
    const d = linePath(vals, max);
    let line = svg.querySelector(".c-line");
    if (!line) {
        const gid = "grad" + (gradSeq++);
        svg.innerHTML =
            `<defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
               <stop offset="0" style="stop-color:var(--chart-line)" stop-opacity="0.30"/>
               <stop offset="1" style="stop-color:var(--chart-line)" stop-opacity="0"/>
             </linearGradient></defs>
             <path class="c-area" fill="url(#${gid})" stroke="none"/>
             <path class="c-line" fill="none" style="stroke:var(--chart-line)"
                   stroke-width="2" stroke-linejoin="round" stroke-linecap="round"
                   vector-effect="non-scaling-stroke"/>`;
        line = svg.querySelector(".c-line");
    }
    line.setAttribute("d", d);
    svg.querySelector(".c-area").setAttribute(
        "d", d + `L${W - PAD} ${H - PAD}L${PAD} ${H - PAD}Z`);
    if (!chartDrawn[svgId]) {
        chartDrawn[svgId] = true;
        drawIn(svgId);
    }
}

function drawIn(svgId) {
    if (REDUCED) return;
    const svg = $(svgId);
    const line = svg.querySelector(".c-line");
    const area = svg.querySelector(".c-area");
    if (!line) return;
    const len = line.getTotalLength();
    line.style.strokeDasharray = len;
    line.style.strokeDashoffset = len;
    animate(line, {
        strokeDashoffset: [len, 0], duration: 1100, ease: "outQuart",
        onComplete: () => { line.style.strokeDasharray = "none"; },
    });
    if (area) animate(area, { opacity: [0, 1], duration: 900, ease: "outCubic", delay: 250 });
}

const TAB_CHARTS = { overview: ["reqChart", "loadChart"], security: ["bansChart", "appsecChart"] };

function replayCharts(tab) {
    (TAB_CHARTS[tab] || []).forEach((id) => { if (chartDrawn[id]) drawIn(id); });
}

let lastHistory = null;

function renderHistory() {
    if (!lastHistory) return;
    const pts = lastHistory.points;
    const num = (k) => pts.map((p) => (typeof p[k] === "number" ? p[k] : 0));
    const req = bucketize(num("req"), 140, "avg");
    const load = bucketize(num("load"), 140, "avg");
    const bans = bucketize(num("bans"), 140, "max");
    const sec = bucketize(num("sec"), 140, "sum");
    renderChart("reqChart", req, { minMax: 5 });
    renderChart("loadChart", load, { minMax: 1 });
    renderChart("bansChart", bans, { minMax: 4 });
    renderChart("appsecChart", sec, { minMax: 4 });
    const last = pts[pts.length - 1] || {};
    $("reqNow").textContent = (last.req ?? "–") + "/min";
    $("loadNow").textContent = last.load ?? "–";
    $("bansNow").textContent = last.bans ?? "–";
    $("appsecNow").textContent = (last.sec ?? "–") + "/min";
}

async function fetchHistory() {
    const res = await fetch("/api/history").then((r) => r.json()).catch(() => null);
    if (!res || !res.ok) return;
    lastHistory = res;
    renderHistory();
}

// ─── gauges ──────────────────────────────────────────────────────────────

const CIRC = 2 * Math.PI * 36;

function setGauge(circleId, textId, pct) {
    const c = $(circleId);
    if (pct == null) { $(textId).textContent = "–"; return; }
    $(textId).textContent = pct + "%";
    c.classList.toggle("is-bad", pct > 90);
    c.classList.toggle("is-warn", pct > 75 && pct <= 90);
    const off = CIRC * (1 - pct / 100);
    if (REDUCED) c.style.strokeDashoffset = off;
    else animate(c, { strokeDashoffset: off, duration: 900, ease: "outCubic" });
}

// ─── system micro-bars (storage / memory / load) ────────────────────────

const sysBarState = { disk: null, mem: null, load: null };

function setBar(id, pct, key) {
    const el = $(id);
    if (!el) return;
    const target = Math.max(0, Math.min(100, pct));
    const prev = sysBarState[key];
    sysBarState[key] = target;
    if (REDUCED || prev == null || prev === target) {
        el.style.width = target + "%";
        return;
    }
    el.style.width = prev + "%";
    animate(el, { width: target + "%", duration: 700, ease: "outCubic" });
}

function loadPct(load) {
    return load == null ? 0 : Math.max(0, Math.min(100, Math.round((load / 4) * 100)));
}

function loadWord(load) {
    if (load == null) return { txt: "–", cls: "" };
    if (load > 2) return { txt: t("load_high"), cls: "is-warn" };
    if (load >= 1) return { txt: t("load_mid"), cls: "" };
    return { txt: t("load_low"), cls: "" };
}

function pctCls(pct, warnAt) {
    return pct != null && pct > warnAt ? "is-warn" : "";
}

function sysBarRow(label, valueHtml, fillCls, fillId) {
    return `<div class="sysbar"><div class="sysbar-head"><span class="sysbar-label">${label}</span>` +
        `<span class="sysbar-val">${valueHtml}</span></div>` +
        `<div class="sysbar-track"><div class="sysbar-fill ${fillCls}" id="${fillId}"></div></div></div>`;
}

function sysBarsHtml(sy) {
    const disk = sy.disk_pct ?? null;
    const mem = sy.mem_pct ?? null;
    const load = sy.load ?? null;
    const lw = loadWord(load);
    return `<div class="sysbar-list">` +
        sysBarRow(t("sys_disk"), disk == null ? "–" : disk + "%", pctCls(disk, 85), "sysDiskFill") +
        sysBarRow(t("sys_mem"), mem == null ? "–" : mem + "%", pctCls(mem, 90), "sysMemFill") +
        sysBarRow(t("sys_load"),
            `${lw.txt} <span class="mono sysbar-raw">${load == null ? "–" : load}</span>`,
            lw.cls, "sysLoadFill") +
        `</div>`;
}

// ─── status refresh ──────────────────────────────────────────────────────

function tile(label, sub, value, cls, extraCls) {
    return `<div class="card tile ${cls || ""} ${extraCls || ""}"><div class="label">${label}</div>` +
        (sub ? `<div class="tile-sub">${sub}</div>` : "") +
        `<div class="value"><span class="dot"></span>${value}</div></div>`;
}

const SEV = { "": 0, ok: 0, warn: 1, bad: 2 };
let tilesBuilt = false;
let failedFetches = 0;

async function refresh() {
    const res = await fetch("/api/status").then((r) => r.json()).catch(() => null);
    if (!res || !res.ok) {
        if (++failedFetches >= 2) $("liveDot").classList.add("is-stale");
        return;
    }
    failedFetches = 0;
    $("liveDot").classList.remove("is-stale");
    const s = res.status, tiles = [];
    let worst = 0;
    const push = (label, sub, value, cls, extraCls) => {
        worst = Math.max(worst, SEV[cls] || 0);
        tiles.push(tile(label, sub, value, cls, extraCls));
    };

    const badSvc = Object.entries(s.services).filter(([, v]) => v !== "active");
    push(t("svc"), t("svc_sub"), badSvc.length ? esc(badSvc.map(([k, v]) => k + ": " + v).join(", ")) : "OK",
        badSvc.length ? "bad" : "ok");
    if (s.cert_days === null) push(t("cert"), t("cert_sub"), t("no_cert"), s.mode === "tls" ? "warn" : "");
    else push(t("cert"), t("cert_sub"), s.cert_days + " " + t("days"),
        s.cert_days < 7 ? "bad" : (s.cert_days < 21 ? "warn" : "ok"));
    if (s.miniserver !== null) push(t("ms"), t("ms_sub"), s.miniserver ? t("reach") : t("unreach"),
        s.miniserver ? "ok" : "bad");
    push(t("bans"), t("bans_sub"), s.decisions.count, s.decisions.count > 0 ? "warn" : "ok");
    push(t("appsec"), t("appsec_sub"),
        s.appsec.hits + " (" + s.appsec.ips + " " + t("appsec_ips") + ")", s.appsec.hits ? "warn" : "ok");
    push(t("backup"), t("backup_sub"), s.backup ? s.backup.age_hours + " " + t("hours_ago") : "—",
        s.backup && s.backup.age_hours < 26 ? "ok" : "bad");
    const sy = s.system;
    push(t("sys"), t("sys_sub"), sysBarsHtml(sy),
        (sy.disk_pct > 85 || sy.mem_pct > 90) ? "warn" : "ok", "sys-tile");
    push(t("mode"), t("mode_sub"), t("mode_" + s.mode) || s.mode, "");

    $("tiles").innerHTML = tiles.join("");
    setBar("sysDiskFill", sy.disk_pct ?? 0, "disk");
    setBar("sysMemFill", sy.mem_pct ?? 0, "mem");
    setBar("sysLoadFill", loadPct(sy.load ?? null), "load");
    if (!tilesBuilt && !REDUCED) {
        tilesBuilt = true;
        animate([...$("tiles").children], {
            translateY: [14, 0], opacity: [0, 1],
            duration: 500, ease: "outCubic", delay: stagger(40),
        });
    }

    // hero
    const sev = ["ok", "warn", "bad"][worst];
    $("heroTitle").textContent = t("hero_" + sev);
    $("heroTitle").className = "hero-title" + (worst === 1 ? " is-warn" : worst === 2 ? " is-bad" : "");
    $("heroSub").textContent = `${t("mode")}: ${t("mode_" + s.mode) || s.mode} · ${t("updated")} ${s.time.slice(11)}`;
    setCounter("hsBans", s.decisions.count);
    setCounter("hsAppsec", s.appsec.hits);
    setCounter("hsCert", s.cert_days ?? NaN);
    const lastPoint = lastHistory && lastHistory.points[lastHistory.points.length - 1];
    setCounter("hsReq", lastPoint ? lastPoint.req : NaN);
    setGauge("gMem", "gMemPct", sy.mem_pct ?? null);
    setGauge("gDisk", "gDiskPct", sy.disk_pct ?? null);
    scene.setSeverity(sev);

    $("frpcBtn").hidden = s.mode !== "tunnel";
    $("footLine").textContent = `LoxProx Panel v2.2 · ${s.time}`;

    const tb = $("banTable").querySelector("tbody");
    tb.innerHTML = s.decisions.items.map((d) =>
        `<tr><td>${esc(d.ip)}</td><td>${esc(d.origin)}</td><td>${esc(d.scenario)}</td>` +
        `<td>${esc(d.duration)}</td><td><button class="danger" data-unban="${esc(d.ip)}">×</button></td></tr>`
    ).join("") || `<tr><td colspan="5" class="hint">—</td></tr>`;
    tb.querySelectorAll("[data-unban]").forEach((b) => { b.onclick = () => unban(b.dataset.unban); });

    if (s.job && s.job.running) pollJob(s.job.id);
}

// ─── config form ─────────────────────────────────────────────────────────

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

const ENUM_OPTIONS = { appsec_mode: ["monitor", "enforce"], tunnel_proto: ["quic", "tcp"] };

function cfgField(key, value, kind) {
    const wrap = document.createElement("div");
    const label = document.createElement("label");
    label.textContent = key;
    wrap.appendChild(label);
    if (kind === "bool") {
        const sw = document.createElement("label");
        sw.className = "switch";
        sw.innerHTML = `<input type="checkbox" data-key="${key}"><span class="slider"></span>`;
        sw.querySelector("input").checked = String(value).toLowerCase() === "true";
        wrap.appendChild(sw);
    } else if (ENUM_OPTIONS[kind]) {
        const sel = document.createElement("select");
        sel.dataset.key = key;
        sel.innerHTML = ENUM_OPTIONS[kind].map((o) => `<option>${o}</option>`).join("");
        sel.value = ENUM_OPTIONS[kind].includes(value) ? value : ENUM_OPTIONS[kind][0];
        wrap.appendChild(sel);
    } else {
        const inp = document.createElement("input");
        inp.dataset.key = key;
        if (kind === "int" || kind === "port" || kind === "ip") inp.classList.add("mono");
        let v = Array.isArray(value) ? value.join(" ") : String(value);
        // bash-array raw form ("a" "b") → display as plain space-separated list
        if (/^\(.*\)$/.test(v)) v = v.slice(1, -1).replace(/"/g, " ").trim().replace(/\s+/g, " ");
        inp.value = v;
        wrap.appendChild(inp);
    }
    return wrap;
}

async function loadConfig() {
    const res = await fetch("/api/config").then((r) => r.json()).catch(() => null);
    if (!res || !res.ok) return;
    authRequired = res.auth_required;
    $("qrHost").value = res.qr_host || "";
    $("qrModeLine").textContent = "Mode: " + res.qr_mode;
    if (res.qr_host) {
        $("qrHolder").innerHTML =
            `<img src="/qr.svg?host=${encodeURIComponent(res.qr_host)}" alt="QR">`;
    }
    const schema = res.schema || {};
    const form = $("cfgForm");
    form.innerHTML = "";
    const placed = new Set();
    for (const [gkey, keys] of CFG_GROUPS) {
        const present = keys.filter((k) => k in res.config);
        if (!present.length) continue;
        const group = document.createElement("div");
        group.className = "cfg-group";
        group.innerHTML = `<h4>${t(gkey)}</h4>`;
        const fields = document.createElement("div");
        fields.className = "cfg-fields";
        present.forEach((k) => {
            fields.appendChild(cfgField(k, res.config[k], schema[k]));
            placed.add(k);
        });
        group.appendChild(fields);
        form.appendChild(group);
    }
    const rest = Object.keys(res.config).filter((k) => !placed.has(k));
    if (rest.length) {
        const group = document.createElement("div");
        group.className = "cfg-group";
        group.innerHTML = `<h4>${t("grp_other")}</h4>`;
        const fields = document.createElement("div");
        fields.className = "cfg-fields";
        rest.forEach((k) => fields.appendChild(cfgField(k, res.config[k], schema[k])));
        group.appendChild(fields);
        form.appendChild(group);
    }
}

$("cfgSave").onclick = async () => {
    const changes = {};
    $("cfgForm").querySelectorAll("[data-key]").forEach((el) => {
        changes[el.dataset.key] = el.type === "checkbox" ? String(el.checked) : el.value;
    });
    const res = await post("/api/config", { changes });
    if (res.ok) toast(t("done") + " → " + res.hint);
    else toast(JSON.stringify(res.errors || res.error));
};

// ─── actions ─────────────────────────────────────────────────────────────

async function unban(ip) {
    if (!ip || !confirm(t("confirm_unban") + ip)) return;
    const res = await post("/api/unban", { ip });
    toast(res.ok ? t("done") : (res.error || t("failed")));
    refresh();
}

$("unbanBtn").onclick = () => unban($("unbanIp").value.trim());

document.querySelectorAll("[data-restart]").forEach((b) => {
    b.onclick = async () => {
        const svc = b.dataset.restart;
        if (!confirm(t("confirm_restart") + svc)) return;
        const res = await post("/api/restart", { service: svc });
        toast((res.ok ? t("done") : t("failed")) + " — " + svc + " " + (res.state || ""));
        refresh();
    };
});

$("alertBtn").onclick = async () => {
    const r = await post("/api/test-alert");
    toast(r.ok ? t("done") : t("failed"));
};

$("renewBtn").onclick = async () => {
    const r = await post("/api/renew-tls");
    if (r.ok) pollJob(r.job_id); else toast(r.error || t("failed"));
};

$("applyBtn").onclick = async () => {
    if (!confirm(t("confirm_apply"))) return;
    const r = await post("/api/apply");
    if (r.ok) pollJob(r.job_id); else toast(r.error || t("failed"));
};

$("qrSave").onclick = async () => {
    const res = await post("/api/qr-host", { host: $("qrHost").value.trim() });
    toast(res.ok ? t("done") : (res.error || t("failed")));
    loadConfig();
};

$("qrCopy").onclick = () => {
    const h = $("qrHost").value.trim();
    if (h) { navigator.clipboard.writeText("loxone://ms?host=" + h); toast(t("done")); }
};

// ─── job polling ─────────────────────────────────────────────────────────

let jobTimer = null;

function pollJob(id) {
    if (jobTimer) return;
    $("jobLog").hidden = false;
    jobTimer = setInterval(async () => {
        const res = await fetch("/api/job/" + id).then((r) => r.json()).catch(() => null);
        if (!res || !res.ok) { clearInterval(jobTimer); jobTimer = null; return; }
        $("jobLog").textContent = "[" + res.job.name + " · " + res.job.elapsed + "s]\n" + (res.log || "");
        $("jobLog").scrollTop = $("jobLog").scrollHeight;
        if (!res.job.running) {
            clearInterval(jobTimer); jobTimer = null;
            // deploy.sh rc=3: deployed, but one or more OPTIONAL steps degraded
            // (already listed in the log tail above) — a warning, not a failure.
            if (res.job.rc === 0) toast(t("done"));
            else if (res.job.rc === 3) toast(t("degraded"));
            else toast(t("failed") + " (rc=" + res.job.rc + ")");
            refresh();
        }
    }, 2000);
}

// ─── logs ────────────────────────────────────────────────────────────────

const LOGS = ["nginx-error", "nginx-access", "appsec", "watchdog",
    "tunnel-watchdog", "monitor", "deploy", "gui"];
let activeLog = LOGS[0];
let followTimer = null;

$("logChips").innerHTML = LOGS.map((l) =>
    `<button class="chip${l === activeLog ? " is-active" : ""}" data-log="${l}">${l}</button>`).join("");

document.querySelectorAll("[data-log]").forEach((b) => {
    b.onclick = () => {
        activeLog = b.dataset.log;
        document.querySelectorAll("[data-log]").forEach((x) =>
            x.classList.toggle("is-active", x.dataset.log === activeLog));
        loadLog();
    };
});

async function loadLog() {
    const res = await fetch("/api/log/" + activeLog).then((r) => r.json()).catch(() => null);
    $("logView").hidden = false;
    $("logView").textContent = res && res.ok ? res.lines : ((res && res.error) || "?");
    $("logView").scrollTop = $("logView").scrollHeight;
}

$("logFollow").onchange = () => {
    clearInterval(followTimer);
    followTimer = null;
    if ($("logFollow").checked) {
        followTimer = setInterval(() => {
            if (activeTab === "logs" && !document.hidden) loadLog();
        }, 5000);
    }
};

// ─── three.js background scene ───────────────────────────────────────────

const scene = (() => {
    if (REDUCED) return { setSeverity() {}, recolor() {} };
    const canvas = $("bg3d");
    let renderer;
    try {
        renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    } catch (e) {
        canvas.remove();
        return { setSeverity() {}, recolor() {} };
    }
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2));

    const scn = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(55, 1, 0.1, 100);
    camera.position.z = 7;

    const cssColor = (name) =>
        new THREE.Color(getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#69c350");

    const group = new THREE.Group();
    scn.add(group);

    const shellMat = new THREE.LineBasicMaterial({ transparent: true, opacity: 0.34 });
    const shell = new THREE.LineSegments(
        new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(2.4, 1)), shellMat);
    group.add(shell);

    const coreMat = new THREE.LineBasicMaterial({ transparent: true, opacity: 0.14 });
    const core = new THREE.LineSegments(
        new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(1.3, 0)), coreMat);
    group.add(core);

    const N = SMALL ? 260 : 650;
    const pos = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) {
        const r = 2.9 + Math.random() * 1.8;
        const th = Math.random() * Math.PI * 2;
        const ph = Math.acos(2 * Math.random() - 1);
        pos[i * 3] = r * Math.sin(ph) * Math.cos(th);
        pos[i * 3 + 1] = r * Math.sin(ph) * Math.sin(th);
        pos[i * 3 + 2] = r * Math.cos(ph);
    }
    const pGeo = new THREE.BufferGeometry();
    pGeo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    const pMat = new THREE.PointsMaterial({
        size: 0.035, transparent: true, opacity: 0.75,
        blending: THREE.AdditiveBlending, depthWrite: false,
    });
    const particles = new THREE.Points(pGeo, pMat);
    scn.add(particles);

    const target = cssColor("--accent");
    const mats = [shellMat, coreMat, pMat];
    mats.forEach((m) => m.color.copy(target));

    let sevVar = "--ok";
    const api = {
        setSeverity(sev) {
            sevVar = sev === "bad" ? "--bad" : sev === "warn" ? "--warn" : "--accent";
            target.copy(cssColor(sevVar));
        },
        recolor() { target.copy(cssColor(sevVar)); },
    };

    let px = 0, py = 0;
    addEventListener("pointermove", (e) => {
        px = (e.clientX / innerWidth - 0.5) * 0.8;
        py = (e.clientY / innerHeight - 0.5) * 0.5;
    }, { passive: true });

    function resize() {
        const w = innerWidth, h = innerHeight;
        renderer.setSize(w, h, false);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
    }
    addEventListener("resize", resize);
    resize();

    const clock = new THREE.Clock();
    let raf = null;

    function frame() {
        raf = requestAnimationFrame(frame);
        const dt = Math.min(clock.getDelta(), 0.1);
        const tm = clock.elapsedTime;
        group.rotation.y += dt * 0.10;
        group.rotation.x = Math.sin(tm * 0.18) * 0.16;
        particles.rotation.y -= dt * 0.035;
        camera.position.x += (px * 1.6 - camera.position.x) * 0.04;
        camera.position.y += (-py * 1.2 - camera.position.y) * 0.04;
        camera.lookAt(0, 0, 0);
        mats.forEach((m) => m.color.lerp(target, 0.04));
        renderer.render(scn, camera);
    }

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) { cancelAnimationFrame(raf); raf = null; }
        else if (!raf) { clock.getDelta(); frame(); }
    });
    frame();
    return api;
})();

// ─── boot ────────────────────────────────────────────────────────────────

applyLang();
setTheme(currentTheme());

if (!REDUCED) {
    animate(document.querySelectorAll(".hero > *"), {
        translateY: [18, 0], opacity: [0, 1],
        duration: 650, ease: "outCubic", delay: stagger(80),
    });
}

loadConfig();
refresh();
fetchHistory();
setInterval(() => { if (!document.hidden) refresh(); }, 10000);
setInterval(() => { if (!document.hidden) fetchHistory(); }, 60000);
