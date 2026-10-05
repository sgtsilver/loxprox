/* LoxProx Panel — 24-hour charts from /api/history.
   Hand-rolled SVG, one series per chart. Every chart has a text twin: a
   one-sentence summary and an hourly table. Hover and arrow keys move a
   cursor that reads out single values; the table carries the same numbers
   for anyone not using a pointer. DOM is built with safe APIs only. */

const SVG_NS = "http://www.w3.org/2000/svg";
const DAY = 24 * 3600;
const HOUR = 3600;
const LINE_BUCKET = 300;          // 5 minutes per drawn point
const COLLECT_MIN_POINTS = 3;     // fewer samples than this = "collecting data"

function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
}

function svgEl(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    return node;
}

function niceMax(value, floor) {
    const v = Math.max(value, floor);
    if (!(v > 0)) return floor || 1;
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) {
        if (m * mag >= v) return m * mag;
    }
    return 10 * mag;
}

function aggregate(values, agg) {
    if (!values.length) return null;
    if (agg === "sum") return values.reduce((a, b) => a + b, 0);
    if (agg === "max") return Math.max(...values);
    return values.reduce((a, b) => a + b, 0) / values.length;
}

/* Bucket raw points into fixed time slots between start and end. */
function bucketize(points, key, start, size, count, agg) {
    const slots = Array.from({ length: count }, () => []);
    for (const p of points) {
        const v = p[key];
        if (typeof v !== "number" || !Number.isFinite(v)) continue;
        const i = Math.floor((p.t - start) / size);
        if (i >= 0 && i < count) slots[i].push(v);
    }
    return slots.map((vals) => aggregate(vals, agg));
}

export function createChart(fig, spec, ctx) {
    // spec: { kind: "line"|"bars", titleKey, key, agg, decimals, floor }
    // ctx:  { t(key, vars), num(value, decimals), time(epochSec), announce(msg) }
    const head = el("figcaption", "chart-head");
    const titleBox = el("span", "chart-titles");
    const title = el("span", "chart-title");
    const note = el("span", "chart-note");
    titleBox.append(title, note);
    const now = el("span", "chart-now");
    const nowVal = el("strong");
    const nowLabel = el("span");
    now.append(nowVal, nowLabel);
    head.append(titleBox, now);

    const frame = el("div", "chart-frame");
    const yAxis = el("div", "chart-y");
    yAxis.setAttribute("aria-hidden", "true");
    const yLabels = [el("span"), el("span"), el("span")];
    yAxis.append(...yLabels);
    const plot = el("div", "chart-plot");
    plot.tabIndex = 0;
    plot.setAttribute("role", "group");
    const svg = svgEl("svg", { "aria-hidden": "true", focusable: "false" });
    const tip = el("div", "chart-tip");
    tip.setAttribute("aria-hidden", "true");
    tip.hidden = true;
    plot.append(svg, tip);
    const xAxis = el("div", "chart-x");
    xAxis.setAttribute("aria-hidden", "true");
    const xLabels = Array.from({ length: 5 }, () => el("span"));
    xAxis.append(...xLabels);
    const empty = el("div", "chart-empty");
    empty.hidden = true;
    frame.append(yAxis, plot, xAxis, empty);

    const summary = el("p", "chart-summary");
    const details = el("details", "chart-table");
    const sum = el("summary");
    const chev = svgEl("svg", { class: "icon summary-chev", "aria-hidden": "true" });
    chev.append(svgEl("use", { href: "#i-chevron" }));
    const sumText = el("span");
    sum.append(chev, sumText);
    const wrap = el("div", "table-wrap");
    wrap.tabIndex = 0;
    wrap.setAttribute("role", "region");
    const table = el("table", "table");
    const thead = el("thead");
    const tbody = el("tbody");
    table.append(thead, tbody);
    wrap.append(table);
    details.append(sum, wrap);

    fig.replaceChildren(head, frame, summary, details);
    const titleId = fig.id + "-title";
    title.id = titleId;
    wrap.setAttribute("aria-labelledby", titleId);

    let model = null;      // { start, end, size, values[], max }
    let cursor = -1;
    let state = "loading";

    function label(i) {
        if (!model) return "";
        const from = model.start + i * model.size;
        if (spec.kind === "bars") return ctx.time(from) + "–" + ctx.time(from + model.size);
        return ctx.time(from);
    }

    function fmt(v) {
        return v === null || v === undefined ? ctx.t("ch_nodata") : ctx.num(v, spec.decimals);
    }

    function geometry() {
        const w = Math.max(plot.clientWidth, 1);
        const h = Math.max(plot.clientHeight, 1);
        return { w, h, top: 6 };
    }

    function y(v, g) {
        return g.h - (v / model.max) * (g.h - g.top);
    }

    function draw() {
        svg.replaceChildren();
        if (!model) return;
        const g = geometry();
        svg.setAttribute("viewBox", `0 0 ${g.w} ${g.h}`);
        svg.setAttribute("width", g.w);
        svg.setAttribute("height", g.h);

        // recessive grid: top and middle hairlines, solid baseline
        for (const f of [1, 0.5]) {
            const gy = Math.round(y(model.max * f, g)) + 0.5;
            svg.append(svgEl("line", { class: "c-grid", x1: 0, x2: g.w, y1: gy, y2: gy }));
        }
        const by = Math.round(g.h) - 0.5;
        svg.append(svgEl("line", { class: "c-base", x1: 0, x2: g.w, y1: by, y2: by }));

        // y labels at the same heights as the lines
        [model.max, model.max / 2, 0].forEach((v, i) => {
            const dec = Number.isInteger(v) ? 0 : Number.isInteger(v * 10) ? 1 : 2;
            yLabels[i].textContent = ctx.num(v, dec);
            yLabels[i].style.top = y(v, g) + "px";
        });

        const n = model.values.length;
        if (spec.kind === "bars") {
            const slot = g.w / n;
            const bw = Math.min(24, slot * 0.62);
            model.values.forEach((v, i) => {
                if (v === null || v <= 0) return;
                const x = slot * i + (slot - bw) / 2;
                const top = y(v, g);
                const hgt = g.h - top;
                const r = Math.min(4, hgt, bw / 2);
                const d = `M${x} ${g.h}V${top + r}Q${x} ${top} ${x + r} ${top}H${x + bw - r}` +
                    `Q${x + bw} ${top} ${x + bw} ${top + r}V${g.h}Z`;
                svg.append(svgEl("path", { class: "c-bar" + (i === cursor ? " is-hot" : ""), d }));
            });
        } else {
            const xAt = (i) => ((i + 0.5) / n) * g.w;
            let line = "";
            let area = "";
            let seg = [];
            const flush = () => {
                if (!seg.length) return;
                if (seg.length === 1) seg.push([seg[0][0] + 1, seg[0][1]]);
                line += seg.map(([px, py], k) => (k ? "L" : "M") + px.toFixed(1) + " " + py.toFixed(1)).join("");
                area += `M${seg[0][0].toFixed(1)} ${g.h}` +
                    seg.map(([px, py]) => `L${px.toFixed(1)} ${py.toFixed(1)}`).join("") +
                    `L${seg[seg.length - 1][0].toFixed(1)} ${g.h}Z`;
                seg = [];
            };
            model.values.forEach((v, i) => {
                if (v === null) { flush(); return; }
                seg.push([xAt(i), y(v, g)]);
            });
            flush();
            svg.append(svgEl("path", { class: "c-area", d: area }));
            svg.append(svgEl("path", { class: "c-line", d: line }));
            const last = model.lastIndex;
            if (last >= 0) {
                svg.append(svgEl("circle", { class: "c-dot", cx: xAt(last), cy: y(model.values[last], g), r: 4 }));
            }
            if (cursor >= 0) {
                const cx = Math.round(xAt(cursor)) + 0.5;
                svg.append(svgEl("line", { class: "c-cross", x1: cx, x2: cx, y1: 0, y2: g.h }));
                const cv = model.values[cursor];
                if (cv !== null) svg.append(svgEl("circle", { class: "c-dot", cx: xAt(cursor), cy: y(cv, g), r: 4 }));
            }
        }
    }

    function showTip(announce) {
        if (!model || cursor < 0) { tip.hidden = true; return; }
        const g = geometry();
        const n = model.values.length;
        const x = ((cursor + 0.5) / n) * g.w;
        tip.replaceChildren(el("strong", "", fmt(model.values[cursor])), document.createTextNode(label(cursor)));
        tip.hidden = false;
        const half = tip.offsetWidth / 2;
        tip.style.left = Math.min(Math.max(x, half), g.w - half) + "px";
        draw();
        if (announce) {
            ctx.announce(ctx.t("ch_point", { time: label(cursor), value: fmt(model.values[cursor]) }));
        }
    }

    function hideTip() {
        cursor = -1;
        tip.hidden = true;
        draw();
    }

    plot.addEventListener("pointermove", (e) => {
        if (!model) return;
        const rect = plot.getBoundingClientRect();
        const n = model.values.length;
        const i = Math.floor(((e.clientX - rect.left) / rect.width) * n);
        cursor = Math.min(Math.max(i, 0), n - 1);
        showTip(false);
    });
    plot.addEventListener("pointerleave", () => { if (document.activeElement !== plot) hideTip(); });
    plot.addEventListener("focus", () => {
        if (!model) return;
        cursor = model.lastIndex >= 0 ? model.lastIndex : model.values.length - 1;
        showTip(true);
    });
    plot.addEventListener("blur", hideTip);
    plot.addEventListener("keydown", (e) => {
        if (!model) return;
        const n = model.values.length;
        const page = spec.kind === "bars" ? 6 : 12;
        const moves = { ArrowLeft: -1, ArrowRight: 1, PageUp: -page, PageDown: page };
        if (e.key in moves) cursor = Math.min(Math.max(cursor + moves[e.key], 0), n - 1);
        else if (e.key === "Home") cursor = 0;
        else if (e.key === "End") cursor = n - 1;
        else return;
        e.preventDefault();
        showTip(true);
    });

    if (typeof ResizeObserver === "function") {
        new ResizeObserver(() => { if (state === "ready") { draw(); if (cursor >= 0) showTip(false); } }).observe(plot);
    }

    function setEmpty(msg, isError) {
        empty.textContent = msg;
        empty.hidden = false;
        empty.dataset.state = isError ? "error" : "info";
        plot.hidden = true;
        yAxis.hidden = true;
        xAxis.hidden = true;
        details.hidden = true;
        summary.textContent = "";
        nowVal.textContent = "";
        nowLabel.textContent = "";
    }

    function buildTable(points, end) {
        const hourEnd = Math.floor(end / HOUR) * HOUR;
        const start = hourEnd - 23 * HOUR;
        const rows = [];
        for (let i = 23; i >= 0; i--) {
            const from = start + i * HOUR;
            const vals = points.filter((p) => p.t >= from && p.t < from + HOUR && Number.isFinite(p[spec.key]))
                .map((p) => p[spec.key]);
            rows.push({ from, vals });
        }
        const hr = el("tr");
        const cols = spec.kind === "bars" ? ["ch_th_hour", "ch_th_sum"] : ["ch_th_hour", "ch_th_avg", "ch_th_max"];
        cols.forEach((k, i) => {
            const th = el("th", i ? "num" : "", ctx.t(k));
            th.scope = "col";
            hr.append(th);
        });
        thead.replaceChildren(hr);
        tbody.replaceChildren(...rows.map(({ from, vals }) => {
            const tr = el("tr");
            const th = el("th", "", ctx.time(from));
            th.scope = "row";
            tr.append(th);
            if (spec.kind === "bars") {
                tr.append(el("td", "num", vals.length ? ctx.num(aggregate(vals, "sum"), 0) : ctx.t("ch_nodata")));
            } else {
                tr.append(el("td", "num", vals.length ? ctx.num(aggregate(vals, "avg"), spec.decimals) : ctx.t("ch_nodata")));
                tr.append(el("td", "num", vals.length ? ctx.num(Math.max(...vals), spec.decimals) : ctx.t("ch_nodata")));
            }
            return tr;
        }));
    }

    return {
        /* history: { points, interval } | null; error: message or null */
        render(history, error) {
            const ttl = ctx.t(spec.titleKey);
            title.textContent = ttl;
            note.textContent = spec.noteKey ? ctx.t(spec.noteKey) : "";
            note.hidden = !spec.noteKey;
            plot.setAttribute("aria-label", ctx.t("ch_plot_label", { title: ttl }));
            sumText.textContent = ctx.t("ch_table");

            if (!history) {
                state = error ? "error" : "loading";
                model = null;
                setEmpty(error ? ctx.t("ch_failed", { err: error }) : ctx.t("ch_loading"), Boolean(error));
                return;
            }
            const nowSec = Date.now() / 1000;
            const points = history.points.filter((p) => p && typeof p.t === "number");
            const lastT = points.length ? points[points.length - 1].t : nowSec;
            const end = Math.max(nowSec, lastT);
            const inWindow = points.filter((p) => p.t > end - DAY);
            const usable = inWindow.filter((p) => Number.isFinite(p[spec.key]));
            if (usable.length < COLLECT_MIN_POINTS) {
                state = "collecting";
                model = null;
                setEmpty(ctx.t("ch_collecting"), false);
                return;
            }

            let start, size, count;
            if (spec.kind === "bars") {
                size = HOUR;
                count = 24;
                start = Math.floor(end / HOUR) * HOUR - 23 * HOUR;
            } else {
                size = LINE_BUCKET;
                count = DAY / LINE_BUCKET;
                start = end - DAY;
            }
            const values = bucketize(inWindow, spec.key, start, size, count, spec.agg);
            let lastIndex = -1;
            values.forEach((v, i) => { if (v !== null) lastIndex = i; });
            const peak = Math.max(0, ...values.filter((v) => v !== null));
            model = { start, size, values, lastIndex, max: niceMax(peak, spec.floor) };
            state = "ready";

            empty.hidden = true;
            plot.hidden = false;
            yAxis.hidden = false;
            xAxis.hidden = false;
            details.hidden = false;

            // x labels: clock times across the window, last one is "now"
            const span = spec.kind === "bars" ? count * size : DAY;
            xLabels.forEach((node, i) => {
                node.textContent = i === 4 ? ctx.t("ch_now") : ctx.time(start + (span * i) / 4);
            });

            const raw = usable.map((p) => p[spec.key]);
            if (spec.kind === "bars") {
                const total = raw.reduce((a, b) => a + b, 0);
                nowVal.textContent = ctx.num(total, 0);
                nowLabel.textContent = ctx.t("ch_total");
                let best = -1;
                values.forEach((v, i) => { if (v !== null && (best < 0 || v > values[best])) best = i; });
                summary.textContent = total > 0
                    ? ctx.t("ch_summary_bars", { sum: ctx.num(total, 0), max: ctx.num(values[best], 0), time: ctx.time(start + best * size) })
                    : ctx.t("ch_summary_zero");
            } else {
                const latest = usable[usable.length - 1];
                let peakPoint = usable[0];
                for (const p of usable) if (p[spec.key] > peakPoint[spec.key]) peakPoint = p;
                nowVal.textContent = ctx.num(latest[spec.key], spec.decimals);
                nowLabel.textContent = ctx.t("ch_latest");
                summary.textContent = ctx.t("ch_summary", {
                    avg: ctx.num(aggregate(raw, "avg"), spec.decimals),
                    max: ctx.num(peakPoint[spec.key], spec.decimals),
                    time: ctx.time(peakPoint.t),
                    now: ctx.num(latest[spec.key], spec.decimals),
                });
            }
            buildTable(inWindow, end);
            draw();
            if (cursor >= 0) showTip(false);
        },
    };
}
