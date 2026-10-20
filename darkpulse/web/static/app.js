/* DarkPulse v2 — dashboard frontend.
   No framework, no CDN: ECharts + fonts are served locally by FastAPI. */
(() => {
  "use strict";

  // ------------------------------------------------------------------
  // Constants & tiny helpers
  // ------------------------------------------------------------------
  const TYPES = {
    vulnerability: { label: "Vulnerability", color: "#ff5d7a" },
    malware: { label: "Malware", color: "#f6b441" },
    threat_actor: { label: "Threat actor", color: "#a78bfa" },
    organization: { label: "Organization", color: "#5aa9ff" },
    technology: { label: "Technology", color: "#38e1d0" },
    incident: { label: "Incident", color: "#f472b6" },
    indicator: { label: "Indicator", color: "#94a3b8" },
    source: { label: "Record", color: "#5d7089" },
  };
  const PALETTE = ["#38e1d0", "#5aa9ff", "#a78bfa", "#f6b441", "#ff5d7a", "#46d68b"];
  const TYPE_ORDER = Object.keys(TYPES);
  const VIEWS = {
    overview: { title: "Overview", eyebrow: "Command center" },
    alerts: { title: "Priority alerts", eyebrow: "Risk engine" },
    graph: { title: "Relationship graph", eyebrow: "Knowledge graph" },
    trends: { title: "Threat trends", eyebrow: "Temporal analysis" },
    records: { title: "Source inspector", eyebrow: "Provenance" },
  };

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const esc = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));
  const truncate = (text, size) => (String(text ?? "").length > size ? `${String(text).slice(0, size - 1)}…` : String(text ?? ""));
  const debounce = (fn, wait) => {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), wait);
    };
  };

  /* Re-rendering a view replaces its inputs; restore focus + caret afterwards. */
  async function withFocus(inputId, render) {
    const active = document.activeElement;
    const caret = active && active.id === inputId ? active.selectionStart : null;
    await render();
    const input = document.getElementById(inputId);
    if (!input) return;
    input.focus();
    if (caret != null && typeof input.setSelectionRange === "function") {
      try {
        input.setSelectionRange(caret, caret);
      } catch {
        /* not a text input */
      }
    }
  }

  const fmt = {
    int: (n) => Number(n ?? 0).toLocaleString(),
    score: (n) => Number(n ?? 0).toFixed(3),
    pct: (n) => `${Math.round(Number(n ?? 0) * 100)}%`,
    date: (iso) => {
      if (!iso) return "—";
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return "—";
      return d.toLocaleDateString(undefined, { month: "short", day: "2-digit" });
    },
    dateTime: (iso) => {
      if (!iso) return "—";
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return "—";
      return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
    },
    rel: (iso) => {
      if (!iso) return "—";
      const then = new Date(iso).getTime();
      if (Number.isNaN(then)) return "—";
      const diff = (then - Date.now()) / 1000;
      const abs = Math.abs(diff);
      const units = [
        ["year", 31536000],
        ["month", 2592000],
        ["week", 604800],
        ["day", 86400],
        ["hour", 3600],
        ["minute", 60],
      ];
      const fmtRel = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
      for (const [unit, secs] of units) {
        if (abs >= secs) return fmtRel.format(Math.round(diff / secs), unit);
      }
      return "just now";
    },
  };

  const typePill = (type) => `<span class="type-pill type-${esc(type)}">${esc(TYPES[type]?.label || type)}</span>`;
  const scoreClass = (score) => (score >= 0.55 ? "is-hot" : score >= 0.35 ? "is-warm" : "");

  // ------------------------------------------------------------------
  // API client
  // ------------------------------------------------------------------
  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  }

  async function request(path, options = {}, attempt = 0) {
    let response;
    try {
      response = await fetch(path, { headers: { Accept: "application/json" }, ...options });
    } catch (error) {
      if (attempt < 1) {
        await sleep(350);
        return request(path, options, attempt + 1);
      }
      throw new ApiError("The DarkPulse server is not responding.", 0);
    }
    if (!response.ok) {
      let detail = "";
      try {
        const body = await response.json();
        detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      } catch {
        detail = response.statusText;
      }
      const error = new ApiError(detail || `Request failed (${response.status})`, response.status);
      const retryable = response.status >= 500 || response.status === 0;
      if (retryable && attempt < 1) {
        await sleep(450);
        return request(path, options, attempt + 1);
      }
      throw error;
    }
    return response.json();
  }

  const api = {
    status: () => request("/api/status"),
    meta: () => request("/api/meta"),
    overview: () => request("/api/overview"),
    alerts: (params) => request(`/api/alerts?${new URLSearchParams(params)}`),
    alert: (key) => request(`/api/alerts/${encodeURIComponent(key)}`),
    graph: (params) => request(`/api/graph?${new URLSearchParams(params)}`),
    neighbors: (node, limit = 70) => request(`/api/graph/neighbors?${new URLSearchParams({ node, limit })}`),
    graphSearch: (q, limit = 10) => request(`/api/graph/search?${new URLSearchParams({ q, limit })}`),
    trends: (days) => request(`/api/trends?${new URLSearchParams({ days })}`),
    records: (params) => request(`/api/records?${new URLSearchParams(params)}`),
    record: (id) => request(`/api/records/${encodeURIComponent(id)}`),
    refresh: (offline = null) =>
      request("/api/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ offline }),
      }),
  };

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------
  const state = {
    status: null,
    meta: null,
    loaded: false,
    view: "overview",
    overview: null,
    alerts: { items: [], types: {}, total: 0, query: "", typesFilter: new Set(), sort: "score" },
    graph: {
      payload: null,
      focus: "",
      depth: 2,
      limit: 320,
      typeFilter: new Set(TYPE_ORDER.filter((t) => t !== "source")),
      includeRecords: false,
      selected: null,
      loading: false,
      appliedFocus: null,
    },
    trends: { days: 60, data: null },
    records: { data: null, source: "", query: "", cve: "", offset: 0, limit: 40 },
    charts: new Map(),
    bootTimer: null,
    drawerToken: 0,
    drawerTimer: null,
  };

  let graphRequest = 0;

  // ------------------------------------------------------------------
  // Charts
  // ------------------------------------------------------------------
  function disposeChart(id) {
    const chart = state.charts.get(id);
    if (!chart) return;
    chart.dispose();
    state.charts.delete(id);
  }

  function disposeChartsIn(container) {
    if (!container) return;
    for (const [id, chart] of Array.from(state.charts.entries())) {
      if (container.contains(chart.getDom())) {
        chart.dispose();
        state.charts.delete(id);
      }
    }
  }

  function makeChart(id, option) {
    const el = document.getElementById(id);
    if (!el) return null;
    let chart = state.charts.get(id);
    if (chart && chart.getDom() !== el) {
      chart.dispose();
      chart = null;
      state.charts.delete(id);
    }
    if (!chart) {
      chart = echarts.init(el, null, { renderer: "canvas" });
      state.charts.set(id, chart);
    }
    chart.setOption(option, true);
    return chart;
  }

  const CHART_TEXT = { fontFamily: "Inter, sans-serif", fontSize: 10, color: "#8ea1ba" };
  const MONO = "JetBrains Mono, monospace";

  function chartTooltip(extra = {}) {
    return {
      backgroundColor: "rgba(9, 14, 22, 0.96)",
      borderColor: "#1d2838",
      borderWidth: 1,
      padding: [8, 10],
      textStyle: { color: "#e7eef9", fontFamily: "Inter, sans-serif", fontSize: 11 },
      extraCssText: "border-radius:10px;box-shadow:0 14px 40px rgba(0,0,0,.55);",
      ...extra,
    };
  }

  function axisCategory(dates, { show = true } = {}) {
    return {
      type: "category",
      data: dates,
      boundaryGap: false,
      axisLine: { lineStyle: { color: "#1d2838" } },
      axisTick: { show: false },
      axisLabel: {
        show,
        color: "#5d7089",
        fontSize: 9,
        fontFamily: MONO,
        hideOverlap: true,
        formatter: (value) => String(value).slice(5),
      },
    };
  }

  function axisValue({ split = true } = {}) {
    return {
      type: "value",
      splitLine: { show: split, lineStyle: { color: "#141e2b" } },
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: "#5d7089", fontSize: 9, fontFamily: MONO },
    };
  }

  function areaSeries(name, values, color, { stack = null } = {}) {
    return {
      name,
      type: "line",
      data: values,
      stack: stack || undefined,
      smooth: 0.35,
      showSymbol: false,
      symbol: "circle",
      symbolSize: 5,
      lineStyle: { width: 1.7, color },
      itemStyle: { color },
      emphasis: { focus: "series" },
      areaStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: hexAlpha(color, 0.26) },
          { offset: 1, color: hexAlpha(color, 0.01) },
        ]),
      },
    };
  }

  function hexAlpha(hex, alpha) {
    const value = hex.replace("#", "");
    const bigint = parseInt(value.length === 3 ? value.split("").map((c) => c + c).join("") : value, 16);
    const r = (bigint >> 16) & 255;
    const g = (bigint >> 8) & 255;
    const b = bigint & 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  // ------------------------------------------------------------------
  // Toasts / banners / boot
  // ------------------------------------------------------------------
  function toast(message, kind = "info") {
    const host = $("#toasts");
    const node = document.createElement("div");
    node.className = `toast${kind === "error" ? " is-error" : ""}`;
    node.innerHTML = `<span class="dot"></span><span>${esc(message)}</span>`;
    host.appendChild(node);
    setTimeout(() => {
      node.style.opacity = "0";
      node.style.transform = "translateY(6px)";
      node.style.transition = "opacity .2s, transform .2s";
      setTimeout(() => node.remove(), 220);
    }, kind === "error" ? 7000 : 3800);
  }

  function renderBanner() {
    const host = $("#banner");
    const status = state.status || {};
    const messages = [];
    if (status.error) {
      messages.push(`<div class="banner is-error">${icon("alert")}<span><strong>Last run failed:</strong> ${esc(status.error)}</span></div>`);
    }
    if ((status.warnings || []).length) {
      const list = status.warnings.map((warning) => esc(warning)).join(" · ");
      messages.push(`<div class="banner">${icon("alert")}<span><strong>Partial run:</strong> ${list}</span></div>`);
    }
    host.innerHTML = messages.join("");
  }

  function icon(name) {
    const icons = {
      alert: '<svg viewBox="0 0 24 24" fill="none"><path d="M12 3l9 16H3L12 3z" stroke="currentColor" stroke-width="1.6"/><path d="M12 9v4.5M12 17h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
      empty: '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.4"/><path d="M8.5 12h7" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>',
      close: '<svg viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
      external: '<svg viewBox="0 0 24 24" fill="none"><path d="M14 4h6v6M20 4l-9 9" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
      refresh: '<svg viewBox="0 0 24 24" fill="none"><path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v4h-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
      arrow: '<svg viewBox="0 0 24 24" fill="none"><path d="M5 12h13M13 6l6 6-6 6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    };
    return icons[name] || "";
  }

  const bootEl = () => $("#boot");
  const bootFill = () => $("#boot-bar-fill");

  function showBoot(message) {
    const el = bootEl();
    el.classList.remove("is-done");
    el.hidden = false;
    $("#boot-error").hidden = true;
    if (message) $("#boot-sub").textContent = message;
    bootFill().style.width = "18%";
  }

  function bootProgress(message, pct) {
    showBoot(message);
    bootFill().style.width = `${clamp(pct, 8, 92)}%`;
  }

  function hideBoot() {
    bootEl().classList.add("is-done");
    setTimeout(() => {
      if (bootEl().classList.contains("is-done")) bootEl().hidden = true;
    }, 400);
  }

  function showBootError(message) {
    const el = bootEl();
    el.classList.remove("is-done");
    el.hidden = false;
    $("#boot-sub").textContent = "The pipeline could not produce a dataset.";
    $("#boot-hint").hidden = true;
    $("#boot-error").hidden = false;
    $("#boot-error-text").textContent = message || "Unknown error.";
    bootFill().style.width = "100%";
    bootFill().style.background = "linear-gradient(90deg,#8c2437,#ff5d7a)";
  }

  function emptyState(title, subtitle) {
    return `<div class="empty">${icon("empty")}<strong>${esc(title)}</strong><span>${esc(subtitle)}</span></div>`;
  }

  function errorState(message, actionLabel = "Retry") {
    return `<div class="error-state"><span class="msg">${esc(message)}</span><button class="btn btn-ghost" data-retry>${icon("refresh")}${esc(actionLabel)}</button></div>`;
  }

  // ------------------------------------------------------------------
  // Status, chrome, polling
  // ------------------------------------------------------------------
  function syncChrome(status) {
    if (!status) return;
    const hasData = Boolean(status.has_data);
    $("#nav-alerts-count").textContent = hasData ? fmt.int(status.alerts) : "—";
    $("#nav-spikes-count").textContent = hasData ? fmt.int(status.spikes) : "—";
    const modeLabel = $("#mode-label");
    const modeDot = $("#mode-dot");
    const runState = $("#run-state");
    const runLabel = $("#run-state-label");
    runState.classList.remove("is-busy", "is-error");

    if (status.state === "running") {
      modeLabel.textContent = status.offline ? "Offline run in progress" : "Live collection in progress";
      modeDot.className = "mode-dot is-busy";
      runState.classList.add("is-busy");
      runLabel.textContent = "Running";
      modeLabel.title = status.message || "";
    } else {
      modeLabel.textContent = status.offline ? "Offline fixtures" : "Live sources";
      modeDot.className = `mode-dot${status.offline ? "" : " is-live"}`;
      if (status.error) {
        runState.classList.add("is-error");
        runLabel.textContent = "Degraded";
      } else {
        runLabel.textContent = "Ready";
      }
    }

    const parts = [];
    if (hasData) {
      parts.push(`${fmt.int(status.records)} records`);
      parts.push(`${fmt.int(status.alerts)} scored`);
    }
    if (status.duration_ms != null) parts.push(`${(status.duration_ms / 1000).toFixed(1)}s run`);
    $("#sidebar-meta").textContent = parts.join(" · ") || "No dataset yet";
    $("#version-label").textContent = `v${status.version || "2"}`;
    $("#refresh-btn").disabled = status.state === "running";
    $("#refresh-icon") && ($("#refresh-icon").disabled = status.state === "running");
    renderBanner();
  }

  async function handleStatus(status) {
    const previous = state.status;
    state.status = status;
    syncChrome(status);

    if (status.state === "running") {
      if (!status.has_data) bootProgress(status.message || "Pipeline running…", 55);
      pollStatus(1300);
      return;
    }
    if (!status.has_data) {
      if (status.state === "error") showBootError(status.error);
      else pollStatus(1600);
      return;
    }
    const changed = !state.loaded || (previous && previous.generated_at !== status.generated_at);
    if (changed) {
      if (!state.loaded) {
        await enterApp();
      } else {
        invalidate();
        await loadMeta();
        await renderCurrentView();
        toast("Dataset refreshed.", "info");
      }
    }
    if (status.state === "error") {
      toast(status.error || "Pipeline run failed; showing the previous dataset.", "error");
    }
  }

  async function pollStatus(delay = 1300) {
    clearTimeout(state.bootTimer);
    state.bootTimer = setTimeout(async () => {
      try {
        await handleStatus(await api.status());
      } catch (error) {
        if (!state.loaded) showBootError(error.message);
        else toast(error.message, "error");
      }
    }, delay);
  }

  function invalidate() {
    state.overview = null;
    state.alerts.items = [];
    state.alerts.types = {};
    state.graph.payload = null;
    state.graph.selected = null;
    state.graph.appliedFocus = null;
    state.trends.data = null;
    state.records.data = null;
    state.records.offset = 0;
    for (const id of Array.from(state.charts.keys())) disposeChart(id);
  }

  async function loadMeta() {
    state.meta = await api.meta();
    if (!state.alerts.typesFilter.size) {
      state.alerts.typesFilter = new Set(Object.keys(state.meta.types || {}));
    }
    state.graph.typeFilter = new Set(
      Object.keys(state.meta.types || {}).filter((type) => type !== "source")
    );
  }

  async function enterApp() {
    bootProgress("Indexing entities and risk scores…", 78);
    $("#shell").classList.remove("hidden");
    $("#shell").hidden = false;
    await loadMeta();
    hideBoot();
    state.loaded = true;
    await route();
  }

  async function refreshRun() {
    const buttons = [$("#refresh-btn"), $("#refresh-icon")].filter(Boolean);
    buttons.forEach((button) => (button.disabled = true));
    try {
      const response = await api.refresh(null);
      state.status = response.status;
      syncChrome(response.status);
      if (!response.started) {
        toast("A pipeline run is already in progress.", "info");
      } else {
        toast("Pipeline started. This view updates when it finishes.", "info");
      }
      pollStatus(900);
    } catch (error) {
      toast(error.message, "error");
      buttons.forEach((button) => (button.disabled = false));
    }
  }

  // ------------------------------------------------------------------
  // Router
  // ------------------------------------------------------------------
  function currentViewFromHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    return VIEWS[raw] ? raw : "overview";
  }

  async function route() {
    const view = currentViewFromHash();
    state.view = view;
    for (const name of Object.keys(VIEWS)) {
      const section = document.getElementById(`view-${name}`);
      if (section) section.hidden = name !== view;
    }
    $$("#nav .nav-item").forEach((item) => {
      item.classList.toggle("is-active", item.dataset.view === view);
    });
    $("#page-title").textContent = VIEWS[view].title;
    $("#page-eyebrow").textContent = VIEWS[view].eyebrow;
    document.title = `DarkPulse — ${VIEWS[view].title}`;
    window.scrollTo(0, 0);
    await renderCurrentView();
  }

  async function renderCurrentView() {
    if (!state.loaded) return;
    const view = state.view;
    try {
      if (view === "overview") await renderOverview();
      else if (view === "alerts") await renderAlerts();
      else if (view === "graph") await renderGraphView();
      else if (view === "trends") await renderTrends();
      else if (view === "records") await renderRecords();
    } catch (error) {
      const section = document.getElementById(`view-${view}`);
      section.innerHTML = errorState(error.message);
      section.querySelector("[data-retry]").addEventListener("click", () => renderCurrentView());
    }
  }

  // ------------------------------------------------------------------
  // Overview
  // ------------------------------------------------------------------
  async function renderOverview() {
    if (!state.overview) state.overview = await api.overview();
    const data = state.overview;
    const section = $("#view-overview");
    disposeChartsIn(section);

    const topAlerts = data.top_alerts || [];
    const activity = data.activity || { dates: [], values: [] };
    const sourceEntries = Object.entries(data.sources || {});
    const typeEntries = Object.entries(data.type_counts || {});

    section.innerHTML = `
      <div class="view-head">
        <div>
          <h2>Threat landscape</h2>
          <p>One run, fully correlated. ${fmt.int(data.records)} observations across ${fmt.int(data.source_total)} sources, distilled into ${fmt.int(data.alerts)} scored entities.</p>
        </div>
        <div class="view-actions">
          <span class="chip chip-static"><span class="dot" style="background:${data.offline ? "#f6b441" : "#46d68b"}"></span>${data.offline ? "Offline fixtures" : "Live collection"}</span>
          <span class="chip chip-static mono">${esc(fmt.dateTime(data.generated_at))}</span>
        </div>
      </div>

      <div class="kpis">
        ${kpi("Observations", fmt.int(data.records), `${fmt.int(data.edges)} graph edges`, "")}
        ${kpi("Entities", fmt.int(data.entities), `${fmt.int(data.nodes)} nodes indexed`, "blue")}
        ${kpi("Correlated events", fmt.int(data.events), "cross-source clusters", "violet")}
        ${kpi("Priority alerts", fmt.int(data.alerts), `avg top-5 ${fmt.score(data.avg_top_score)}`, "red")}
        ${kpi("Detected spikes", fmt.int(data.spikes), "z-score anomalies", "amber")}
        ${kpi("Source coverage", fmt.int(data.source_total), sourceEntries.map(([key]) => key).join(" · ") || "none", "")}
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="card-head">
            <div><h3>Top prioritized entities</h3><div class="card-sub">Multi-factor score, highest exposure first</div></div>
            <a class="btn btn-ghost" href="#/alerts">All alerts ${icon("arrow")}</a>
          </div>
          <div class="alert-list">
            ${topAlerts.length ? topAlerts.map((alert) => alertRow(alert, { compact: false })).join("") : emptyState("No alerts", "Run the pipeline with data to score entities.")}
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <div><h3>Coverage by source</h3><div class="card-sub">Normalized observations per connector</div></div>
          </div>
          <div class="card-body">
            ${sourceEntries.length ? `<div class="chart chart-sm" id="ch-source"></div>
            <div class="graph-legend" style="margin-top:10px">
              ${sourceEntries.map(([name, count], index) => `<span class="legend-item"><span class="legend-dot" style="background:${PALETTE[index % PALETTE.length]}"></span>${esc(name)} <span class="mono dim">${fmt.int(count)}</span></span>`).join("")}
            </div>` : emptyState("No sources", "Ingestion returned no observations.")}
          </div>
        </div>
      </div>

      <div class="grid grid-2-even">
        <div class="card">
          <div class="card-head">
            <div><h3>Activity, last 14 days</h3><div class="card-sub">Daily observations across all sources</div></div>
            <span class="card-tag mono">${fmt.int(activity.values.reduce((a, b) => a + b, 0))} obs</span>
          </div>
          <div class="card-body">${activity.dates.length ? '<div class="chart chart-sm" id="ch-activity"></div>' : emptyState("No timeline", "Records have no usable timestamps.")}</div>
        </div>

        <div class="card">
          <div class="card-head">
            <div><h3>Pipeline health</h3><div class="card-sub">Phases are isolated; one failure never kills the run</div></div>
            <span class="card-tag mono">${data.errors?.length ? `${data.errors.length} warning(s)` : "clean"}</span>
          </div>
          <div class="card-body">
            <div class="stat-line"><span class="k">Raw records stored</span><span class="v">${fmt.int(data.result?.raw_stored ?? data.records)}</span></div>
            <div class="stat-line"><span class="k">Normalized records</span><span class="v">${fmt.int(data.result?.normalized_stored ?? data.records)}</span></div>
            <div class="stat-line"><span class="k">Extractions</span><span class="v">${fmt.int(data.result?.extractions ?? 0)}</span></div>
            <div class="stat-line"><span class="k">Graph</span><span class="v">${fmt.int(data.nodes)} nodes / ${fmt.int(data.edges)} edges</span></div>
            <div class="stat-line"><span class="k">Data range</span><span class="v">${esc(fmt.date(data.range?.min))} → ${esc(fmt.date(data.range?.max))}</span></div>
            <div class="stat-line"><span class="k">Entity mix</span><span class="v">${esc(typeEntries.slice(0, 3).map(([type, count]) => `${type} ${count}`).join(" · ") || "—")}</span></div>
            ${data.errors?.length ? `<div style="margin-top:10px">${errorState(data.errors.join(" · "), "Re-run")}</div>` : ""}
          </div>
        </div>
      </div>
    `;

    section.querySelectorAll("[data-alert]").forEach((row) => {
      row.addEventListener("click", () => openAlert(row.dataset.alert));
    });
    const rerun = section.querySelector("[data-retry]");
    if (rerun) rerun.addEventListener("click", refreshRun);

    $("#nav-spikes-count").textContent = fmt.int(data.spikes);

    if (sourceEntries.length) {
      makeChart("ch-source", {
        tooltip: chartTooltip({ trigger: "item", formatter: (p) => `${esc(p.name)}: <b>${fmt.int(p.value)}</b>` }),
        series: [
          {
            type: "pie",
            radius: ["62%", "86%"],
            center: ["50%", "50%"],
            avoidLabelOverlap: true,
            itemStyle: { borderColor: "#0b111b", borderWidth: 3, borderRadius: 5 },
            label: { show: false },
            labelLine: { show: false },
            emphasis: { scale: true, scaleSize: 4 },
            data: sourceEntries.map(([name, value], index) => ({
              name,
              value,
              itemStyle: { color: PALETTE[index % PALETTE.length] },
            })),
          },
        ],
      });
    }

    if (activity.dates.length) {
      makeChart("ch-activity", {
        grid: { left: 34, right: 12, top: 14, bottom: 24 },
        tooltip: chartTooltip({ trigger: "axis", axisPointer: { type: "line", lineStyle: { color: "#2a3b52" } } }),
        xAxis: axisCategory(activity.dates),
        yAxis: axisValue(),
        series: [areaSeries("Observations", activity.values, "#38e1d0")],
      });
    }
  }

  function kpi(label, value, sub, tone) {
    return `<div class="kpi"${tone ? ` data-tone="${tone}"` : ""}>
      <div class="kpi-label">${esc(label)}</div>
      <div class="kpi-value">${esc(value)}</div>
      <div class="kpi-sub">${esc(sub)}</div>
    </div>`;
  }

  // ------------------------------------------------------------------
  // Alerts
  // ------------------------------------------------------------------
  function alertRow(alert, { compact = true } = {}) {
    const reasons = alert.reasons || [];
    const cves = alert.related_cves || [];
    const badges = [];
    if (cves.length) badges.push(`<span class="badge badge-cvss">${cves.length} CVE${cves.length > 1 ? "s" : ""}</span>`);
    if (reasons.some((reason) => /KEV/i.test(reason))) badges.push('<span class="badge badge-kev">KEV</span>');
    if (alert.cvss != null) badges.push(`<span class="badge badge-cvss">CVSS ${Number(alert.cvss).toFixed(1)}</span>`);
    if (!badges.length) badges.push('<span class="badge badge-neu">signal</span>');

    return `<div class="alert-row" data-alert="${esc(alert.node_id)}" role="button" tabindex="0">
      <div class="alert-rank">${String(alert.rank).padStart(2, "0")}</div>
      <div class="alert-main">
        <div class="alert-name">${esc(alert.entity)}</div>
        <div class="alert-meta">
          ${typePill(alert.type)}
          ${compact ? `<span>${reasons[0] ? esc(truncate(reasons[0], 54)) : "no reasons recorded"}</span>` : `<span>${fmt.int(alert.mentions)} mentions · ${fmt.int(alert.degree)} links · ${esc(fmt.rel(alert.last_seen))}</span>`}
        </div>
      </div>
      <div class="alert-badges">${badges.join("")}</div>
      <div class="score-wrap">
        <span class="score-value">${fmt.score(alert.score)}</span>
        <span class="score-track"><span class="score-fill ${scoreClass(alert.score)}" style="width:${clamp(alert.score * 100, 3, 100)}%"></span></span>
      </div>
    </div>`;
  }

  async function renderAlerts() {
    const section = $("#view-alerts");
    const filters = state.alerts;
    if (!filters.items.length) {
      // One bounded payload, then every filter is instant and client-side.
      const response = await api.alerts({ limit: 500 });
      filters.items = response.items;
      filters.types = response.types;
      filters.total = response.total;
    }
    const typeEntries = Object.entries(filters.types);
    const items = sortedAlerts();

    section.innerHTML = `
      <div class="view-head">
        <div>
          <h2>Prioritized emerging threats</h2>
          <p>Weighted blend of activity growth, relationship density, CVSS severity, recency and monitored-asset relevance. Select a row for the full breakdown and its evidence trail.</p>
        </div>
        <div class="view-actions">
          <span class="chip chip-static mono">${fmt.int(filters.items.length)} of ${fmt.int(filters.total)} scored</span>
          <select class="select" id="alert-sort" aria-label="Sort alerts">
            <option value="score"${filters.sort === "score" ? " selected" : ""}>Sort: risk score</option>
            <option value="recent"${filters.sort === "recent" ? " selected" : ""}>Sort: most recent</option>
            <option value="degree"${filters.sort === "degree" ? " selected" : ""}>Sort: most connected</option>
            <option value="mentions"${filters.sort === "mentions" ? " selected" : ""}>Sort: mention volume</option>
          </select>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="chips" id="alert-type-chips">
            <button class="chip${filters.typesFilter.size === typeEntries.length ? " is-active" : ""}" data-type="__all">All types</button>
            ${typeEntries.map(([type, count]) => `<button class="chip${filters.typesFilter.has(type) ? " is-active" : ""}" data-type="${esc(type)}"><span class="dot" style="background:${TYPES[type]?.color || "#8ea1ba"}"></span>${esc(TYPES[type]?.label || type)} <span class="mono dim">${count}</span></button>`).join("")}
          </div>
          <input class="text-input" id="alert-search" style="max-width:230px" placeholder="Filter by entity or CVE…" value="${esc(filters.query)}" />
        </div>
        <div class="alert-list card-body flush" id="alert-rows">
          ${items.length ? items.map((alert) => alertRow(alert)).join("") : emptyState("No matching entities", "Loosen the filters or re-run the pipeline.")}
        </div>
      </div>
    `;

    bindAlertRows();

    section.querySelectorAll("[data-type]").forEach((chip) => {
      chip.addEventListener("click", () => {
        const type = chip.dataset.type;
        if (type === "__all") {
          filters.typesFilter = new Set(typeEntries.map(([name]) => name));
        } else if (filters.typesFilter.has(type)) {
          filters.typesFilter.delete(type);
        } else {
          filters.typesFilter.add(type);
        }
        section.querySelectorAll("[data-type]").forEach((item) => {
          const key = item.dataset.type;
          const active = key === "__all" ? filters.typesFilter.size === typeEntries.length : filters.typesFilter.has(key);
          item.classList.toggle("is-active", active);
        });
        paintAlertRows();
      });
    });

    const search = $("#alert-search");
    search.addEventListener(
      "input",
      debounce(() => {
        filters.query = search.value;
        paintAlertRows();
      }, 180)
    );

    $("#alert-sort").addEventListener("change", (event) => {
      filters.sort = event.target.value;
      paintAlertRows();
    });
  }

  function bindAlertRows() {
    $$("#alert-rows [data-alert]").forEach((row) => {
      row.addEventListener("click", () => openAlert(row.dataset.alert));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openAlert(row.dataset.alert);
        }
      });
    });
  }

  function paintAlertRows() {
    const host = $("#alert-rows");
    if (!host) return;
    const items = sortedAlerts();
    host.innerHTML = items.length
      ? items.map((alert) => alertRow(alert)).join("")
      : emptyState("No matching entities", "Loosen the filters or re-run the pipeline.");
    bindAlertRows();
  }

  function sortedAlerts() {
    const filters = state.alerts;
    const needle = filters.query.trim().toLowerCase();
    const items = filters.items.filter((alert) => {
      if (filters.typesFilter.size && !filters.typesFilter.has(alert.type)) return false;
      if (!needle) return true;
      return (
        alert.entity.toLowerCase().includes(needle) ||
        (alert.related_cves || []).some((cve) => cve.toLowerCase().includes(needle)) ||
        (alert.reasons || []).some((reason) => reason.toLowerCase().includes(needle))
      );
    });
    const sort = filters.sort;
    const copy = [...items];
    if (sort === "recent") copy.sort((a, b) => String(b.last_seen || "").localeCompare(String(a.last_seen || "")));
    else if (sort === "degree") copy.sort((a, b) => b.degree - a.degree || b.score - a.score);
    else if (sort === "mentions") copy.sort((a, b) => b.mentions - a.mentions || b.score - a.score);
    else copy.sort((a, b) => b.score - a.score);
    return copy;
  }

  // ------------------------------------------------------------------
  // Graph
  // ------------------------------------------------------------------
  async function renderGraphView() {
    const section = $("#view-graph");
    if (!state.graph.payload) {
      if (!section.innerHTML) section.innerHTML = skeletonGraph();
      await loadGraph();
    } else if (state.graph.appliedFocus !== state.graph.focus) {
      // Focus changed elsewhere (global search, alert drawer) while the graph
      // view was hidden: fetch the matching subgraph before drawing.
      await loadGraph();
    }
    drawGraphView();
  }

  function skeletonGraph() {
    return `<div class="grid">
      <div class="card"><div class="card-head"><h3>Loading graph…</h3></div><div class="card-body"><div class="skeleton" style="height:420px"></div></div></div>
    </div>`;
  }

  function graphParams() {
    const g = state.graph;
    return {
      depth: g.depth,
      limit: g.limit,
      include_records: g.includeRecords ? "true" : "false",
      types: Array.from(g.typeFilter).join(","),
      focus: g.focus,
    };
  }

  async function loadGraph() {
    const token = ++graphRequest;
    state.graph.loading = true;
    try {
      const payload = await api.graph(graphParams());
      if (token !== graphRequest) return false; // a newer request superseded this one
      state.graph.payload = payload;
      if (payload.meta?.missing_focus) {
        toast(`No entity matched “${state.graph.focus}”. Showing the global core.`, "info");
        state.graph.focus = "";
      }
      state.graph.appliedFocus = state.graph.focus;
      return true;
    } finally {
      if (token === graphRequest) state.graph.loading = false;
    }
  }

  const graphReload = debounce(async () => {
    try {
      if (await loadGraph()) drawGraphView();
    } catch (error) {
      toast(error.message, "error");
    }
  }, 260);

  function drawGraphView() {
    const section = $("#view-graph");
    const payload = state.graph.payload;
    if (!payload) return;
    const meta = payload.meta;
    disposeChartsIn(section);

    const typeEntries = Object.entries(state.meta?.types || {}).filter(([type]) => type !== "source");
    const available = meta.types || [];
    const selected = state.graph.selected ? payload.nodes.find((node) => node.id === state.graph.selected) : null;

    section.innerHTML = `
      <div class="view-head">
        <div>
          <h2>Threat knowledge graph</h2>
          <p>Entities are connected by typed relations (exploited by, affects, used by, attributed to). Views are bounded server-side — the browser only lays out what it can render smoothly.</p>
        </div>
        <div class="view-actions">
          <span class="chip chip-static mono">${fmt.int(meta.entity_nodes)} entities</span>
          <span class="chip chip-static mono">${fmt.int(meta.total_edges)} relations</span>
        </div>
      </div>

      <div class="graph-layout">
        <div class="card" style="padding:0">
          <div class="graph-stage">
            <div class="graph-hud">
              <span><strong>${fmt.int(meta.shown)}</strong> nodes</span><span class="sep">/</span>
              <span><strong>${fmt.int(payload.links.length)}</strong> links</span><span class="sep">/</span>
              <span>depth ${meta.depth}</span>
              ${meta.truncated ? '<span class="sep">/</span><span style="color:#f6b441">capped</span>' : ""}
            </div>
            <div class="graph-canvas" id="ch-graph" role="img" aria-label="Threat entity relationship graph"></div>
          </div>
          <div class="graph-foot">
            <div class="graph-legend">
              ${available.map((type) => `<span class="legend-item"><span class="legend-dot" style="background:${TYPES[type]?.color || "#8ea1ba"}"></span>${esc(TYPES[type]?.label || type)}</span>`).join("")}
            </div>
            <span class="mono">${meta.truncated ? `${fmt.int(meta.dropped)} nodes hidden by cap` : "complete view"} · click a node to inspect, double-click to focus</span>
          </div>
        </div>

        <div class="grid" style="gap:12px">
          <div class="card">
            <div class="card-head"><div><h3>Explore</h3><div class="card-sub">Bounded, ranked subgraph</div></div></div>
            <div class="graph-controls">
              <div class="control-block">
                <div class="control-label"><span>Focus entity</span><button class="btn btn-ghost" id="graph-clear" style="padding:2px 7px;font-size:10px">Clear</button></div>
                <div class="searchbox" style="width:100%">
                  <input id="graph-focus" placeholder="Search entity or CVE…" autocomplete="off" value="${esc(meta.focus?.name || state.graph.focus || "")}" />
                  <div class="search-results" id="graph-focus-results" hidden></div>
                </div>
                <div class="tiny dim">${meta.focus ? `Focused on <span class="mono">${esc(meta.focus.name)}</span> · ${meta.focus.degree} links` : "Showing the highest-risk core of the graph"}</div>
              </div>

              <div class="control-block">
                <div class="control-label"><span>Hops from focus</span><span class="mono">${meta.depth}</span></div>
                <input type="range" id="graph-depth" min="1" max="4" step="1" value="${meta.depth}" />
              </div>

              <div class="control-block">
                <div class="control-label"><span>Node cap</span><span class="mono">${fmt.int(meta.limit)}</span></div>
                <input type="range" id="graph-limit" min="80" max="900" step="40" value="${state.graph.limit}" />
              </div>

              <div class="control-block">
                <div class="control-label"><span>Node types</span></div>
                <div class="chips">
                  ${typeEntries.map(([type, count]) => `<button class="chip${state.graph.typeFilter.has(type) ? " is-active" : ""}" data-gtype="${esc(type)}"><span class="dot" style="background:${TYPES[type]?.color || "#8ea1ba"}"></span>${esc(TYPES[type]?.label || type)} <span class="mono dim">${count}</span></button>`).join("")}
                </div>
              </div>

              <div class="control-block">
                <label class="switch"><input type="checkbox" id="graph-records"${state.graph.includeRecords ? " checked" : ""} /> Include provenance records</label>
              </div>
            </div>
          </div>

          <div class="card" id="node-inspector">
            ${selected ? nodeInspector(selected) : `<div class="node-card"><div class="section-label">Inspector</div><p class="small dim">Click any node on the canvas to see its footprint. Double-click to re-center the graph on it.</p></div>`}
          </div>
        </div>
      </div>
    `;

    bindGraphControls();
    paintGraph(payload);

    const inspector = $("#node-inspector");
    inspector.querySelector("[data-focus]")?.addEventListener("click", () => {
      state.graph.focus = inspector.querySelector("[data-focus]").dataset.focus;
      state.graph.selected = null;
      graphReload();
    });
    inspector.querySelector("[data-open-alert]")?.addEventListener("click", () => {
      openAlert(inspector.querySelector("[data-open-alert]").dataset.openAlert);
    });
    inspector.querySelector("[data-find-records]")?.addEventListener("click", () => {
      state.records.query = inspector.querySelector("[data-find-records]").dataset.findRecords;
      state.records.offset = 0;
      location.hash = "#/records";
    });
  }

  function bindGraphControls() {
    const focusInput = $("#graph-focus");
    const focusResults = $("#graph-focus-results");

    const searchEntities = debounce(async () => {
      const query = focusInput.value.trim();
      if (query.length < 2) {
        focusResults.hidden = true;
        return;
      }
      try {
        const response = await api.graphSearch(query, 8);
        focusResults.innerHTML = response.items.length
          ? response.items.map((node) => `<button class="search-hit" data-pick="${esc(node.id)}" data-name="${esc(node.name)}"><span class="hit-name">${esc(node.name)}</span><span class="hit-type">${esc(node.type)}</span></button>`).join("")
          : '<div class="search-empty">No matching entity.</div>';
        focusResults.hidden = false;
        focusResults.querySelectorAll("[data-pick]").forEach((hit) => {
          hit.addEventListener("click", () => {
            focusInput.value = hit.dataset.name;
            state.graph.focus = hit.dataset.pick;
            focusResults.hidden = true;
            graphReload();
          });
        });
      } catch (error) {
        focusResults.hidden = true;
      }
    }, 180);

    focusInput.addEventListener("input", searchEntities);
    focusInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        state.graph.focus = focusInput.value.trim();
        focusResults.hidden = true;
        graphReload();
      } else if (event.key === "Escape") {
        focusResults.hidden = true;
      }
    });

    $("#graph-clear").addEventListener("click", () => {
      state.graph.focus = "";
      state.graph.selected = null;
      graphReload();
    });

    $("#graph-depth").addEventListener("input", (event) => {
      state.graph.depth = Number(event.target.value);
      event.target.closest(".control-block").querySelector(".mono").textContent = state.graph.depth;
      graphReload();
    });

    $("#graph-limit").addEventListener("input", (event) => {
      state.graph.limit = Number(event.target.value);
      event.target.closest(".control-block").querySelector(".mono").textContent = fmt.int(state.graph.limit);
      graphReload();
    });

    $$("[data-gtype]").forEach((chip) => {
      chip.addEventListener("click", () => {
        const type = chip.dataset.gtype;
        if (state.graph.typeFilter.has(type)) {
          if (state.graph.typeFilter.size === 1) {
            toast("Keep at least one node type visible.", "info");
            return;
          }
          state.graph.typeFilter.delete(type);
          chip.classList.remove("is-active");
        } else {
          state.graph.typeFilter.add(type);
          chip.classList.add("is-active");
        }
        graphReload();
      });
    });

    $("#graph-records").addEventListener("change", (event) => {
      state.graph.includeRecords = event.target.checked;
      graphReload();
    });
  }

  async function paintGraph(payload) {
    const nodes = payload.nodes || [];
    const links = payload.links || [];
    if (!nodes.length) {
      const el = $("#ch-graph");
      if (el) el.innerHTML = emptyState("Nothing to draw", "No entities match the current filters.");
      return;
    }
    const usedTypes = Array.from(new Set(nodes.map((node) => node.type)));
    const categories = usedTypes.map((type) => ({ name: TYPES[type]?.label || type }));
    const categoryIndex = new Map(usedTypes.map((type, index) => [type, index]));
    const maxScore = state.alerts.items.length ? Math.max(...state.alerts.items.map((alert) => alert.score)) : 0;
    const showLabels = nodes.length <= 110;

    const nodeById = new Map(nodes.map((node) => [node.id, node]));

    const chart = makeChart("ch-graph", {
      backgroundColor: "transparent",
      tooltip: chartTooltip({
        formatter: (params) => {
          if (params.dataType === "edge") {
            const data = params.data;
            return `<b>${esc(data.relType || "relation")}</b><br/><span style="color:#8ea1ba">${esc(data.sourceName)} → ${esc(data.targetName)}</span><br/>weight ${esc(data.weight)} · ${esc(data.count)} mention(s)`;
          }
          const node = params.data;
          return `<b>${esc(node.name)}</b><br/><span style="color:#8ea1ba">${esc(TYPES[node.type]?.label || node.type)}</span>
            <br/>degree ${fmt.int(node.degree)} · ${fmt.int(node.records)} record(s)
            ${node.score ? `<br/>risk score ${fmt.score(node.score)}` : ""}
            ${node.cvss != null ? `<br/>CVSS ${Number(node.cvss).toFixed(1)}` : ""}`;
        },
      }),
      legend: { show: false },
      series: [
        {
          type: "graph",
          layout: "force",
          roam: true,
          draggable: true,
          categories,
          top: 22,
          bottom: 22,
          left: 22,
          right: 22,
          force: {
            repulsion: nodes.length > 220 ? 420 : 260,
            gravity: 0.08,
            edgeLength: [55, 130],
            friction: 0.22,
            layoutAnimation: nodes.length <= 220,
          },
          label: {
            show: showLabels,
            position: "right",
            distance: 5,
            color: "#b9c9dd",
            fontSize: 9,
            fontFamily: "Inter, sans-serif",
            formatter: (params) => truncate(params.data.name, 20),
          },
          labelLayout: { hideOverlap: true },
          lineStyle: { color: "rgba(132, 154, 184, 0.22)", width: 0.9, curveness: 0.06 },
          emphasis: {
            focus: "adjacency",
            scale: true,
            lineStyle: { width: 1.8, color: "rgba(56, 225, 208, 0.6)" },
            label: { show: true, color: "#ffffff" },
          },
          edgeSymbol: ["none", "arrow"],
          edgeSymbolSize: [0, 3.5],
          itemStyle: { borderColor: "rgba(6, 8, 13, 0.9)", borderWidth: 1.4 },
          data: nodes.map((node) => ({
            id: node.id,
            name: node.name,
            type: node.type,
            degree: node.degree,
            records: node.records,
            score: node.score,
            cvss: node.cvss,
            category: categoryIndex.get(node.type) ?? 0,
            symbolSize: nodeSize(node, maxScore),
            itemStyle: {
              color: TYPES[node.type]?.color || "#8ea1ba",
              opacity: node.type === "source" ? 0.55 : 1,
            },
          })),
          links: links.map((link) => {
            const source = nodeById.get(link.source);
            const target = nodeById.get(link.target);
            return {
              source: link.source,
              target: link.target,
              sourceName: source?.name || link.source,
              targetName: target?.name || link.target,
              relType: link.type,
              weight: link.weight,
              count: link.count,
              lineStyle: { width: clamp(0.6 + Math.log1p(link.weight) * 0.5, 0.6, 2.4) },
            };
          }),
        },
      ],
    });

    if (!chart) return;
    chart.off("click");
    chart.off("dblclick");
    chart.on("click", (params) => {
      if (params.dataType !== "node") return;
      state.graph.selected = params.data.id;
      const node = (state.graph.payload?.nodes || []).find((item) => item.id === params.data.id);
      const inspector = $("#node-inspector");
      if (node && inspector) inspector.innerHTML = nodeInspector(node);
      inspector.querySelector("[data-focus]")?.addEventListener("click", () => {
        state.graph.focus = params.data.id;
        state.graph.selected = null;
        graphReload();
      });
      inspector.querySelector("[data-open-alert]")?.addEventListener("click", (event) => openAlert(event.currentTarget.dataset.openAlert));
      inspector.querySelector("[data-find-records]")?.addEventListener("click", (event) => {
        state.records.query = event.currentTarget.dataset.findRecords;
        state.records.offset = 0;
        location.hash = "#/records";
      });
    });
    chart.on("dblclick", (params) => {
      if (params.dataType !== "node") return;
      state.graph.focus = params.data.id;
      state.graph.selected = null;
      graphReload();
    });
  }

  function nodeSize(node, maxScore) {
    const base = 7 + Math.sqrt(Math.max(node.degree, 1)) * 3.4;
    const boost = maxScore ? (node.score / maxScore) * 6 : 0;
    return clamp(base + boost, 8, 34);
  }

  function nodeInspector(node) {
    const inAlerts = state.alerts.items.some((alert) => alert.node_id === node.id);
    return `<div class="node-card">
      <div class="section-label">Inspector</div>
      <div>${typePill(node.type)}</div>
      <h4>${esc(node.name)}</h4>
      <div class="node-stats">
        <div class="node-stat"><b>${fmt.int(node.degree)}</b><span>relations</span></div>
        <div class="node-stat"><b>${fmt.int(node.records)}</b><span>records</span></div>
        <div class="node-stat"><b>${node.score ? fmt.score(node.score) : "—"}</b><span>risk score</span></div>
        <div class="node-stat"><b>${node.cvss != null ? Number(node.cvss).toFixed(1) : "—"}</b><span>CVSS</span></div>
      </div>
      <div class="tiny dim">first seen ${esc(fmt.date(node.first_seen))} · last seen ${esc(fmt.date(node.last_seen))}</div>
      <div class="drawer-actions">
        <button class="btn btn-primary" data-focus="${esc(node.id)}">Focus graph</button>
        ${inAlerts ? `<button class="btn btn-ghost" data-open-alert="${esc(node.id)}">Open alert</button>` : ""}
        <button class="btn btn-ghost" data-find-records="${esc(node.name)}">Find records</button>
      </div>
    </div>`;
  }

  // ------------------------------------------------------------------
  // Trends
  // ------------------------------------------------------------------
  async function renderTrends() {
    const section = $("#view-trends");
    const days = state.trends.days;
    if (!state.trends.data) state.trends.data = await api.trends(days);
    const data = state.trends.data;
    disposeChartsIn(section);

    const sources = Object.entries(data.series || {});
    const total = (data.total || []).reduce((a, b) => a + b, 0);
    const peak = Math.max(0, ...(data.total || []));
    const entities = data.entities || [];

    section.innerHTML = `
      <div class="view-head">
        <div>
          <h2>Activity &amp; anomalies</h2>
          <p>Daily observation volume per source, entity mention trajectories, and z-score spikes measured against a rolling baseline.</p>
        </div>
        <div class="chips">
          ${[30, 60, 90, 365].map((value) => `<button class="chip${days === value ? " is-active" : ""}" data-days="${value}">${value === 365 ? "All" : `${value}d`}</button>`).join("")}
        </div>
      </div>

      <div class="kpis" style="grid-template-columns:repeat(4,minmax(0,1fr))">
        ${kpi("Observations in range", fmt.int(total), `${fmt.int((data.dates || []).length)} days`, "")}
        ${kpi("Peak day", fmt.int(peak), esc(fmt.date((data.dates || [])[data.total.indexOf(peak)] || null)), "blue")}
        ${kpi("Active sources", fmt.int(sources.length), sources.map(([name]) => name).join(" · "), "violet")}
        ${kpi("Detected spikes", fmt.int((data.spikes || []).length), "z-score anomalies", "amber")}
      </div>

      <div class="card">
        <div class="card-head">
          <div><h3>Daily observations by source</h3><div class="card-sub">Stacked volume, UTC days</div></div>
          <span class="card-tag mono">${fmt.int(total)} obs</span>
        </div>
        <div class="card-body">
          ${sources.length ? '<div class="chart chart-md" id="ch-trends"></div>' : emptyState("No timeline", "No records with usable timestamps in this range.")}
        </div>
      </div>

      <div class="grid grid-2">
        <div class="card">
          <div class="card-head"><div><h3>Entity trajectories</h3><div class="card-sub">Mentions for the five highest-risk entities</div></div></div>
          <div class="card-body">
            ${entities.length ? '<div class="chart chart-md" id="ch-entities"></div>' : emptyState("Nothing to plot", "Risk scoring produced no entities.")}
          </div>
        </div>

        <div class="card">
          <div class="card-head"><div><h3>Spike detection</h3><div class="card-sub">Observed vs trailing baseline</div></div><span class="card-tag mono">${fmt.int((data.spikes || []).length)}</span></div>
          <div class="card-body flush">
            <div class="spike-list">
              ${(data.spikes || []).length
                ? data.spikes.slice(0, 14).map((spike) => `<div class="spike-row">
                    <div style="min-width:0">
                      <div class="alert-name">${esc(spike.entity)} ${typePill(spike.type)}</div>
                      <div class="spike-sub">${esc(spike.window)} · observed ${fmt.int(spike.observed)} vs baseline ${spike.baseline.toFixed(2)}</div>
                    </div>
                    <div class="spike-z">z=${spike.z_score.toFixed(2)}</div>
                  </div>`).join("")
                : emptyState("No spikes", "Spikes need at least three days of baseline observations.")}
            </div>
          </div>
        </div>
      </div>
    `;

    section.querySelectorAll("[data-days]").forEach((chip) => {
      chip.addEventListener("click", async () => {
        state.trends.days = Number(chip.dataset.days);
        state.trends.data = null;
        await renderTrends();
      });
    });

    if (sources.length) {
      makeChart("ch-trends", {
        grid: { left: 36, right: 14, top: 16, bottom: 26 },
        tooltip: chartTooltip({ trigger: "axis", axisPointer: { type: "line", lineStyle: { color: "#2a3b52" } } }),
        xAxis: axisCategory(data.dates),
        yAxis: axisValue(),
        series: sources.map(([name, values], index) => areaSeries(name, values, PALETTE[index % PALETTE.length], { stack: "volume" })),
      });
    }

    if (entities.length) {
      makeChart("ch-entities", {
        grid: { left: 32, right: 12, top: 30, bottom: 26 },
        tooltip: chartTooltip({ trigger: "axis", axisPointer: { type: "line", lineStyle: { color: "#2a3b52" } } }),
        legend: {
          top: 0,
          left: 0,
          itemWidth: 8,
          itemHeight: 8,
          icon: "circle",
          textStyle: { color: "#8ea1ba", fontSize: 9, fontFamily: "Inter, sans-serif" },
        },
        xAxis: axisCategory(data.dates),
        yAxis: axisValue(),
        series: entities.map((entity, index) => {
          const series = areaSeries(entity.entity, entity.values, PALETTE[index % PALETTE.length]);
          series.areaStyle = undefined;
          series.lineStyle.width = 1.5;
          return series;
        }),
      });
    }
  }

  // ------------------------------------------------------------------
  // Records
  // ------------------------------------------------------------------
  async function renderRecords() {
    const section = $("#view-records");
    const filters = state.records;
    const params = { offset: filters.offset, limit: filters.limit };
    if (filters.source) params.source = filters.source;
    if (filters.query) params.q = filters.query;
    if (filters.cve) params.cve = filters.cve;
    filters.data = await api.records(params);
    const data = filters.data;
    const sources = Object.keys(data.sources || {});

    section.innerHTML = `
      <div class="view-head">
        <div>
          <h2>Source inspector</h2>
          <p>Every normalized observation with its provenance identifiers, labels and original metadata. Search first, then open a row for the full text.</p>
        </div>
        <div class="view-actions">
          <span class="chip chip-static mono">${fmt.int(data.total)} matching</span>
          <span class="chip chip-static mono">${fmt.int(Object.values(data.sources || {}).reduce((a, b) => a + b, 0))} total</span>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="flex" style="flex-wrap:wrap;gap:10px">
            <div class="field">
              <label for="rec-source">Source</label>
              <select class="select" id="rec-source">
                <option value="">All sources</option>
                ${sources.map((source) => `<option value="${esc(source)}"${filters.source === source ? " selected" : ""}>${esc(source)} (${data.sources[source]})</option>`).join("")}
              </select>
            </div>
            <div class="field">
              <label for="rec-query">Text search</label>
              <input class="text-input" id="rec-query" placeholder="title, body, label…" value="${esc(filters.query)}" style="min-width:190px" />
            </div>
            <div class="field">
              <label for="rec-cve">CVE filter</label>
              <input class="text-input" id="rec-cve" placeholder="CVE-2024-3400" value="${esc(filters.cve)}" style="min-width:150px" />
            </div>
          </div>
          <button class="btn btn-ghost" id="rec-reset">${icon("refresh")}Reset</button>
        </div>

        <div class="table-scroll">
          ${data.items.length ? `<table class="records-table">
            <thead><tr><th>Source</th><th>Observation</th><th>CVEs</th><th>Published</th></tr></thead>
            <tbody>
              ${data.items.map((record) => `<tr data-record="${esc(record.id)}">
                <td><span class="src-tag" data-src="${esc(record.source)}">${esc(record.source)}</span></td>
                <td>
                  <div class="record-title">${esc(record.title)}</div>
                  <div class="record-snippet">${esc(record.snippet)}</div>
                </td>
                <td>${record.cves.length ? `<span class="cve-chip">${esc(record.cves[0])}</span>${record.cves.length > 1 ? `<span class="tiny dim"> +${record.cves.length - 1}</span>` : ""}` : '<span class="tiny dim">—</span>'}</td>
                <td class="records-date">${esc(fmt.date(record.published_at || record.ingested_at))}</td>
              </tr>`).join("")}
            </tbody>
          </table>` : emptyState("No matching records", "Broaden the search or switch the source filter.")}
        </div>

        <div class="pager">
          <span class="mono">${data.total === 0 ? "0" : fmt.int(data.offset + 1)}–${fmt.int(Math.min(data.offset + data.limit, data.total))} of ${fmt.int(data.total)}</span>
          <div class="pager-actions">
            <button class="btn btn-ghost" id="rec-prev"${data.offset <= 0 ? " disabled" : ""}>Previous</button>
            <button class="btn btn-ghost" id="rec-next"${data.offset + data.limit >= data.total ? " disabled" : ""}>Next</button>
          </div>
        </div>
      </div>
    `;

    section.querySelectorAll("[data-record]").forEach((row) => {
      row.addEventListener("click", () => openRecord(row.dataset.record));
    });

    $("#rec-source").addEventListener("change", (event) => {
      filters.source = event.target.value;
      filters.offset = 0;
      renderRecords().catch((error) => toast(error.message, "error"));
    });

    const queryInput = $("#rec-query");
    queryInput.addEventListener(
      "input",
      debounce(() => {
        filters.query = queryInput.value.trim();
        filters.offset = 0;
        withFocus("rec-query", () =>
          renderRecords().catch((error) => toast(error.message, "error"))
        );
      }, 300)
    );

    const cveInput = $("#rec-cve");
    cveInput.addEventListener(
      "input",
      debounce(() => {
        filters.cve = cveInput.value.trim();
        filters.offset = 0;
        withFocus("rec-cve", () =>
          renderRecords().catch((error) => toast(error.message, "error"))
        );
      }, 300)
    );

    $("#rec-reset").addEventListener("click", () => {
      Object.assign(filters, { source: "", query: "", cve: "", offset: 0 });
      renderRecords().catch((error) => toast(error.message, "error"));
    });

    $("#rec-prev").addEventListener("click", () => {
      filters.offset = Math.max(0, filters.offset - filters.limit);
      renderRecords().catch((error) => toast(error.message, "error"));
    });

    $("#rec-next").addEventListener("click", () => {
      filters.offset += filters.limit;
      renderRecords().catch((error) => toast(error.message, "error"));
    });
  }

  // ------------------------------------------------------------------
  // Drawer
  // ------------------------------------------------------------------
  const drawer = () => $("#drawer");

  function openDrawer(html) {
    clearTimeout(state.drawerTimer);
    const el = drawer();
    el.innerHTML = html;
    el.hidden = false;
    $("#scrim").hidden = false;
    requestAnimationFrame(() => {
      el.classList.add("is-open");
      $("#scrim").classList.add("is-open");
    });
    document.body.style.overflow = "hidden";
  }

  function closeDrawer() {
    const el = drawer();
    el.classList.remove("is-open");
    $("#scrim").classList.remove("is-open");
    document.body.style.overflow = "";
    disposeChartsIn(el);
    state.drawerToken += 1;
    state.drawerTimer = setTimeout(() => {
      if (el.classList.contains("is-open")) return; // reopened meanwhile
      el.hidden = true;
      el.innerHTML = "";
      $("#scrim").hidden = true;
    }, 240);
  }

  function drawerShell(kicker, title, type, bodyHtml) {
    return `<div class="drawer-head">
      <div style="min-width:0">
        <div class="kicker">${esc(kicker)}</div>
        <h3>${esc(title)}</h3>
        <div style="margin-top:7px">${typePill(type)}</div>
      </div>
      <button class="icon-btn close" data-close aria-label="Close">${icon("close")}</button>
    </div>
    <div class="drawer-body">${bodyHtml}</div>`;
  }

  async function openAlert(key) {
    const token = ++state.drawerToken;
    openDrawer(`<div class="drawer-head"><div><div class="kicker">Alert</div><h3>Loading…</h3></div><button class="icon-btn close" data-close>${icon("close")}</button></div><div class="drawer-body"><div class="skeleton" style="height:90px"></div><div class="skeleton" style="height:180px;margin-top:12px"></div></div>`);
    try {
      const alert = await api.alert(key);
      if (token !== state.drawerToken) return;
      renderAlertDrawer(alert);
    } catch (error) {
      if (token !== state.drawerToken) return;
      openDrawer(`<div class="drawer-head"><div><div class="kicker">Alert</div><h3>Could not load</h3></div><button class="icon-btn close" data-close>${icon("close")}</button></div><div class="drawer-body">${errorState(error.message)}</div>`);
    }
  }

  function renderAlertDrawer(alert) {
    const components = alert.components || {};
    const componentEntries = Object.entries(components).sort((a, b) => b[1] - a[1]);
    const reasons = alert.reasons || [];
    const cves = alert.related_cves || [];
    const evidence = alert.records || [];
    const neighbours = alert.neighbours || [];
    const score = Number(alert.score || 0);

    openDrawer(
      drawerShell(
        `Rank #${alert.rank} · risk breakdown`,
        alert.entity,
        alert.type,
        `<div class="score-hero">
          <div class="score-ring ${scoreClass(score)}" style="--p:${clamp(score * 100, 1, 100)}"><b>${fmt.score(score)}</b></div>
          <div class="score-hero-text">
            <p><strong style="color:var(--text)">${fmt.int(alert.mentions)}</strong> observations · <strong style="color:var(--text)">${fmt.int(alert.degree)}</strong> graph relations</p>
            <p>First seen ${esc(fmt.date(alert.first_seen))} · last seen ${esc(fmt.rel(alert.last_seen))}</p>
            ${alert.cvss != null ? `<p>CVSS base <strong style="color:#ffd38a">${Number(alert.cvss).toFixed(1)}</strong></p>` : ""}
          </div>
        </div>

        <div class="drawer-actions">
          <button class="btn btn-primary" data-graph>${icon("arrow")}Open in graph</button>
          <button class="btn btn-ghost" data-records>${icon("empty")}Matching records</button>
        </div>

        <div class="drawer-section">
          <div class="section-label">Score factors <span class="mono">weighted contribution</span></div>
          <div class="chart chart-sm" id="ch-factors"></div>
        </div>

        <div class="drawer-section">
          <div class="section-label">Why it surfaced</div>
          ${reasons.length ? `<ul class="reason-list">${reasons.map((reason) => `<li>${esc(reason)}</li>`).join("")}</ul>` : `<p class="small dim">No qualitative reasons recorded for this entity.</p>`}
        </div>

        ${cves.length ? `<div class="drawer-section"><div class="section-label">Related CVEs</div><div class="cve-chips">${cves.map((cve) => `<span class="cve-chip">${esc(cve)}</span>`).join("")}</div></div>` : ""}

        <div class="drawer-section">
          <div class="section-label">Mention activity <span class="mono">30d</span></div>
          <div class="chart chart-sm" id="ch-mentions"></div>
        </div>

        ${neighbours.length ? `<div class="drawer-section"><div class="section-label">Connected entities</div><div class="chips">${neighbours.map((node) => `<span class="chip chip-static">${esc(node.name)} <span class="mono dim">${node.type}</span></span>`).join("")}</div></div>` : ""}

        <div class="drawer-section">
          <div class="section-label">Supporting evidence <span class="mono">${evidence.length}</span></div>
          ${evidence.length ? evidence.map((record) => evidenceBlock(record)).join("") : `<p class="small dim">No linked records.</p>`}
        </div>`
      )
    );

    const el = drawer();
    el.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
    el.querySelector("[data-graph]")?.addEventListener("click", () => {
      closeDrawer();
      state.graph.focus = alert.node_id;
      state.graph.selected = alert.node_id;
      location.hash = "#/graph";
    });
    el.querySelector("[data-records]")?.addEventListener("click", () => {
      closeDrawer();
      state.records.query = alert.entity;
      state.records.offset = 0;
      location.hash = "#/records";
    });

    if (componentEntries.length) {
      const names = componentEntries.map(([name]) => name.replace(/_/g, " "));
      const values = componentEntries.map(([, value]) => Number(value.toFixed(4)));
      const maxValue = Math.max(...values, 0.001);
      makeChart("ch-factors", {
        grid: { left: 118, right: 42, top: 6, bottom: 6 },
        tooltip: chartTooltip({ trigger: "item", formatter: (params) => `${esc(params.name)}: <b>${params.value}</b>` }),
        xAxis: { type: "value", max: maxValue * 1.2, splitLine: { show: false }, axisLabel: { show: false }, axisLine: { show: false } },
        yAxis: {
          type: "category",
          data: names,
          axisLine: { show: false },
          axisTick: { show: false },
          axisLabel: { color: "#8ea1ba", fontSize: 9, fontFamily: MONO },
        },
        series: [
          {
            type: "bar",
            data: values.map((value, index) => ({
              value,
              itemStyle: {
                borderRadius: [0, 4, 4, 0],
                color: index === 0 ? "#38e1d0" : "#2a6f83",
              },
            })),
            barWidth: 9,
            label: { show: true, position: "right", color: "#8ea1ba", fontSize: 9, fontFamily: MONO, formatter: (params) => params.value.toFixed(3) },
          },
        ],
      });
    }

    const series = alert.series || { dates: [], values: [] };
    if (series.dates?.length) {
      makeChart("ch-mentions", {
        grid: { left: 28, right: 8, top: 10, bottom: 20 },
        tooltip: chartTooltip({ trigger: "axis", axisPointer: { type: "line", lineStyle: { color: "#2a3b52" } } }),
        xAxis: axisCategory(series.dates),
        yAxis: axisValue({ split: false }),
        series: [areaSeries("Mentions", series.values, "#f6b441")],
      });
    }
  }

  function evidenceBlock(record) {
    return `<div class="evidence">
      <button class="evidence-head" type="button">
        <span class="src-tag" data-src="${esc(record.source)}">${esc(record.source)}</span>
        <span class="ev-title">${esc(record.title)}</span>
        <span class="ev-date">${esc(fmt.date(record.timestamp))}</span>
      </button>
      <div class="evidence-body">
        <p>${esc(record.text || "no text")}</p>
        ${record.url ? `<p style="margin-top:8px"><a href="${esc(record.url)}" target="_blank" rel="noopener noreferrer">Open original source ↗</a></p>` : ""}
      </div>
    </div>`;
  }

  async function openRecord(recordId) {
    const token = ++state.drawerToken;
    openDrawer(`<div class="drawer-head"><div><div class="kicker">Observation</div><h3>Loading…</h3></div><button class="icon-btn close" data-close>${icon("close")}</button></div><div class="drawer-body"><div class="skeleton" style="height:120px"></div></div>`);
    try {
      const record = await api.record(recordId);
      if (token !== state.drawerToken) return;
      const meta = record.metadata || {};
      const metaRows = Object.entries(meta).map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(typeof value === "object" ? JSON.stringify(value) : value)}</dd>`).join("");
      openDrawer(
        drawerShell(
          "Source observation",
          record.title,
          "source",
          `<dl class="kv">
            <dt>Source</dt><dd><span class="src-tag" data-src="${esc(record.source)}">${esc(record.source)}</span></dd>
            <dt>Type</dt><dd>${esc(record.record_type)}</dd>
            <dt>Published</dt><dd>${esc(fmt.dateTime(record.published_at))}</dd>
            <dt>Ingested</dt><dd>${esc(fmt.dateTime(record.ingested_at))}</dd>
            <dt>Source id</dt><dd class="mono">${esc(record.source_record_id)}</dd>
            <dt>Record id</dt><dd class="mono">${esc(record.id)}</dd>
            <dt>Raw id</dt><dd class="mono">${esc(record.raw_id || "—")}</dd>
            ${metaRows}
          </dl>

          ${record.labels?.length ? `<div class="drawer-section"><div class="section-label">Labels</div><div class="chips">${record.labels.map((label) => `<span class="chip chip-static">${esc(label)}</span>`).join("")}</div></div>` : ""}

          <div class="drawer-section">
            <div class="section-label">Text</div>
            <div class="evidence-body" style="display:block">
              <p>${esc(record.text || "no text")}</p>
            </div>
          </div>

          <div class="drawer-actions">
            ${record.url ? `<a class="btn btn-primary" href="${esc(record.url)}" target="_blank" rel="noopener noreferrer">${icon("external")}Open original</a>` : ""}
            <button class="btn btn-ghost" data-close>Close</button>
          </div>`
        )
      );
      drawer().querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
    } catch (error) {
      if (token !== state.drawerToken) return;
      openDrawer(`<div class="drawer-head"><div><div class="kicker">Observation</div><h3>Could not load</h3></div><button class="icon-btn close" data-close>${icon("close")}</button></div><div class="drawer-body">${errorState(error.message)}</div>`);
      drawer().querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", closeDrawer));
    }
  }

  // ------------------------------------------------------------------
  // Global search
  // ------------------------------------------------------------------
  function bindGlobalSearch() {
    const input = $("#global-search");
    const results = $("#search-results");

    const search = debounce(async () => {
      const query = input.value.trim();
      if (query.length < 2) {
        results.hidden = true;
        return;
      }
      try {
        const [entities, alerts] = await Promise.all([
          api.graphSearch(query, 6),
          api.alerts({ q: query, limit: 5 }),
        ]);
        const rows = [];
        for (const node of entities.items) {
          rows.push(`<button class="search-hit" data-entity="${esc(node.id)}"><span class="hit-name">${esc(node.name)}</span><span class="hit-type">${esc(node.type)}</span></button>`);
        }
        for (const alert of alerts.items) {
          const known = entities.items.some((node) => node.id === alert.node_id);
          if (!known) rows.push(`<button class="search-hit" data-alert-key="${esc(alert.node_id)}"><span class="hit-name">${esc(alert.entity)}</span><span class="hit-type">alert #${alert.rank}</span></button>`);
        }
        rows.push(`<button class="search-hit" data-records="${esc(query)}"><span class="hit-name">Search records for “${esc(query)}”</span><span class="hit-type">records</span></button>`);
        results.innerHTML = rows.join("");
        results.hidden = false;
        results.querySelectorAll("[data-entity]").forEach((hit) =>
          hit.addEventListener("click", () => {
            results.hidden = true;
            input.value = "";
            state.graph.focus = hit.dataset.entity;
            state.graph.selected = null;
            location.hash = "#/graph";
          })
        );
        results.querySelectorAll("[data-alert-key]").forEach((hit) =>
          hit.addEventListener("click", () => {
            results.hidden = true;
            input.value = "";
            openAlert(hit.dataset.alertKey);
          })
        );
        results.querySelectorAll("[data-records]").forEach((hit) =>
          hit.addEventListener("click", () => {
            results.hidden = true;
            input.value = "";
            state.records.query = hit.dataset.records;
            state.records.offset = 0;
            location.hash = "#/records";
          })
        );
      } catch (error) {
        results.innerHTML = `<div class="search-empty">${esc(error.message)}</div>`;
        results.hidden = false;
      }
    }, 190);

    input.addEventListener("input", search);
    input.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        results.hidden = true;
        input.blur();
      } else if (event.key === "Enter" && input.value.trim()) {
        results.hidden = true;
        state.records.query = input.value.trim();
        state.records.offset = 0;
        location.hash = "#/records";
      }
    });

    document.addEventListener("click", (event) => {
      if (!$("#search-wrap").contains(event.target)) results.hidden = true;
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) {
        event.preventDefault();
        input.focus();
        input.select();
      }
      if (event.key === "Escape") {
        results.hidden = true;
        $(".sidebar").classList.remove("is-open");
        if (!drawer().hidden) closeDrawer();
      }
    });
  }

  // ------------------------------------------------------------------
  // Wiring
  // ------------------------------------------------------------------
  function bindShell() {
    window.addEventListener("hashchange", () => {
      route().catch((error) => toast(error.message, "error"));
    });
    if (!location.hash) location.hash = "#/overview";

    const sidebar = $(".sidebar");
    const closeSidebar = () => sidebar.classList.remove("is-open");
    $("#nav-toggle").addEventListener("click", (event) => {
      event.stopPropagation();
      sidebar.classList.toggle("is-open");
    });
    $$("#nav .nav-item, .brand").forEach((item) =>
      item.addEventListener("click", closeSidebar)
    );
    document.addEventListener("click", (event) => {
      if (window.innerWidth <= 980 && sidebar.classList.contains("is-open") && !sidebar.contains(event.target)) {
        closeSidebar();
      }
    });

    $("#refresh-btn").addEventListener("click", refreshRun);
    $("#refresh-icon")?.addEventListener("click", refreshRun);
    $("#boot-retry").addEventListener("click", async () => {
      $("#boot-hint").hidden = false;
      bootFill().style.background = "";
      showBoot("Starting the pipeline…");
      try {
        const response = await api.refresh(null);
        state.status = response.status;
        pollStatus(1000);
      } catch (error) {
        showBootError(error.message);
      }
    });

    $("#scrim").addEventListener("click", closeDrawer);
    drawer().addEventListener("click", (event) => {
      if (event.target.closest("[data-close]")) closeDrawer();
      const head = event.target.closest(".evidence-head");
      if (head) head.parentElement.classList.toggle("is-open");
    });

    window.addEventListener("resize", debounce(() => {
      for (const chart of state.charts.values()) chart.resize();
    }, 120));

    setInterval(() => {
      $("#clock").textContent = new Date().toLocaleTimeString(undefined, { hour12: false });
    }, 1000);
    $("#clock").textContent = new Date().toLocaleTimeString(undefined, { hour12: false });

    // Status heartbeat keeps the run indicator honest even without a refresh.
    setInterval(async () => {
      if (state.status?.state === "running") return;
      try {
        const status = await api.status();
        const previous = state.status;
        if (status.state !== previous?.state || (status.generated_at && previous?.generated_at !== status.generated_at)) {
          await handleStatus(status);
        } else {
          state.status = status;
          syncChrome(status);
        }
      } catch {
        /* transient; the next heartbeat or user action retries */
      }
    }, 20000);
  }

  async function start() {
    bindShell();
    bindGlobalSearch();
    try {
      state.status = await api.status();
      syncChrome(state.status);
    } catch (error) {
      showBootError(error.message);
      return;
    }
    if (state.status.has_data) {
      await enterApp();
      pollStatus(3000);
      return;
    }
    if (state.status.state === "error") {
      showBootError(state.status.error);
      return;
    }
    bootProgress(state.status.message || "Running the pipeline…", 42);
    pollStatus(1100);
  }

  start().catch((error) => showBootError(error.message));
})();
