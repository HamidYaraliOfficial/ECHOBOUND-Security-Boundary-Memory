// ECHOBOUND — Security Command Center application logic
// Talks to the FastAPI backend (echobound.api) over REST + WebSocket.

const State = {
  apiBase: localStorage.getItem("echobound_api_base") || "http://localhost:8088",
  lang: localStorage.getItem("echobound_lang") || "en",
  theme: localStorage.getItem("echobound_theme") || "win11-light",
  currentView: "overview",
  ws: null,
};

function t(path) {
  const dict = ECHOBOUND_I18N[State.lang];
  const parts = path.split(".");
  let node = dict;
  for (const p of parts) node = node && node[p];
  return node ?? path;
}

// ------------------------------------------------------------------ API
async function api(path, opts = {}) {
  const res = await fetch(State.apiBase + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text || res.statusText}`);
  }
  return res.json();
}
const apiGet = (path) => api(path);
const apiPost = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

// -------------------------------------------------------------- toasts
function toast(message, kind = "info") {
  const stack = document.getElementById("toast-stack");
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

// --------------------------------------------------------------- theme
function applyTheme(theme) {
  State.theme = theme;
  localStorage.setItem("echobound_theme", theme);
  document.documentElement.setAttribute("data-theme", theme);
  document.querySelectorAll(".theme-pill").forEach((p) => p.classList.toggle("active", p.dataset.theme === theme));
}

function applyLanguage(lang) {
  State.lang = lang;
  localStorage.setItem("echobound_lang", lang);
  const dict = ECHOBOUND_I18N[lang];
  document.documentElement.setAttribute("lang", dict.lang);
  document.documentElement.setAttribute("dir", dict.dir);
  document.querySelectorAll(".lang-pill").forEach((p) => p.classList.toggle("active", p.dataset.lang === lang));
  renderStaticText();
}

function renderStaticText() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.getElementById("nav-search-input").placeholder = t("searchPlaceholder");
}

// ---------------------------------------------------------------- nav
function switchView(viewId) {
  State.currentView = viewId;
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === viewId));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + viewId));
  const loader = VIEW_LOADERS[viewId];
  if (loader) loader().catch((e) => toast(String(e.message || e), "error"));
}

// ----------------------------------------------------------- utilities
function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
function severityBadge(sev) {
  return `<span class="badge ${sev || "info"}">${sev || "info"}</span>`;
}
function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstChild;
}

// ================================================================ OVERVIEW
async function loadOverview() {
  const root = document.getElementById("view-overview");
  root.querySelector(".metric-entities") && null;
  try {
    const [entities, drifts, incidents, blind] = await Promise.all([
      apiGet("/api/v1/entities?limit=500"),
      apiGet("/api/v1/drifts"),
      apiGet("/api/v1/incidents"),
      apiGet("/api/v1/blind-spots").catch(() => ({ low_visibility_entities: [] })),
    ]);
    document.getElementById("metric-entities").textContent = entities.length;
    const since = Date.now() / 1000 - 86400;
    document.getElementById("metric-drifts").textContent = drifts.filter((d) => d.detected_at >= since).length;
    document.getElementById("metric-incidents").textContent = incidents.filter((i) => i.state === "open").length;
    document.getElementById("metric-blindspots").textContent = blind.low_visibility_entities.length;

    const recentList = document.getElementById("recent-drifts-list");
    recentList.innerHTML = "";
    drifts.slice(0, 8).forEach((d) => {
      recentList.appendChild(el(`<tr>
        <td>${d.entity_id}</td>
        <td>${d.drift_type}</td>
        <td>${severityBadge(d.severity)}</td>
        <td>${fmtTime(d.detected_at)}</td>
      </tr>`));
    });

    const counts = {};
    drifts.forEach((d) => (counts[d.entity_id] = (counts[d.entity_id] || 0) + 1));
    const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const topList = document.getElementById("top-drift-entities");
    topList.innerHTML = "";
    if (ranked.length === 0) topList.appendChild(el(`<div class="empty-state">${t("common.noData")}</div>`));
    ranked.forEach(([entityId, count]) => {
      topList.appendChild(el(`<div class="oh-day-row" style="grid-template-columns:1fr auto;">
        <div>${entityId}</div><div class="badge high">${count}</div></div>`));
    });
  } catch (e) {
    toast("Overview load failed: " + e.message);
  }
}

// ================================================================ ENTITIES
async function loadEntities() {
  const search = document.getElementById("entity-search").value;
  const type = document.getElementById("entity-type-filter").value;
  let url = "/api/v1/entities?limit=200";
  if (search) url += "&search=" + encodeURIComponent(search);
  if (type) url += "&type=" + encodeURIComponent(type);
  const entities = await apiGet(url);
  const body = document.getElementById("entities-table-body");
  body.innerHTML = "";
  if (entities.length === 0) {
    body.appendChild(el(`<tr><td colspan="5" class="empty-state">${t("common.noData")}</td></tr>`));
  }
  entities.forEach((e) => {
    body.appendChild(el(`<tr style="cursor:pointer" onclick="openEntityDetail('${e.id}')">
      <td>${e.name}</td><td>${e.type}</td><td>${e.archetype || "—"}</td>
      <td>${fmtTime(e.last_seen)}</td><td><span class="btn ghost" style="padding:4px 10px;">→</span></td>
    </tr>`));
  });
}

async function openEntityDetail(entityId) {
  switchView("investigation");
  document.getElementById("investigate-entity-id").value = entityId;
  await runInspectBoundary();
}

// ================================================================ DRIFT
async function loadDrifts() {
  const drifts = await apiGet("/api/v1/drifts");
  const body = document.getElementById("drift-table-body");
  body.innerHTML = "";
  if (drifts.length === 0) body.appendChild(el(`<tr><td colspan="6" class="empty-state">${t("common.noData")}</td></tr>`));
  drifts.forEach((d) => {
    body.appendChild(el(`<tr>
      <td>${d.entity_id}</td>
      <td>${d.drift_type}</td>
      <td>${severityBadge(d.severity)}</td>
      <td>${(d.confidence * 100).toFixed(0)}%</td>
      <td>${fmtTime(d.detected_at)}</td>
      <td>
        <select class="select-control" style="font-size:11px;padding:4px 6px;" onchange="submitFeedback('${d.id}', this.value)">
          <option value="">${t("common.run")}…</option>
          <option value="expected">${t("drift.feedbackExpected")}</option>
          <option value="legitimate_change">${t("drift.feedbackLegit")}</option>
          <option value="false_positive_candidate">${t("drift.feedbackFP")}</option>
          <option value="investigation_required">${t("drift.feedbackInvestigate")}</option>
          <option value="confirmed_behavioral_drift">${t("drift.feedbackConfirmed")}</option>
        </select>
      </td>
    </tr>`));
  });
}

async function submitFeedback(driftId, label) {
  if (!label) return;
  await apiPost(`/api/v1/drifts/${driftId}/feedback`, { label });
  toast("Feedback recorded");
}

async function runDriftForEntity() {
  const id = document.getElementById("drift-run-entity-id").value.trim();
  if (!id) return;
  const events = await apiPost(`/api/v1/entities/${id}/drift/run`, {});
  toast(`Drift run complete: ${events.length} event(s)`);
  loadDrifts();
}

// ================================================================ INCIDENTS
async function loadIncidents() {
  const incidents = await apiGet("/api/v1/incidents");
  const body = document.getElementById("incidents-table-body");
  body.innerHTML = "";
  if (incidents.length === 0) body.appendChild(el(`<tr><td colspan="5" class="empty-state">${t("common.noData")}</td></tr>`));
  incidents.forEach((i) => {
    body.appendChild(el(`<tr style="cursor:pointer" onclick="openIncidentTimeline('${i.id}')">
      <td>${i.title}</td><td>${i.entity_ids.length}</td>
      <td>${severityBadge(i.severity)}</td><td>${i.state}</td><td>${fmtTime(i.opened_at)}</td>
    </tr>`));
  });
}
async function correlateIncidents() {
  const since = Date.now() / 1000 - 6 * 3600;
  const result = await apiPost(`/api/v1/incidents/correlate?since=${since}`, {});
  toast(`Correlated ${result.length} incident(s)`);
  loadIncidents();
}
async function openIncidentTimeline(id) {
  const timeline = await apiGet(`/api/v1/incidents/${id}/timeline`);
  const box = document.getElementById("incident-timeline-box");
  box.innerHTML = "";
  box.appendChild(el(`<div class="timeline-item"><div class="timeline-time">${fmtTime(timeline.earliest_drift?.detected_at)}</div>
    <b>Earliest drift</b><br/><span class="small-muted">${timeline.earliest_drift?.description || "—"}</span></div>`));
  (timeline.nearby_changes || []).forEach((c) => {
    box.appendChild(el(`<div class="timeline-item"><div class="timeline-time">${fmtTime(c.happened_at)}</div>
      <b>${c.kind}</b> — ${c.ref}</div>`));
  });
  box.appendChild(el(`<div class="small-muted">${timeline.disclaimer}</div>`));
}

// ================================================================ INVESTIGATION
async function runInspectBoundary() {
  const id = document.getElementById("investigate-entity-id").value.trim();
  if (!id) return;
  const data = await apiGet(`/api/v1/entities/${id}/boundary`);
  document.getElementById("investigate-boundary-output").textContent = JSON.stringify(data, null, 2);
  const hyp = await apiGet(`/api/v1/ai/entities/${id}/hypotheses`);
  const list = document.getElementById("investigate-hypotheses");
  list.innerHTML = "";
  hyp.forEach((h) => list.appendChild(el(`<li>${h}</li>`)));
}
async function explainDrift() {
  const driftId = document.getElementById("investigate-drift-id").value.trim();
  if (!driftId) return;
  const result = await apiGet(`/api/v1/ai/drift/${driftId}/explain`);
  document.getElementById("investigate-ai-output").textContent =
    (result.narrative || "") + "\n\n" + JSON.stringify(result.structured || result, null, 2);
}

// ================================================================ BASELINE
async function buildBaseline() {
  const id = document.getElementById("baseline-entity-id").value.trim();
  const context = document.getElementById("baseline-context").value.trim();
  if (!id) return;
  let ctx = {};
  try { ctx = context ? JSON.parse(context) : {}; } catch { toast("Invalid context JSON"); return; }
  const result = await apiPost(`/api/v1/entities/${id}/baseline`, { context: ctx, notes: "manual build" });
  toast("Baseline built: " + result.id);
  loadBaselineHistory();
}
async function loadBaselineHistory() {
  const id = document.getElementById("baseline-entity-id").value.trim();
  if (!id) return;
  const history = await apiGet(`/api/v1/entities/${id}/baseline/history`);
  const body = document.getElementById("baseline-history-body");
  body.innerHTML = "";
  if (history.length === 0) body.appendChild(el(`<tr><td colspan="4" class="empty-state">${t("common.noData")}</td></tr>`));
  history.forEach((b) => {
    body.appendChild(el(`<tr><td>${b.id}</td><td>${b.context_key}</td><td>${b.status}</td><td>${fmtTime(b.created_at)}</td></tr>`));
  });
}

// ================================================================ POLICY
async function loadPolicies() {
  const policies = await apiGet("/api/v1/policies");
  const body = document.getElementById("policy-table-body");
  body.innerHTML = "";
  if (policies.length === 0) body.appendChild(el(`<tr><td colspan="3" class="empty-state">${t("common.noData")}</td></tr>`));
  policies.forEach((p) => {
    body.appendChild(el(`<tr><td>${p.id}</td><td>${JSON.stringify(p.entity_selector)}</td><td>${p.change_policy}</td></tr>`));
  });
}
async function simulatePolicy() {
  const entityId = document.getElementById("sim-entity-id").value.trim();
  const relation = document.getElementById("sim-relation").value.trim();
  const targetId = document.getElementById("sim-target-id").value.trim();
  if (!entityId || !relation || !targetId) return;
  const result = await apiPost("/api/v1/policies/simulate", { entity_id: entityId, relation, target_id: targetId });
  document.getElementById("sim-result").innerHTML =
    `<span class="badge ${result.verdict === "violation" ? "high" : result.verdict === "allow" ? "low" : "medium"}">${result.verdict}</span> ${result.reason}`;
}

// ================================================================ AGENTS
async function loadAgents() {
  const agents = await apiGet("/api/v1/agents");
  const body = document.getElementById("agents-table-body");
  body.innerHTML = "";
  if (agents.length === 0) body.appendChild(el(`<tr><td colspan="5" class="empty-state">${t("common.noData")}</td></tr>`));
  agents.forEach((a) => {
    body.appendChild(el(`<tr><td>${a.host_id}</td><td>${a.status}</td>
      <td>${a.events_per_sec}</td><td>${a.dropped_events}</td><td>${fmtTime(a.last_heartbeat)}</td></tr>`));
  });
}

// ================================================================ BLIND SPOTS
async function loadBlindSpots() {
  const data = await apiGet("/api/v1/blind-spots");
  const body = document.getElementById("blindspots-table-body");
  body.innerHTML = "";
  const rows = [...data.stale_agents.map((a) => ({ label: `agent: ${a.host_id}`, reason: "stale heartbeat" })),
                ...data.low_visibility_entities.map((b) => ({ label: b.entity.name, reason: b.reason }))];
  if (rows.length === 0) body.appendChild(el(`<tr><td colspan="2" class="empty-state">${t("common.noData")}</td></tr>`));
  rows.forEach((r) => body.appendChild(el(`<tr><td>${r.label}</td><td>${r.reason}</td></tr>`)));
}

// ================================================================ REPORTS
async function generateOrgReport() {
  const report = await apiGet("/api/v1/reports/organization?fmt=markdown");
  document.getElementById("report-output").textContent = report.content;
}

// ================================================================ ADMIN
async function loadAdmin() {
  const health = await apiGet("/api/v1/platform/health");
  document.getElementById("platform-health-output").textContent = JSON.stringify(health, null, 2);
}

// ================================================================ SYNTHETIC / BENCHMARK (simple views)
async function loadObservatory() {
  await loadEntities();
  const entities = await apiGet("/api/v1/entities?limit=30");
  const box = document.getElementById("observatory-entities");
  box.innerHTML = "";
  entities.forEach((e) => {
    box.appendChild(el(`<div class="pill" onclick="openEntityDetail('${e.id}')">${e.name} <span class="small-muted">(${e.type})</span></div>`));
  });
}
async function loadGraphView() {
  const entities = await apiGet("/api/v1/entities?limit=15");
  const box = document.getElementById("graph-canvas");
  box.innerHTML = "";
  for (const e of entities) {
    const edges = await apiGet(`/api/v1/entities/${e.id}/edges`);
    box.appendChild(el(`<div class="card" style="margin-bottom:10px;">
      <b>${e.name}</b> <span class="small-muted">(${e.type})</span>
      <div class="small-muted" style="margin-top:6px;">${edges.length} relationship(s) tracked</div>
    </div>`));
  }
}
async function seedSynthetic() {
  const result = await apiPost("/api/v1/synthetic/generate", { seed: 42, tenant: "default" });
  toast(`Synthetic world seeded: ${result.events_emitted} events`);
}
async function runBenchmark() {
  const output = document.getElementById("replay-output");
  output.textContent = t("common.loading");
  try {
    const result = await apiPost("/api/v1/benchmark/run?seed=42", {});
    output.textContent = JSON.stringify(result.summary, null, 2) +
      "\n\nfalse_negative_candidates: " + JSON.stringify(result.false_negative_candidates);
  } catch (e) {
    output.textContent = "Error: " + e.message;
  }
}

// ================================================================ SETTINGS / OPERATING HOURS
let ohCountdownInterval = null;

async function refreshOperatingHoursStatus() {
  try {
    const status = await apiGet("/api/v1/context/operating-hours/status");
    renderOperatingHoursStatus(status);
  } catch (e) {
    document.getElementById("oh-status-box").innerHTML =
      `<div class="empty-state">${t("common.loading")} (${e.message})</div>`;
  }
}

function renderOperatingHoursStatus(status) {
  const box = document.getElementById("oh-status-box");
  if (!status.configured) {
    box.innerHTML = `<div class="empty-state">${t("settings.notConfigured")}</div>`;
    return;
  }
  const dotClass = status.in_maintenance_window ? "maintenance" : status.is_open ? "open" : "closed";
  const label = status.in_maintenance_window ? t("settings.inMaintenance") : status.is_open ? t("settings.open") : t("settings.closed");
  box.innerHTML = `
    <div class="hgap" style="align-items:center; margin-bottom: 10px;">
      <span class="status-dot ${dotClass}"></span>
      <b style="font-size:16px;">${label}</b>
      <span class="small-muted">— ${status.current_local_time} (${status.timezone})</span>
    </div>
    <div class="small-muted">${t("settings.nextChange")}: ${status.next_change_at || "—"}</div>
    <div class="oh-countdown" id="oh-live-countdown">${status.human_readable_countdown || "—"}</div>
    <div class="small-muted">${t("settings.timeUntilNext")}</div>
  `;
  clearInterval(ohCountdownInterval);
  let remaining = status.seconds_until_next_change;
  if (remaining != null) {
    ohCountdownInterval = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) { refreshOperatingHoursStatus(); return; }
      const h = Math.floor(remaining / 3600);
      const m = Math.floor((remaining % 3600) / 60);
      const s = remaining % 60;
      const el2 = document.getElementById("oh-live-countdown");
      if (el2) el2.textContent = `${h}h ${m}m ${s}s`;
    }, 1000);
  }
}

async function quickSetupOperatingHours() {
  const tenant = "default";
  const timezone = document.getElementById("oh-timezone").value.trim() || "UTC";
  const start = document.getElementById("oh-start").value;
  const end = document.getElementById("oh-end").value;
  const days = Array.from(document.querySelectorAll(".oh-day-checkbox:checked")).map((c) => parseInt(c.value, 10));
  if (days.length === 0) { toast("Select at least one day"); return; }
  try {
    await apiPost("/api/v1/context/operating-hours/quick-setup", {
      tenant, timezone, start_hhmm: start, end_hhmm: end, weekdays: days,
    });
    toast("Operating hours saved");
    refreshOperatingHoursStatus();
  } catch (e) {
    toast("Failed to save: " + e.message);
  }
}

function buildOperatingHoursDayCheckboxes() {
  const box = document.getElementById("oh-days-box");
  box.innerHTML = "";
  const days = t("settings.days");
  days.forEach((label, idx) => {
    box.appendChild(el(`<label class="pill" style="display:flex;gap:6px;align-items:center;">
      <input type="checkbox" class="oh-day-checkbox" value="${idx}" ${idx < 5 ? "checked" : ""}/> ${label}
    </label>`));
  });
}

// ================================================================ view loaders map
const VIEW_LOADERS = {
  overview: loadOverview,
  explorer: loadEntities,
  drift: loadDrifts,
  incidents: loadIncidents,
  investigation: async () => {},
  baseline: async () => {},
  policy: loadPolicies,
  agents: loadAgents,
  blindspots: loadBlindSpots,
  reports: async () => {},
  admin: loadAdmin,
  observatory: loadObservatory,
  graph: loadGraphView,
  replay: async () => {},
  timeline: loadOverview,
  settings: async () => {
    buildOperatingHoursDayCheckboxes();
    refreshOperatingHoursStatus();
  },
};

// ================================================================ command palette
const COMMANDS = [
  { id: "overview", label: "Go to Overview" }, { id: "explorer", label: "Go to Entity Explorer" },
  { id: "drift", label: "Go to Drift Center" }, { id: "incidents", label: "Go to Incident Center" },
  { id: "investigation", label: "Go to Investigation Workspace" }, { id: "baseline", label: "Go to Baseline Studio" },
  { id: "policy", label: "Go to Policy Studio" }, { id: "agents", label: "Go to Agent Management" },
  { id: "blindspots", label: "Go to Blind Spot Map" }, { id: "reports", label: "Go to Reports" },
  { id: "admin", label: "Go to Administration" }, { id: "settings", label: "Go to Settings" },
];
function openCommandPalette() {
  document.getElementById("command-palette-overlay").classList.add("active");
  document.getElementById("command-input").value = "";
  document.getElementById("command-input").focus();
  renderCommandResults("");
}
function closeCommandPalette() {
  document.getElementById("command-palette-overlay").classList.remove("active");
}
function renderCommandResults(query) {
  const results = COMMANDS.filter((c) => c.label.toLowerCase().includes(query.toLowerCase()));
  const box = document.getElementById("command-results");
  box.innerHTML = "";
  results.forEach((c) => {
    box.appendChild(el(`<div class="command-result-item" onclick="switchView('${c.id}'); closeCommandPalette();">${c.label}</div>`));
  });
}

// ================================================================ websocket
function connectWebSocket() {
  try {
    const wsUrl = State.apiBase.replace(/^http/, "ws") + "/ws";
    State.ws = new WebSocket(wsUrl);
    State.ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        if (data.type === "drift_detected") toast(`New drift: ${data.payload.entity_id}`, "warning");
        if (data.type === "agent_health") toast(`Agent update: ${data.payload.agent_id} (${data.payload.status})`);
        if (data.type === "case_updated") toast(`Incident updated: ${data.payload.id}`);
      } catch {}
    };
    State.ws.onerror = () => {};
  } catch {}
}

// ================================================================ init
function init() {
  applyTheme(State.theme);
  applyLanguage(State.lang);
  document.getElementById("api-base-input").value = State.apiBase;

  document.querySelectorAll(".nav-item").forEach((n) => {
    n.addEventListener("click", () => switchView(n.dataset.view));
  });
  document.querySelectorAll(".theme-pill").forEach((p) => p.addEventListener("click", () => applyTheme(p.dataset.theme)));
  document.querySelectorAll(".lang-pill").forEach((p) => p.addEventListener("click", () => applyLanguage(p.dataset.lang)));

  document.getElementById("command-palette-btn").addEventListener("click", openCommandPalette);
  document.getElementById("command-palette-overlay").addEventListener("click", (e) => {
    if (e.target.id === "command-palette-overlay") closeCommandPalette();
  });
  document.getElementById("command-input").addEventListener("input", (e) => renderCommandResults(e.target.value));
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openCommandPalette(); }
    if (e.key === "Escape") closeCommandPalette();
  });

  document.getElementById("api-base-input").addEventListener("change", (e) => {
    State.apiBase = e.target.value.trim();
    localStorage.setItem("echobound_api_base", State.apiBase);
    toast("API base updated");
    connectWebSocket();
  });

  document.getElementById("nav-search-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      switchView("explorer");
      document.getElementById("entity-search").value = e.target.value;
      loadEntities();
    }
  });

  switchView("overview");
  connectWebSocket();
  setInterval(() => { if (State.currentView === "overview") loadOverview(); }, 20000);
}

document.addEventListener("DOMContentLoaded", init);
