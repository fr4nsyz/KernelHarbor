const API_BASE = "";

async function apiFetch(path) {
  try {
    const res = await fetch(`${API_BASE}${path}`);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

async function apiPost(path, body) {
  try {
    const res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

function updateClock() {
  const el = document.getElementById("clock");
  if (!el) return;
  const now = new Date();
  el.textContent = now.toTimeString().split(" ")[0];
}

function formatTimestamp(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  const date = d.toISOString().split("T")[0];
  const time = d.toTimeString().split(" ")[0];
  return `${date} ${time}`;
}

function updateLastRefresh() {
  const el = document.getElementById("last-refresh");
  if (el) {
    const now = new Date();
    el.textContent = `REFRESHED ${now.toTimeString().split(" ")[0]}`;
  }
}

function renderHealth() {
  apiFetch("/health").then((data) => {
    const badge = document.getElementById("health-status");
    if (!badge) return;
    if (data && data.status === "ok") {
      badge.dataset.status = "ok";
      badge.querySelector(".health-text").textContent = "ONLINE";
    } else {
      badge.dataset.status = "error";
      badge.querySelector(".health-text").textContent = "OFFLINE";
    }
  });
}

function renderStats() {
  apiFetch("/api/alerts/stats").then((data) => {
    if (!data) {
      document.querySelectorAll(".stat-value").forEach((el) => (el.textContent = "--"));
      return;
    }
    animateValue("stat-total", data.alerts_24h ?? 0);
    animateValue("stat-malicious", data.malicious ?? 0);
    animateValue("stat-suspicious", data.suspicious ?? 0);
    animateValue("stat-confirmed", data.confirmed ?? 0);
    animateValue("stat-fp", data.false_posatives ?? data.false_positives ?? 0);
  });
}

function animateValue(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const diff = target - current;
  const steps = Math.min(Math.abs(diff), 15);
  const stepTime = 40;
  let step = 0;
  const interval = setInterval(() => {
    step++;
    const progress = step / steps;
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(current + diff * eased);
    if (step >= steps) {
      el.textContent = target;
      clearInterval(interval);
    }
  }, stepTime);
}

function getSeverityFilter() {
  const raw = document.querySelector(".severity-pill.active")?.dataset?.severity || "all";
  return raw === "all" ? "benign" : raw;
}

function setSeverityFilter(severity) {
  document.querySelectorAll(".severity-pill").forEach((el) => {
    el.classList.toggle("active", el.dataset.severity === severity);
  });
}

let currentView = "cards";

function groupByTimeBucket(alerts) {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 86400000);
  const weekAgo = new Date(today.getTime() - 7 * 86400000);
  const buckets = { today: [], yesterday: [], week: [], older: [] };
  for (const a of alerts) {
    const t = a.timestamp ? new Date(a.timestamp) : new Date();
    if (t >= today) buckets.today.push(a);
    else if (t >= yesterday) buckets.yesterday.push(a);
    else if (t >= weekAgo) buckets.week.push(a);
    else buckets.older.push(a);
  }
  const labels = { today: "TODAY", yesterday: "YESTERDAY", week: "THIS WEEK", older: "ARCHIVE" };
  const result = [];
  for (const key of ["today", "yesterday", "week", "older"]) {
    if (buckets[key].length > 0) {
      result.push({ label: labels[key], alerts: buckets[key] });
    }
  }
  return result;
}

function renderAlerts() {
  const severity = getSeverityFilter();
  const since = document.getElementById("filter-since")?.value || "24h";
  const listEl = document.getElementById("alert-list");

  listEl.innerHTML = '<div class="loading">ACQUIRING SIGNAL <span class="loading-dots">...</span></div>';

  apiFetch(`/api/alerts?since=${since}&min_verdict=${severity}&limit=100`).then((data) => {
    if (!data) {
      listEl.innerHTML = '<div class="error">// SIGNAL LOST - RETRYING //</div>';
      return;
    }

    const alerts = data.alerts || [];
    const countEl = document.getElementById("alert-count");
    if (countEl) countEl.textContent = `${alerts.length} event${alerts.length !== 1 ? "s" : ""}`;

    if (alerts.length === 0) {
      listEl.innerHTML = '<div class="empty">// NO THREATS DETECTED //</div>';
      return;
    }

    if (currentView === "timeline") {
      const buckets = groupByTimeBucket(alerts);
      listEl.innerHTML = buckets
        .map(
          (b) => `
        <div class="timeline-group">
          <div class="timeline-header">${b.label} [${b.alerts.length}]</div>
          ${b.alerts.map((a) => renderAlertCard(a, true)).join("")}
        </div>`
        )
        .join("");
    } else {
      listEl.innerHTML = alerts.map((a) => renderAlertCard(a, false)).join("");
    }

    alerts.forEach((a) => {
      const confirmBtn = document.getElementById(`confirm-${a.id}`);
      const fpBtn = document.getElementById(`fp-${a.id}`);
      if (confirmBtn) confirmBtn.addEventListener("click", () => sendFeedback(a.id, "confirmed"));
      if (fpBtn) fpBtn.addEventListener("click", () => sendFeedback(a.id, "false_positive"));
    });

    updateLastRefresh();
  });
}

function renderAlertCard(a, compact) {
  const ts = formatTimestamp(a.timestamp);
  const confidence = a.confidence != null ? `${(a.confidence * 100).toFixed(0)}%` : "";
  const source = a.source || "";
  const host = a["host.name"] || "";
  const model = a["model.used"] || "";
  const evidence = Array.isArray(a.evidence) ? a.evidence : [];
  const falcoRule = a.metadata?.falco_rule || "";
  const falcoPriority = a.metadata?.falco_priority || "";

  let feedbackHtml = "";
  if (a.feedback) {
    const fType = a.feedback;
    const fLabel = a.feedback === "confirmed" ? "CONFIRMED" : "FALSE POSITIVE";
    feedbackHtml = `<span class="alert-feedback" data-type="${fType}">${fLabel}</span>`;
  } else {
    feedbackHtml = `
      <div class="alert-actions">
        <button class="btn btn-success" id="confirm-${a.id}">CONFIRM</button>
        <button class="btn btn-danger" id="fp-${a.id}">FALSE +</button>
      </div>`;
  }

  const evidenceHtml =
    evidence.length > 0
      ? `<div class="alert-evidence"><strong>EVIDENCE:</strong> ${evidence.join(" // ")}</div>`
      : "";

  const metaParts = [];
  if (host) metaParts.push(`<span>HOST: ${host}</span>`);
  if (source) metaParts.push(`<span>SRC: ${source}</span>`);
  if (source === "llm" && model) metaParts.push(`<span>MODEL: ${model}</span>`);
  if (confidence) metaParts.push(`<span>CONF: ${confidence}</span>`);
  if (falcoRule) metaParts.push(`<span>RULE: ${falcoRule}</span>`);
  if (falcoPriority) metaParts.push(`<span>PRI: ${falcoPriority}</span>`);

  const metaHtml = compact ? "" : metaParts.length > 0 ? `<div class="alert-meta">${metaParts.join("")}</div>` : "";

  return `
    <div class="alert-card" data-verdict="${a.verdict}">
      <div class="alert-header">
        <span class="alert-verdict ${a.verdict}">${a.verdict?.toUpperCase()}</span>
        <span class="alert-timestamp">${ts}</span>
      </div>
      <div class="alert-summary">${a.summary || "no summary"}</div>
      ${evidenceHtml}
      ${metaHtml}
      <div>${feedbackHtml}</div>
    </div>`;
}

async function sendFeedback(id, feedback) {
  const result = await apiPost(`/api/alerts/${id}/feedback`, { feedback });
  if (result && result.status === "ok") {
    renderAlerts();
    renderStats();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  updateClock();
  setInterval(updateClock, 1000);

  renderHealth();
  renderStats();
  renderAlerts();

  document.querySelectorAll(".severity-pill").forEach((el) => {
    el.addEventListener("click", () => {
      setSeverityFilter(el.dataset.severity);
      renderAlerts();
    });
  });

  const refreshBtn = document.getElementById("refresh-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", () => { renderAlerts(); renderStats(); });

  const viewToggle = document.getElementById("view-toggle");
  const viewTimelineBtn = document.getElementById("view-timeline-btn");

  function setView(view) {
    currentView = view;
    if (viewToggle) viewToggle.classList.toggle("active", view === "cards");
    if (viewTimelineBtn) viewTimelineBtn.classList.toggle("active", view === "timeline");
    renderAlerts();
  }

  if (viewToggle) viewToggle.addEventListener("click", () => setView("cards"));
  if (viewTimelineBtn) viewTimelineBtn.addEventListener("click", () => setView("timeline"));

  const filterSince = document.getElementById("filter-since");
  if (filterSince) filterSince.addEventListener("change", () => renderAlerts());

  setInterval(() => {
    renderStats();
    renderAlerts();
    renderHealth();
  }, 15000);
});
