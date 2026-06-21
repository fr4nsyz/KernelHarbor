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

function renderHealth() {
  apiFetch("/health").then(data => {
    const el = document.getElementById("health-status");
    if (data && data.status === "ok") {
      el.textContent = "connected";
      el.className = "health ok";
    } else {
      el.textContent = "unavailable";
      el.className = "health error";
    }
  });
}

function renderStats() {
  apiFetch("/api/alerts/stats").then(data => {
    if (!data) {
      document.querySelectorAll(".stat-value").forEach(el => el.textContent = "-");
      return;
    }
    document.getElementById("stat-total").textContent = data.alerts_24h ?? "-";
    document.getElementById("stat-malicious").textContent = data.malicious ?? "-";
    document.getElementById("stat-suspicious").textContent = data.suspicious ?? "-";
    document.getElementById("stat-confirmed").textContent = data.confirmed ?? "-";
    document.getElementById("stat-fp").textContent = data.false_positives ?? "-";
  });
}

function renderAlerts() {
  const verdict = document.getElementById("filter-verdict").value;
  const since = document.getElementById("filter-since").value;
  const limit = document.getElementById("filter-limit").value;
  const listEl = document.getElementById("alert-list");

  listEl.innerHTML = '<div class="loading">Loading alerts...</div>';

  apiFetch(`/api/alerts?since=${since}&min_verdict=${verdict}&limit=${limit}`).then(data => {
    if (!data) {
      listEl.innerHTML = '<div class="error">Failed to fetch alerts</div>';
      return;
    }

    const alerts = data.alerts || [];
    if (alerts.length === 0) {
      listEl.innerHTML = '<div class="empty">No alerts matching filters</div>';
      return;
    }

    listEl.innerHTML = alerts.map(a => renderAlertCard(a)).join("");

    alerts.forEach(a => {
      const confirmBtn = document.getElementById(`confirm-${a.id}`);
      const fpBtn = document.getElementById(`fp-${a.id}`);
      if (confirmBtn) confirmBtn.addEventListener("click", () => sendFeedback(a.id, "confirmed"));
      if (fpBtn) fpBtn.addEventListener("click", () => sendFeedback(a.id, "false_positive"));
    });
  });
}

function renderAlertCard(a) {
  const ts = a.timestamp ? new Date(a.timestamp).toLocaleString() : "";
  const confidence = a.confidence != null ? `confidence: ${(a.confidence * 100).toFixed(0)}%` : "";
  const source = a.source || "";
  const host = a["host.name"] || "";
  const model = a["model.used"] || "";
  const evidence = Array.isArray(a.evidence) ? a.evidence : [];

  let feedbackHtml = "";
  if (a.feedback) {
    feedbackHtml = `<span class="alert-feedback">${a.feedback === "confirmed" ? "✓ confirmed" : "✗ false positive"}</span>`;
  } else {
    feedbackHtml = `
      <div class="alert-actions">
        <button class="btn btn-sm btn-success" id="confirm-${a.id}">Confirm</button>
        <button class="btn btn-sm btn-danger" id="fp-${a.id}">False +</button>
      </div>`;
  }

  const evidenceHtml = evidence.length > 0
    ? `<div class="alert-meta"><strong>Evidence:</strong> ${evidence.join("; ")}</div>`
    : "";

  return `
    <div class="alert-card">
      <div class="alert-header">
        <span class="alert-verdict ${a.verdict}">${a.verdict}</span>
        <span class="alert-meta">${ts}</span>
      </div>
      <div class="alert-summary">${a.summary || "no summary"}</div>
      ${evidenceHtml}
      <div class="alert-meta">
        ${host ? `<span>host: ${host}</span>` : ""}
        ${source ? `<span>source: ${source}</span>` : ""}
        ${source === "llm" && model ? `<span>model: ${model}</span>` : ""}
        ${confidence ? `<span>${confidence}</span>` : ""}
      </div>
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
  renderHealth();
  renderStats();
  renderAlerts();

  document.getElementById("refresh-btn").addEventListener("click", () => {
    renderAlerts();
    renderStats();
  });

  setInterval(() => {
    renderStats();
    renderAlerts();
  }, 15000);
});
