const state = { key: localStorage.getItem("agentic-soc-key") || "", data: {} };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-API-Key": state.key, ...(options.headers || {}) },
  });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || `Request failed: ${response.status}`);
  return response.json();
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  setTimeout(() => element.classList.remove("show"), 2600);
}

const badge = (value) => `<span class="badge ${String(value).toLowerCase()}">${value}</span>`;
const empty = (message) => `<div class="empty">${message}</div>`;
const shortId = (value) => value ? `${value.slice(0, 11)}…` : "—";

function render() {
  $("#authPanel").hidden = Boolean(state.key);
  $("#workspace").hidden = !state.key;
  const { dashboard, cases, approvals, workflows, connectors, writebacks, scenarios } = state.data;
  const metrics = [
    ["Open investigations", dashboard.metrics.cases_created, "All durable cases", "64%"],
    ["Pending decisions", dashboard.metrics.approvals_pending, "Human approval", "42%"],
    ["Mean time to assess", `${dashboard.mtta_seconds.toFixed(1)}s`, "Current window", "77%"],
    ["Escalation precision", `${(dashboard.escalation_accuracy * 100).toFixed(0)}%`, "Analyst verified", "96%"],
  ];
  $("#metrics").innerHTML = metrics.map(([label, value, note, width]) => `<div class="metric"><div class="metric-head"><small>${label}</small><span class="metric-trend">Live</span></div><div class="metric-value"><strong>${value}</strong><span class="metric-note">${note}</span></div><div class="metric-line"><span style="width:${width}"></span></div></div>`).join("");
  $("#caseNavCount").textContent = cases.length;
  $("#lastEventTime").textContent = cases.length ? "Less than 1 min" : "No events";
  $("#scenarios").innerHTML = scenarios.map((item, index) => `<article class="scenario"><span class="scenario-index">0${index + 1}</span><div><span class="source-tag">${item.event.source}</span><h3>${item.title}</h3><p>${item.description}</p></div><button class="button secondary small" data-scenario="${item.id}">Execute</button></article>`).join("");

  const renderCaseRow = (item) => {
    const entities = item.entities.map((entity) => entity.id).slice(0, 2).join(" · ") || "No entities";
    return `<tr><td><div class="case-cell"><i class="severity-rail ${item.severity}"></i><div><span class="case-title">${item.title}</span><span class="case-id">${shortId(item.id)}</span></div></div></td><td>${badge(item.severity)}</td><td>${badge(item.status)}</td><td><span class="entity-list">${entities}</span></td><td>${item.evidence.length}</td></tr>`;
  };
  const caseRows = [...cases].reverse().map(renderCaseRow).join("");
  const tableHead = `<thead><tr><th>Investigation</th><th>Severity</th><th>State</th><th>Primary entities</th><th>Evidence</th></tr></thead>`;
  const caseTable = cases.length ? `<table>${tableHead}<tbody>${caseRows}</tbody></table>` : empty("No cases yet. Run a validation scenario to create one.");
  $("#recentCases").innerHTML = cases.length ? `<table>${tableHead}<tbody>${[...cases].reverse().slice(0, 6).map(renderCaseRow).join("")}</tbody></table>` : empty("No active investigations.");
  $("#caseTable").innerHTML = caseTable;

  const pending = approvals.filter((item) => item.status === "pending");
  $("#approvalCount").textContent = pending.length;
  $("#approvals").innerHTML = pending.length ? pending.slice(0, 4).map((item) => `<div class="approval"><div class="approval-top"><div><strong>${item.action.name}</strong><small>${shortId(item.case_id)} · ${item.action.target?.id || "case action"}</small></div><span class="risk-level">L${item.action.risk_level}</span></div><div class="approval-actions"><button class="button primary small" data-approval="${item.id}" data-decision="true">Approve</button><button class="button secondary small" data-approval="${item.id}" data-decision="false">Deny</button></div></div>`).join("") : empty("No actions require analyst review.");

  const severities = { critical: 0, high: 0, medium: 0, low: 0 };
  cases.forEach((item) => { severities[item.severity] = (severities[item.severity] || 0) + 1; });
  const riskTotal = Math.max(1, cases.length);
  const riskScore = Math.min(99, Math.round((severities.critical * 100 + severities.high * 80 + severities.medium * 45 + severities.low * 15) / riskTotal));
  $("#riskChart").innerHTML = `<div class="risk-summary"><div class="risk-score"><div><strong>${riskScore}</strong><small>Risk index</small></div></div><div class="risk-breakdown">${[["High", severities.critical + severities.high, "high"], ["Medium", severities.medium, "medium"], ["Low", severities.low, "low"]].map(([label, count, level]) => `<div class="risk-row ${level}"><span>${label}</span><div class="risk-bar"><i style="width:${Math.max(4, Number(count) / riskTotal * 100)}%"></i></div><strong>${count}</strong></div>`).join("")}</div></div>`;

  $("#workflowTable").innerHTML = workflows.length ? `<table><thead><tr><th>Workflow ID</th><th>Execution state</th><th>Attempts</th><th>Result case</th><th>Last error</th></tr></thead><tbody>${[...workflows].reverse().map((item) => `<tr><td><span class="case-id">${item.id}</span></td><td>${badge(item.status)}</td><td>${item.attempts} / 3</td><td><span class="case-id">${shortId(item.result_case_id)}</span></td><td>${item.error || "—"}</td></tr>`).join("")}</tbody></table>` : empty("No asynchronous workflow executions recorded.");
  $("#connectors").innerHTML = connectors.map((item) => `<article class="connector"><div><strong>${item.name.replaceAll("_", " ")}</strong><small>${item.type} · ${item.mode}<br>${item.capabilities.join(" · ") || "health monitoring"}</small></div><span class="connector-state">● ${item.status}</span></article>`).join("");
  $("#writebackTable").innerHTML = writebacks.length ? `<table><thead><tr><th>Destination</th><th>Delivery state</th><th>Case reference</th><th>Attempts</th><th>Error</th></tr></thead><tbody>${[...writebacks].reverse().map((item) => `<tr><td><strong>${item.target.toUpperCase()}</strong></td><td>${badge(item.status)}</td><td><span class="case-id">${shortId(item.case_id)}</span></td><td>${item.attempts}</td><td>${item.last_error || "—"}</td></tr>`).join("")}</tbody></table>` : empty("The delivery queue is empty.");

  $$('[data-scenario]').forEach((button) => button.onclick = () => runScenario(button.dataset.scenario));
  $$('[data-approval]').forEach((button) => button.onclick = () => decideApproval(button.dataset.approval, button.dataset.decision === "true"));
  const filterRows = (container, value) => {
    const needle = value.toLowerCase();
    $$(`${container} tbody tr`).forEach((row) => { row.hidden = !row.textContent.toLowerCase().includes(needle); });
  };
  $("#incidentSearch").oninput = (event) => filterRows("#recentCases", event.target.value);
  $("#caseSearch").oninput = (event) => filterRows("#caseTable", event.target.value);
  $$("#incidentFilters button").forEach((button) => button.onclick = () => {
    $$("#incidentFilters button").forEach((item) => item.classList.toggle("active", item === button));
    const value = button.dataset.filter === "all" ? "" : button.dataset.filter === "pending" ? "awaiting_approval" : button.dataset.filter;
    filterRows("#recentCases", value);
  });
}

async function refresh(showToast = false) {
  const endpoints = ["dashboard", "cases", "approvals", "workflows", "connectors", "writebacks", "harness/scenarios"];
  const values = await Promise.all(endpoints.map((path) => api(`/${path}`)));
  state.data = Object.fromEntries(endpoints.map((path, index) => [path.replace("harness/", ""), values[index]]));
  render();
  $("#lastSync").textContent = `Synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  $("#runtimeStatus").textContent = "Database connected";
  if (showToast) toast("Console refreshed");
}

async function connect() {
  state.key = $("#apiKey").value.trim();
  try {
    await api("/health");
    localStorage.setItem("agentic-soc-key", state.key);
    $("#authPanel").hidden = true;
    $("#workspace").hidden = false;
    await refresh();
  } catch (error) { toast(error.message); }
}

async function runScenario(id) {
  try {
    await api(`/harness/scenarios/${id}/run`, { method: "POST" });
    await refresh();
    toast("Scenario analyzed and persisted");
  } catch (error) { toast(error.message); }
}

async function decideApproval(id, approved) {
  try {
    await api(`/approvals/${id}/decision`, { method: "POST", body: JSON.stringify({ approved, decided_by: "console-analyst", notes: "Decision from operator console" }) });
    await refresh();
    toast(approved ? "Action approved" : "Action rejected");
  } catch (error) { toast(error.message); }
}

$("#authForm").addEventListener("submit", (event) => { event.preventDefault(); connect(); });
$("#refreshButton").onclick = () => refresh(true).catch((error) => toast(error.message));
$("#dispatchButton").onclick = async () => { try { const delivered = await api("/writebacks/dispatch", { method: "POST" }); await refresh(); toast(`${delivered.length} writebacks dispatched`); } catch (error) { toast(error.message); } };
$("#newAlertButton").onclick = () => $("#alertDialog").showModal();
$("#closeDialog").onclick = $("#cancelDialog").onclick = () => $("#alertDialog").close();
$("#alertForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  const payload = { source: data.get("source"), name: data.get("name"), category: "manual_ingest", severity: data.get("severity"), entities: [{ type: data.get("entityType"), id: data.get("entityId") }], description: data.get("description") };
  try { await api("/events/sync", { method: "POST", body: JSON.stringify(payload) }); $("#alertDialog").close(); await refresh(); toast("Alert analyzed and persisted"); } catch (error) { toast(error.message); }
});

function selectView(name) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `${name}View`));
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  const titles = { overview: "Command center", cases: "Investigations", workflows: "Automation", integrations: "Data fabric" };
  $("#pageTitle").textContent = titles[name];
  $("#breadcrumbCurrent").textContent = titles[name];
}
$$('[data-view]').forEach((button) => button.onclick = () => selectView(button.dataset.view));
$$('[data-go]').forEach((button) => button.onclick = () => selectView(button.dataset.go));
if (state.key) { $("#apiKey").value = state.key; connect(); }
