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
  const { dashboard, cases, approvals, workflows, connectors, writebacks, scenarios } = state.data;
  const metrics = [
    ["Cases created", dashboard.metrics.cases_created, "durable"],
    ["Pending approval", dashboard.metrics.approvals_pending, "human review"],
    ["MTTA", `${dashboard.mtta_seconds.toFixed(0)}s`, "current"],
    ["Escalation accuracy", `${(dashboard.escalation_accuracy * 100).toFixed(0)}%`, "feedback based"],
  ];
  $("#metrics").innerHTML = metrics.map(([label, value, note]) => `<div class="metric"><small>${label}</small><strong>${value}</strong><span>${note}</span></div>`).join("");
  $("#scenarios").innerHTML = scenarios.map((item) => `<article class="scenario"><span class="source-tag">${item.event.source}</span><h3>${item.title}</h3><p>${item.description}</p><button class="button secondary small" data-scenario="${item.id}">Run scenario</button></article>`).join("");

  const caseRows = [...cases].reverse().map((item) => `<tr><td><span class="case-title">${item.title}</span><span class="case-id">${item.id}</span></td><td>${badge(item.severity)}</td><td>${badge(item.status)}</td><td>${item.evidence.length}</td></tr>`).join("");
  const caseTable = cases.length ? `<table><thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Evidence</th></tr></thead><tbody>${caseRows}</tbody></table>` : empty("No cases yet. Run a scenario to create one.");
  $("#recentCases").innerHTML = cases.length ? `<table><tbody>${[...cases].reverse().slice(0, 4).map((item) => `<tr><td><span class="case-title">${item.title}</span><span class="case-id">${shortId(item.id)}</span></td><td>${badge(item.severity)}</td><td>${badge(item.status)}</td></tr>`).join("")}</tbody></table>` : empty("No cases yet.");
  $("#caseTable").innerHTML = caseTable;

  const pending = approvals.filter((item) => item.status === "pending");
  $("#approvalCount").textContent = pending.length;
  $("#approvals").innerHTML = pending.length ? pending.slice(0, 4).map((item) => `<div class="approval"><strong>${item.action.name}</strong><small>${shortId(item.case_id)} · risk ${item.action.risk_level}</small><div class="approval-actions"><button class="button primary small" data-approval="${item.id}" data-decision="true">Approve</button><button class="button secondary small" data-approval="${item.id}" data-decision="false">Reject</button></div></div>`).join("") : empty("No actions waiting for review.");

  $("#workflowTable").innerHTML = workflows.length ? `<table><thead><tr><th>Workflow</th><th>Status</th><th>Attempts</th><th>Case</th></tr></thead><tbody>${[...workflows].reverse().map((item) => `<tr><td><span class="case-id">${item.id}</span></td><td>${badge(item.status)}</td><td>${item.attempts}</td><td><span class="case-id">${shortId(item.result_case_id)}</span></td></tr>`).join("")}</tbody></table>` : empty("No asynchronous workflows yet.");
  $("#connectors").innerHTML = connectors.map((item) => `<article class="connector"><div><strong>${item.name.replaceAll("_", " ")}</strong><small>${item.type} · ${item.mode}</small></div><span class="connector-state">${item.status}</span></article>`).join("");
  $("#writebackTable").innerHTML = writebacks.length ? `<table><thead><tr><th>Target</th><th>Status</th><th>Case</th><th>Attempts</th></tr></thead><tbody>${[...writebacks].reverse().map((item) => `<tr><td><strong>${item.target.toUpperCase()}</strong></td><td>${badge(item.status)}</td><td><span class="case-id">${shortId(item.case_id)}</span></td><td>${item.attempts}</td></tr>`).join("")}</tbody></table>` : empty("The writeback queue is empty.");

  $$('[data-scenario]').forEach((button) => button.onclick = () => runScenario(button.dataset.scenario));
  $$('[data-approval]').forEach((button) => button.onclick = () => decideApproval(button.dataset.approval, button.dataset.decision === "true"));
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
  const titles = { overview: "Operations overview", cases: "Investigation cases", workflows: "Workflow operations", integrations: "Integration health" };
  $("#pageTitle").textContent = titles[name];
}
$$('[data-view]').forEach((button) => button.onclick = () => selectView(button.dataset.view));
$$('[data-go]').forEach((button) => button.onclick = () => selectView(button.dataset.go));
if (state.key) { $("#apiKey").value = state.key; connect(); }
