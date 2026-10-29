const DATA_URL = "/data/dashboard.json";
const DECISIONS_KEY = "sentinel-ai-demo-decisions";
const viewTitles = {
  overview: "SOC Overview",
  campaigns: "Threat Campaigns",
  telemetry: "Threat Telemetry",
  inspector: "URL Threat Inspector",
  approvals: "Human Approval Center",
};

const root = document.querySelector("#view-root");
const title = document.querySelector("#page-title");
const errorBox = document.querySelector("#load-error");
let dashboard;
let currentView = "overview";

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function decisions() {
  try {
    const stored = JSON.parse(localStorage.getItem(DECISIONS_KEY) || "{}");
    return stored && typeof stored === "object" && !Array.isArray(stored) ? stored : {};
  } catch {
    return {};
  }
}

function saveDecision(actionId, value) {
  const current = decisions();
  current[actionId] = value;
  localStorage.setItem(DECISIONS_KEY, JSON.stringify(current));
}

function incidentCard(incident) {
  const card = element("article", "incident-card");
  const top = element("div", "incident-top");
  const heading = element("h3", "", incident.title || "Threat incident");
  const severity = element("span", `severity severity-${String(incident.severity || "medium").toLowerCase()}`, incident.severity || "MEDIUM");
  top.append(heading, severity);
  const meta = element("div", "incident-meta");
  meta.append(
    element("span", "tag", incident.campaign_tag || "Unclassified"),
    element("span", "risk", `Risk ${Math.round(incident.risk_score || 0)}/100`),
    element("span", "", incident.primary_user || "User unavailable"),
    element("span", "", incident.primary_device || "Device unavailable"),
  );
  card.append(top, meta);

  const explanation = incident.explanation || {};
  const relationships = explanation.inferred_relationships || [];
  if (relationships.length) card.append(element("p", "incident-description", relationships[0]));
  const ruleIds = incident.rule_ids || [];
  if (ruleIds.length) card.append(element("p", "subtle", `Rules: ${ruleIds.join(", ")}`));
  return card;
}

function metric(label, value, hint, color = "") {
  const card = element("article", "metric");
  card.append(
    element("div", "metric-label", label),
    element("div", `metric-value ${color}`, String(value)),
    element("div", "metric-hint", hint),
  );
  return card;
}

function panelHeading(parent, heading, subtitle) {
  const header = element("div", "panel-heading");
  const text = element("div");
  text.append(element("h2", "", heading));
  if (subtitle) text.append(element("p", "panel-subtitle", subtitle));
  header.append(text);
  parent.append(header);
}

function renderSources(parent) {
  const counts = dashboard.events.reduce((result, event) => {
    result[event.source] = (result[event.source] || 0) + 1;
    return result;
  }, {});
  const max = Math.max(1, ...Object.values(counts));
  const bars = element("div", "source-bars");
  for (const source of ["EMAIL", "AUTH", "NETWORK"]) {
    const row = element("div", "source-line");
    const track = element("div", "bar-track");
    const fill = element("div", "bar-fill");
    fill.style.width = `${(counts[source] || 0) / max * 100}%`;
    track.append(fill);
    row.append(element("span", "", source), track, element("span", "bar-count", String(counts[source] || 0)));
    bars.append(row);
  }
  parent.append(bars);
}

function renderOverview() {
  const metrics = dashboard.metrics || {};
  const pending = dashboard.incidents.flatMap((incident) => incident.recommended_actions || [])
    .filter((action) => !decisions()[action.action_id]).length;
  const grid = element("div", "metrics-grid");
  grid.append(
    metric("Telemetry events", dashboard.events.length, "Email, identity and network"),
    metric("Correlated incidents", dashboard.incidents.length, "Detected from sample scenario", "amber"),
    metric("Critical / high", dashboard.incidents.filter((item) => ["CRITICAL", "HIGH"].includes(item.severity)).length, "Prioritized for analyst review", "red"),
    metric("Pending reviews", pending, "Simulated actions only", "blue"),
  );
  root.append(grid);

  const columns = element("div", "content-grid");
  const incidents = element("section", "panel");
  panelHeading(incidents, "Priority incidents", "Correlated multi-source campaigns");
  const list = element("div", "incident-list");
  dashboard.incidents.slice(0, 4).forEach((item) => list.append(incidentCard(item)));
  incidents.append(list);
  const sources = element("section", "panel");
  panelHeading(sources, "Telemetry sources", "Distribution in the demo data");
  renderSources(sources);

  const metricsPanel = element("section", "panel");
  metricsPanel.style.marginTop = "14px";
  panelHeading(metricsPanel, "Synthetic benchmark", "Measured against the included ground truth");
  const benchmarkGrid = element("div", "metrics-grid");
  benchmarkGrid.style.gridTemplateColumns = "repeat(3, minmax(0, 1fr))";
  benchmarkGrid.append(
    metric("Precision", `${Math.round((metrics.precision || 0) * 100)}%`, "Synthetic campaigns", "green"),
    metric("Recall", `${Math.round((metrics.recall || 0) * 100)}%`, `${metrics.campaigns_detected || 0} campaigns detected`, "green"),
    metric("False-positive rate", `${Math.round((metrics.false_positive_rate || 0) * 100)}%`, "Synthetic benign events", "blue"),
  );
  metricsPanel.append(benchmarkGrid, element("p", "subtle", metrics.disclaimer || ""));
  columns.append(incidents, sources);
  root.append(columns, metricsPanel);
}

function renderCampaigns() {
  root.append(element("p", "panel-subtitle", `${dashboard.incidents.length} correlated incidents from the synthetic telemetry set.`));
  const list = element("div", "incident-list");
  dashboard.incidents.forEach((incident) => {
    const card = incidentCard(incident);
    const events = incident.correlated_events || [];
    if (events.length) {
      const evidence = element("div", "incident-meta");
      evidence.append(element("strong", "", "Correlated evidence:"));
      events.forEach((event) => evidence.append(element("span", "source-pill", `${event.source} · ${event.event_id}`)));
      card.append(evidence);
    }
    const timeline = incident.timeline || [];
    if (timeline.length) {
      const details = element("details");
      details.style.marginTop = "12px";
      details.append(element("summary", "text-button", "View campaign timeline"));
      const timelineList = element("ul", "findings");
      timeline.forEach((item) => {
        const description = item.summary || item.description || item.stage || JSON.stringify(item);
        timelineList.append(element("li", "", `${item.timestamp || ""} ${description}`.trim()));
      });
      details.append(timelineList);
      card.append(details);
    }
    list.append(card);
  });
  root.append(list);
}

function renderTelemetry() {
  const toolbar = element("div", "toolbar");
  const search = element("input", "field");
  search.type = "search";
  search.placeholder = "Search user, IP, event or summary";
  search.setAttribute("aria-label", "Search telemetry");
  const source = element("select", "select-field");
  source.setAttribute("aria-label", "Filter by source");
  ["All sources", "EMAIL", "AUTH", "NETWORK"].forEach((value) => {
    const option = element("option", "", value);
    option.value = value === "All sources" ? "" : value;
    source.append(option);
  });
  toolbar.append(search, source);
  root.append(toolbar);
  const count = element("p", "subtle");
  root.append(count);
  const wrap = element("div", "table-wrap");
  const table = element("table");
  const thead = element("thead");
  const headerRow = element("tr");
  ["Event", "Time", "Source", "User", "Device", "Indicator", "Summary"].forEach((label) => headerRow.append(element("th", "", label)));
  thead.append(headerRow);
  const tbody = element("tbody");
  table.append(thead, tbody);
  wrap.append(table);
  root.append(wrap);

  function updateTable() {
    const query = search.value.trim().toLowerCase();
    const selectedSource = source.value;
    const filtered = dashboard.events.filter((event) => {
      const matchesSource = !selectedSource || event.source === selectedSource;
      const searchable = [event.event_id, event.user_id, event.device_id, event.ip_address, event.summary, event.scenario_tag].join(" ").toLowerCase();
      return matchesSource && (!query || searchable.includes(query));
    });
    count.textContent = `Showing ${filtered.length} of ${dashboard.events.length} events`;
    tbody.replaceChildren();
    filtered.forEach((event) => {
      const row = element("tr");
      [
        event.event_id,
        event.timestamp,
        event.source,
        event.user_id || "—",
        event.device_id || "—",
        event.ip_address || "—",
        event.summary || "",
      ].forEach((value, index) => {
        const cell = element("td", index < 3 ? "mono" : index === 6 ? "table-summary" : "", value);
        row.append(cell);
      });
      tbody.append(row);
    });
  }
  search.addEventListener("input", updateTable);
  source.addEventListener("change", updateTable);
  updateTable();
}

const suspiciousTlds = [".xyz", ".top", ".buzz", ".live", ".fit", ".ru", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click", ".icu", ".link", ".online", ".site", ".pw"];
const phishingKeywords = ["login", "signin", "verify", "credential", "account", "update", "banking", "secure", "wallet", "reset", "password", "billing", "invoice", "bonus", "auth", "token", "support", "helpdesk", "renewal", "payroll"];
const spoofPatterns = [
  ["paypa1", "PayPal lookalike"], ["micros0ft", "Microsoft lookalike"], ["goog1e", "Google lookalike"],
  ["app1e", "Apple lookalike"], ["amaz0n", "Amazon lookalike"], ["netf1ix", "Netflix lookalike"],
  ["0kta", "Okta lookalike"], ["c0rp", "Corporate lookalike"],
];

function inspectUrl(value) {
  let url = value.trim();
  if (!url) return { url, risk_score: 0, verdict: "BENIGN / SAFE", findings: ["Enter a URL to inspect."] };
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { url, risk_score: 50, verdict: "SUSPICIOUS", findings: ["Malformed URL syntax"] };
  }
  const hostname = parsed.hostname.toLowerCase();
  const full = url.toLowerCase();
  const findings = [];
  let score = 0;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    findings.push(`Host uses raw numeric IP address instead of domain: ${hostname}`);
    score += 35;
  }
  const tld = suspiciousTlds.find((item) => hostname.endsWith(item));
  if (tld) {
    findings.push(`High-risk untrusted top-level domain: ${tld}`);
    score += 30;
  }
  spoofPatterns.forEach(([pattern, description]) => {
    if (hostname.includes(pattern)) {
      findings.push(`Typosquatting/brand spoofing detected: ${description} ('${pattern}')`);
      score += 40;
    }
  });
  const matches = phishingKeywords.filter((keyword) => full.includes(keyword));
  if (matches.length) {
    findings.push(`Social engineering / credential harvesting keywords: ${matches.slice(0, 4).join(", ")}`);
    score += Math.min(matches.length * 15, 35);
  }
  if (url.toLowerCase().startsWith("http://")) {
    findings.push("Insecure plain HTTP protocol (lacks TLS encryption)");
    score += 10;
  }
  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    findings.push(`Non-standard web port in URL: :${parsed.port}`);
    score += 25;
  }
  if (url.includes("@")) {
    findings.push("URL contains '@' symbol (user-info obfuscation technique)");
    score += 35;
  }
  if ((hostname.match(/\./g) || []).length >= 4) {
    findings.push(`Excessive subdomain depth (${(hostname.match(/\./g) || []).length} levels)`);
    score += 15;
  }
  score = Math.min(100, score);
  return {
    url: value,
    normalized_url: url,
    hostname,
    risk_score: score,
    verdict: score >= 70 ? "MALICIOUS / PHISHING" : score >= 35 ? "SUSPICIOUS" : "BENIGN / SAFE",
    findings,
  };
}

function renderInspector() {
  const panel = element("section", "panel");
  panelHeading(panel, "Inspect a URL", "Heuristic checks run locally in your browser; the URL is not sent to a server.");
  const form = element("form", "form-row");
  const input = element("input", "field");
  input.type = "text";
  input.placeholder = "https://example.com/login";
  input.setAttribute("aria-label", "URL to inspect");
  input.required = true;
  const submit = element("button", "primary-button", "Inspect URL");
  submit.type = "submit";
  form.append(input, submit);
  panel.append(form);
  const presets = element("div", "toolbar");
  presets.style.marginTop = "13px";
  [
    ["Brand spoof", "http://paypa1-security-login.xyz/verify/account?token=8923"],
    ["Raw IP and port", "http://198.51.100.45:8080/admin/reset-password"],
    ["Benign SaaS", "https://app.slack.com/client/T024/C02"],
  ].forEach(([label, value]) => {
    const button = element("button", "secondary-button", label);
    button.type = "button";
    button.addEventListener("click", () => {
      input.value = value;
      showResult(inspectUrl(value));
    });
    presets.append(button);
  });
  panel.append(presets);
  const result = element("div", "scan-result");
  panel.append(result);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    showResult(inspectUrl(input.value));
  });

  function showResult(analysis) {
    result.replaceChildren();
    const heading = element("div", "incident-top");
    heading.append(
      element("h3", "", analysis.verdict),
      element("span", "risk", `Risk ${analysis.risk_score}/100`),
    );
    const scoreTrack = element("div", "score-track");
    const scoreFill = element("div", "score-fill");
    scoreFill.style.width = `${analysis.risk_score}%`;
    scoreTrack.append(scoreFill);
    const target = element("p", "subtle", `Target: ${analysis.normalized_url || analysis.url}`);
    const findings = element("ul", "findings");
    analysis.findings.forEach((finding) => findings.append(element("li", "", finding)));
    result.append(heading, scoreTrack, target, findings);
  }
  root.append(panel);
}

function renderApprovals() {
  const prior = decisions();
  const actions = dashboard.incidents.flatMap((incident) =>
    (incident.recommended_actions || []).map((action) => ({ action, incident })),
  );
  const pending = actions.filter(({ action }) => !prior[action.action_id]);
  const history = actions.filter(({ action }) => prior[action.action_id]);
  root.append(element("p", "panel-subtitle", "All actions below are simulated. Decisions are kept in this browser only and are not shared with other users."));
  const pendingHeading = element("div", "section-heading");
  pendingHeading.append(element("h2", "", `Pending actions (${pending.length})`));
  root.append(pendingHeading);
  const pendingList = element("div", "approval-list");
  if (!pending.length) pendingList.append(element("div", "empty-state", "No pending demo actions. Clear this browser's site data to reset the local review history."));
  pending.forEach(({ action, incident }) => {
    const card = element("article", "approval-card");
    const top = element("div", "incident-top");
    top.append(element("h3", "", action.action_type || "SIMULATED_ACTION"), element("span", "severity severity-high", "PENDING REVIEW"));
    card.append(top);
    card.append(element("p", "incident-meta", `Target: ${action.target_entity || "—"} · Incident: ${incident.incident_id}`));
    if (action.description) card.append(element("p", "incident-description", action.description));
    const controls = element("div", "action-row");
    controls.style.justifyContent = "flex-start";
    const reviewer = element("input", "field");
    reviewer.value = "SOC Analyst";
    reviewer.setAttribute("aria-label", "Reviewer name");
    const notes = element("input", "field");
    notes.placeholder = "Decision notes (optional)";
    notes.setAttribute("aria-label", "Decision notes");
    const approve = element("button", "decision-button", "Approve (simulate)");
    const reject = element("button", "decision-button reject", "Reject");
    approve.addEventListener("click", () => record(action, incident, "APPROVE", reviewer.value, notes.value));
    reject.addEventListener("click", () => record(action, incident, "REJECT", reviewer.value, notes.value));
    controls.append(reviewer, notes, approve, reject);
    card.append(controls);
    pendingList.append(card);
  });
  root.append(pendingList);

  if (history.length) {
    const heading = element("div", "section-heading");
    heading.append(element("h2", "", `This browser's review history (${history.length})`));
    root.append(heading);
    const historyList = element("div", "approval-list");
    history.forEach(({ action, incident }) => {
      const item = prior[action.action_id];
      const card = element("article", "approval-card");
      card.append(
        element("div", "incident-top"),
      );
      const top = card.lastChild;
      top.append(element("h3", "", action.action_type || "SIMULATED_ACTION"), element("span", "tag", item.decision));
      card.append(element("p", "incident-meta", `${action.target_entity || "—"} · ${incident.incident_id} · ${item.reviewer || "SOC Analyst"}`));
      card.append(element("p", "incident-description", item.note || "No reviewer note."));
      historyList.append(card);
    });
    root.append(historyList);
  }
}

function record(action, incident, decision, reviewer, note) {
  const confirmed = decision === "REJECT" || window.confirm(
    `Approve simulated ${action.action_type} for ${action.target_entity || "this target"}? No real-world action will occur.`,
  );
  if (!confirmed) return;
  saveDecision(action.action_id, {
    decision,
    reviewer: reviewer.trim() || "SOC Analyst",
    note: note.trim(),
    incident_id: incident.incident_id,
    decided_at: new Date().toISOString(),
    simulation: true,
  });
  render();
}

function render() {
  if (!dashboard) return;
  title.textContent = viewTitles[currentView];
  root.replaceChildren();
  if (currentView === "overview") renderOverview();
  if (currentView === "campaigns") renderCampaigns();
  if (currentView === "telemetry") renderTelemetry();
  if (currentView === "inspector") renderInspector();
  if (currentView === "approvals") renderApprovals();
}

async function loadDashboard() {
  errorBox.hidden = true;
  try {
    const response = await fetch(DATA_URL, { cache: "no-store" });
    if (!response.ok) throw new Error(`Could not load demo data (HTTP ${response.status}).`);
    dashboard = await response.json();
    if (!Array.isArray(dashboard.events) || !Array.isArray(dashboard.incidents)) {
      throw new Error("The demo data file has an invalid format.");
    }
    render();
  } catch (error) {
    errorBox.textContent = `${error.message} Check that public/data/dashboard.json exists and reload the page.`;
    errorBox.hidden = false;
  }
}

document.querySelectorAll(".nav-link").forEach((button) => {
  button.addEventListener("click", () => {
    currentView = button.dataset.view;
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.toggle("active", item === button));
    render();
  });
});
document.querySelector("#refresh-button").addEventListener("click", loadDashboard);
loadDashboard();
