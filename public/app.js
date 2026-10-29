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
let adminSession = { configured: false, authenticated: false };

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error(`Backend returned an invalid response (HTTP ${response.status}).`);
  }
  if (!response.ok) throw new Error(result.detail || `Request failed (HTTP ${response.status}).`);
  return result;
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
  const pending = dashboard.incidents.flatMap((incident) => incident.recommended_actions || []).length;
  const grid = element("div", "metrics-grid");
  grid.append(
    metric("Telemetry events", dashboard.events.length, "Email, identity and network"),
    metric("Correlated incidents", dashboard.incidents.length, "Detected from sample scenario", "amber"),
    metric("Critical / high", dashboard.incidents.filter((item) => ["CRITICAL", "HIGH"].includes(item.severity)).length, "Prioritized for analyst review", "red"),
    metric("Response actions", pending, "Available in admin approval center", "blue"),
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

function renderInspector() {
  const panel = element("section", "panel");
  panelHeading(panel, "Inspect a URL", "The Python detection API analyzes this URL using Sentinel's phishing heuristics.");
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
      inspect(value);
    });
    presets.append(button);
  });
  panel.append(presets);
  const result = element("div", "scan-result");
  panel.append(result);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    inspect(input.value);
  });

  async function inspect(value) {
    result.replaceChildren();
    result.append(element("p", "subtle", "Sending URL to the Sentinel Python API…"));
    let analysis;
    try {
      analysis = await apiRequest("/api/inspect", {
        method: "POST",
        body: JSON.stringify({ url: value }),
      });
    } catch (error) {
      result.replaceChildren(element("div", "notice error", error.message));
      return;
    }
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

  const emailPanel = element("section", "panel");
  emailPanel.style.marginTop = "14px";
  panelHeading(emailPanel, "Inspect a suspicious email", "Evaluate sender, subject, authentication results, attachments, and links against the server-side email rules.");
  const emailForm = element("form");
  const emailGrid = element("div", "content-grid");
  emailGrid.style.gridTemplateColumns = "repeat(2, minmax(0, 1fr))";
  const emailInputs = {};
  for (const [name, label, multiline] of [
    ["sender", "Sender address", false],
    ["subject", "Subject", false],
    ["urls", "Links (one per line)", true],
    ["attachments", "Attachments (one per line)", true],
  ]) {
    const fieldContainer = element("label", "field-group");
    fieldContainer.append(element("span", "metric-label", label));
    const input = element(multiline ? "textarea" : "input", "field");
    input.name = name;
    input.setAttribute("aria-label", label);
    if (multiline) {
      input.rows = 3;
      input.style.resize = "vertical";
    } else {
      input.type = "text";
    }
    emailInputs[name] = input;
    fieldContainer.append(input);
    emailGrid.append(fieldContainer);
  }
  const authControls = element("div", "toolbar");
  const authInputs = {};
  for (const protocol of ["spf_status", "dkim_status", "dmarc_status"]) {
    const label = protocol.replace("_status", "").toUpperCase();
    const fieldContainer = element("label", "field-group");
    fieldContainer.append(element("span", "metric-label", label));
    const select = element("select", "select-field");
    select.setAttribute("aria-label", label);
    for (const value of ["Not provided", "PASS", "FAIL", "SOFTFAIL"]) {
      const option = element("option", "", value);
      option.value = value === "Not provided" ? "" : value;
      select.append(option);
    }
    authInputs[protocol] = select;
    fieldContainer.append(select);
    authControls.append(fieldContainer);
  }
  const submitEmail = element("button", "primary-button", "Analyze email");
  submitEmail.type = "submit";
  const emailResult = element("div", "scan-result");
  emailForm.append(emailGrid, authControls, submitEmail, emailResult);
  emailPanel.append(emailForm);
  emailForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    submitEmail.disabled = true;
    emailResult.replaceChildren(element("p", "subtle", "Running email rules on the Python API…"));
    try {
      const analysis = await apiRequest("/api/inspect/email", {
        method: "POST",
        body: JSON.stringify({
          sender: emailInputs.sender.value,
          subject: emailInputs.subject.value,
          urls: emailInputs.urls.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
          attachments: emailInputs.attachments.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
          spf_status: authInputs.spf_status.value,
          dkim_status: authInputs.dkim_status.value,
          dmarc_status: authInputs.dmarc_status.value,
        }),
      });
      emailResult.replaceChildren();
      const heading = element("div", "incident-top");
      heading.append(
        element("h3", "", analysis.verdict),
        element("span", "risk", `Risk ${analysis.risk_score}/100`),
      );
      const findings = element("ul", "findings");
      if (analysis.findings.length) {
        analysis.findings.forEach((finding) => {
          findings.append(element("li", "", `${finding.rule_name}: ${finding.evidence}`));
        });
      } else {
        findings.append(element("li", "", "No configured email phishing rules matched."));
      }
      emailResult.append(heading, findings, element("p", "subtle", analysis.disclaimer));
    } catch (error) {
      emailResult.replaceChildren(element("div", "notice error", error.message));
    } finally {
      submitEmail.disabled = false;
    }
  });
  root.append(emailPanel);
}

function renderApprovals() {
  root.append(element("p", "panel-subtitle", "Admin sign-in is required. Decisions are recorded in the configured Postgres database; approved actions remain simulations."));
  const panel = element("section", "panel");
  panelHeading(panel, "Admin access", "Sign in with the password configured for this Vercel deployment.");
  root.append(panel);
  apiRequest("/api/admin/session")
    .then((session) => {
      adminSession = session;
      if (currentView !== "approvals") return;
      if (!session.configured) {
        panel.append(element("div", "notice error", "Admin access is not configured. Set ADMIN_PASSWORD and SESSION_SECRET in Vercel project settings, then redeploy."));
        return;
      }
      if (session.authenticated) {
        loadAdminApprovals(panel);
      } else {
        renderAdminLogin(panel);
      }
    })
    .catch((error) => panel.append(element("div", "notice error", error.message)));
}

function renderAdminLogin(panel) {
  const form = element("form", "form-row");
  const password = element("input", "field");
  password.type = "password";
  password.autocomplete = "current-password";
  password.placeholder = "Admin password";
  password.required = true;
  password.setAttribute("aria-label", "Admin password");
  const submit = element("button", "primary-button", "Sign in");
  submit.type = "submit";
  const feedback = element("div");
  form.append(password, submit);
  panel.append(form, feedback);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    feedback.replaceChildren();
    try {
      await apiRequest("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ password: password.value }),
      });
      adminSession.authenticated = true;
      password.value = "";
      await loadAdminApprovals(panel);
    } catch (error) {
      feedback.append(element("div", "notice error", error.message));
    } finally {
      submit.disabled = false;
    }
  });
}

async function loadAdminApprovals(panel) {
  panel.replaceChildren();
  panelHeading(panel, "Admin approval queue", "Actions are simulated and have no real-world effect.");
  const loading = element("p", "subtle", "Loading decisions from the backend…");
  panel.append(loading);
  try {
    const data = await apiRequest("/api/admin/approvals");
    if (currentView !== "approvals") return;
    panel.replaceChildren();
    const header = element("div", "panel-heading");
    const titleBlock = element("div");
    titleBlock.append(element("h2", "", "Admin approval queue"));
    titleBlock.append(element("p", "panel-subtitle", "Review records are shared and persisted in Postgres."));
    const logout = element("button", "secondary-button", "Sign out");
    logout.addEventListener("click", async () => {
      try {
        await apiRequest("/api/admin/logout", { method: "POST" });
        adminSession.authenticated = false;
        render();
      } catch (error) {
        panel.prepend(element("div", "notice error", error.message));
      }
    });
    header.append(titleBlock, logout);
    panel.append(header);
    renderAdminActions(panel, adminActions);
  } catch (error) {
    loading.replaceWith(element("div", "notice error", error.message));
  }
}

function renderAdminActions(panel, actions) {
  const pending = actions.filter((action) => !action.review);
  const history = actions.filter((action) => action.review);
  const pendingHeading = element("div", "section-heading");
  pendingHeading.append(element("h2", "", `Pending actions (${pending.length})`));
  panel.append(pendingHeading);
  const list = element("div", "approval-list");
  if (!pending.length) list.append(element("div", "empty-state", "No pending actions."));
  pending.forEach((action) => {
    const card = element("article", "approval-card");
    const top = element("div", "incident-top");
    top.append(
      element("h3", "", action.action_type),
      element("span", "severity severity-high", "PENDING REVIEW"),
    );
    card.append(top);
    card.append(element("p", "incident-meta", `Target: ${action.target_entity} · ${action.campaign_tag || action.incident_id}`));
    card.append(element("p", "incident-description", action.description || ""));
    const controls = element("div", "action-row");
    const reviewer = element("input", "field");
    reviewer.value = "SOC Analyst";
    reviewer.setAttribute("aria-label", "Reviewer name");
    const notes = element("input", "field");
    notes.placeholder = "Decision notes (optional)";
    notes.setAttribute("aria-label", "Decision notes");
    for (const decision of ["APPROVE", "REJECT"]) {
      const button = element(
        "button",
        decision === "APPROVE" ? "decision-button" : "decision-button reject",
        decision === "APPROVE" ? "Approve (simulate)" : "Reject",
      );
      button.addEventListener("click", async () => {
        if (decision === "APPROVE" && !window.confirm(
          `Approve simulated ${action.action_type} for ${action.target_entity}? No real-world action will occur.`,
        )) return;
        button.disabled = true;
        try {
          await apiRequest("/api/admin/decisions", {
            method: "POST",
            body: JSON.stringify({
              action_id: action.action_id,
              decision,
              reviewer_name: reviewer.value.trim() || "SOC Analyst",
              reviewer_notes: notes.value.trim(),
            }),
          });
          await loadAdminApprovals(panel);
        } catch (error) {
          panel.prepend(element("div", "notice error", error.message));
          button.disabled = false;
        }
      });
      controls.append(button);
    }
    controls.prepend(reviewer, notes);
    card.append(controls);
    list.append(card);
  });
  panel.append(list);

  if (history.length) {
    const heading = element("div", "section-heading");
    heading.append(element("h2", "", `Decision history (${history.length})`));
    panel.append(heading);
    const historyList = element("div", "approval-list");
    history.forEach((action) => {
      const card = element("article", "approval-card");
      const top = element("div", "incident-top");
      top.append(element("h3", "", action.action_type), element("span", "tag", action.review.decision));
      card.append(
        top,
        element("p", "incident-meta", `${action.target_entity} · ${action.campaign_tag || action.incident_id} · ${action.review.reviewer_name}`),
        element("p", "incident-description", action.review.reviewer_notes || "No reviewer note."),
      );
      if (action.review.execution_log) {
        const detail = element("details");
        detail.style.marginTop = "10px";
        detail.append(element("summary", "text-button", "View simulated execution log"));
        const log = element("pre", "subtle", JSON.stringify(action.review.execution_log, null, 2));
        detail.append(log);
        card.append(detail);
      }
      historyList.append(card);
    });
    panel.append(historyList);
  }
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
  const backendStatus = document.querySelector("#backend-status");
  backendStatus.lastChild.textContent = " API CONNECTING";
  try {
    const health = await apiRequest("/api/health");
    backendStatus.lastChild.textContent = health.status === "online" ? " PYTHON API ONLINE" : " API UNAVAILABLE";
    dashboard = await apiRequest("/api/detections");
    if (!Array.isArray(dashboard.events) || !Array.isArray(dashboard.incidents)) {
      throw new Error("The detection API returned an invalid response.");
    }
    render();
  } catch (error) {
    backendStatus.lastChild.textContent = " API UNAVAILABLE";
    errorBox.textContent = `${error.message} Confirm the Vercel Python function is deployed and check the deployment logs.`;
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
document.querySelector("#refresh-button").addEventListener("click", async () => {
  await loadDashboard();
  if (currentView === "approvals" && adminSession.authenticated) {
    const panel = root.querySelector(".panel");
    if (panel) await loadAdminApprovals(panel);
  }
});
loadDashboard();
