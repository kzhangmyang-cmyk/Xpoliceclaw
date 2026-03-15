const STAGES = [
  { key: "queued", label: "Queued" },
  { key: "collect", label: "Collecting system data" },
  { key: "traffic", label: "Analyzing network traffic" },
  { key: "fs", label: "Scanning filesystem footprint" },
  { key: "model", label: "Inspecting model activity" },
  { key: "signal", label: "Scoring detected signals" },
  { key: "report", label: "Publishing reports" },
  { key: "completed", label: "Completed" },
];

const JOB_STATUS_LABELS = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

const TASK_STATUS_LABELS = {
  pending: "Pending",
  running: "Running",
  success: "Success",
  failed: "Failed",
  partial: "Partial",
};

const CLIENT_BOOTSTRAP = window.POLICE_CLAW_BOOTSTRAP || {};
const API_HEADER_NAME = CLIENT_BOOTSTRAP.apiHeaderName || "X-PoliceClaw-Token";
const API_TOKEN = CLIENT_BOOTSTRAP.apiToken || "";
const PUBLIC_SITE_MODE = Boolean(CLIENT_BOOTSTRAP.publicSiteMode);
const DOWNLOAD_ASSET = CLIENT_BOOTSTRAP.download || {};
const UNINSTALL_CONFIRMATION_TEXT = "UNINSTALL CONFIRMED";
const HIGH_RISK_THRESHOLD = 70;
const TASK_ACTIVE_STATUSES = new Set(["pending", "running"]);
const TASK_TERMINAL_STATUSES = new Set(["success", "failed", "partial"]);
const MANUAL_REVIEW_BLOCK_CODES = new Set(["path_too_broad", "user_data_overlap", "binary_not_safe_to_remove"]);
const state = {
  jobs: [],
  currentJob: null,
  selectedCheckId: null,
  pollTimer: null,
  uninstallTargets: [],
  uninstallTask: null,
  uninstallHistory: [],
  uninstallSourceJobId: null,
  uninstallSourceScanId: null,
  removedTargetIds: new Set(),
  uninstallModalState: buildModalState(),
  uninstallResult: null,
  uninstallPollTimer: null,
  uninstallPollingTaskId: null,
  uninstallPollInFlight: false,
  eventsBound: false,
  notice: null,
  filters: {
    search: "",
    domain: "all",
    status: "all",
    sort: "risk",
  },
};

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  bootstrap();
});

function buildModalState() {
  return {
    open: false,
    targetId: null,
    mode: "standard",
    remove_startup: true,
    remove_cache: true,
    remove_config: true,
    remove_binary: false,
    confirmation_text: "",
    error: "",
  };
}

function bindEvents() {
  if (state.eventsBound) {
    return;
  }
  state.eventsBound = true;
  document.getElementById("startScanBtn").addEventListener("click", handlePrimaryAction);
  document.getElementById("historyList").addEventListener("click", onHistoryClick);
  document.getElementById("domainPortfolio").addEventListener("click", onDomainClick);
  document.getElementById("findingsTable").addEventListener("click", onFindingClick);
  document.getElementById("findingsSearch").addEventListener("input", onFilterChange);
  document.getElementById("domainFilter").addEventListener("change", onFilterChange);
  document.getElementById("statusFilter").addEventListener("change", onFilterChange);
  document.getElementById("sortFilter").addEventListener("change", onFilterChange);
  document.getElementById("uninstallTargetList").addEventListener("click", onTargetActionClick);
  document.getElementById("uninstallHistoryList").addEventListener("click", onUninstallHistoryClick);
  document.getElementById("uninstallCancelBtn").addEventListener("click", closeUninstallModal);
  document.getElementById("uninstallSubmitBtn").addEventListener("click", submitUninstall);
  document.getElementById("uninstallModal").addEventListener("click", onModalShellClick);
  document.getElementById("uninstallMode").addEventListener("change", onModalInputChange);
  document.getElementById("removeStartupToggle").addEventListener("change", onModalInputChange);
  document.getElementById("removeCacheToggle").addEventListener("change", onModalInputChange);
  document.getElementById("removeConfigToggle").addEventListener("change", onModalInputChange);
  document.getElementById("removeBinaryToggle").addEventListener("change", onModalInputChange);
  document.getElementById("confirmationText").addEventListener("input", onModalInputChange);
}

async function bootstrap() {
  renderEmptyState();
  renderGlobalNotice();

  if (PUBLIC_SITE_MODE) {
    renderPublicSiteMode();
    renderModal();
    return;
  }

  const failures = [];
  await Promise.all([
    loadJobs().catch((error) => failures.push(`Scan history: ${error.message}`)),
    loadUninstallHistory().catch((error) => failures.push(`Uninstall history: ${error.message}`)),
  ]);

  if (failures.length) {
    setGlobalNotice("warn", "Partial data loaded", failures.join(" "));
  }

  try {
    const activeJob = state.jobs.find((job) => ["queued", "running"].includes(job.status));
    if (activeJob) {
      await loadJob(activeJob.id);
      startPolling(activeJob.id);
    } else if (state.jobs[0]) {
      await loadJob(state.jobs[0].id);
    } else {
      renderEmptyState();
    }

    await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));

    const activeTask = getScopedUninstallHistory().find((task) => TASK_ACTIVE_STATUSES.has(task.status));
    if (activeTask) {
      await loadUninstallTask(activeTask.id);
      startUninstallPolling(activeTask.id);
    } else if (getScopedUninstallHistory()[0]) {
      state.uninstallTask = getScopedUninstallHistory()[0];
      if (isTerminalTask(state.uninstallTask)) {
        await loadUninstallResult(state.uninstallTask.id);
      }
      renderUninstallPanel();
      renderUninstallResult();
    } else if (state.uninstallHistory[0]) {
      state.uninstallTask = state.uninstallHistory[0];
      if (isTerminalTask(state.uninstallTask)) {
        await loadUninstallResult(state.uninstallTask.id);
      }
      renderUninstallPanel();
      renderUninstallResult();
    }

    renderModal();
    renderSafetyNotes(state.currentJob);
  } catch (error) {
    renderGlobalError(error.message);
  }
}

function handlePrimaryAction() {
  if (PUBLIC_SITE_MODE) {
    openDownloadAsset();
    return;
  }
  startScan();
}

async function startScan() {
  const button = document.getElementById("startScanBtn");
  button.disabled = true;

  try {
    clearGlobalNotice();
    const job = await requestJson("/api/scans", { method: "POST" }, "Unable to start a scan.");
    state.selectedCheckId = null;
    state.currentJob = job;
    renderJob(job);
    await loadJobs();
    await fetchUninstallTargets(getRequestedUninstallJobId(job));
    startPolling(job.id);
  } catch (error) {
    renderGlobalError(error.message);
  } finally {
    syncButtonState();
  }
}

async function loadJobs() {
  const payload = await requestJson("/api/scans", {}, "Unable to load scan history.");
  state.jobs = payload.items || [];
  renderHistory();
}

async function loadJob(jobId) {
  const job = await requestJson(`/api/scans/${jobId}`, {}, "Unable to load the selected scan.");
  state.currentJob = job;
  ensureSelectedCheck(job);
  renderJob(job);
}

async function fetchUninstallTargets(jobId = null) {
  const query = jobId ? `?job_id=${encodeURIComponent(jobId)}` : "";
  const payload = await requestJson(
    `/api/uninstall/targets${query}`,
    {},
    "Unable to load uninstall targets.",
  );
  state.uninstallTargets = payload.items || [];
  state.uninstallSourceJobId = payload.source_job_id || null;
  state.uninstallSourceScanId = payload.source_scan_id || null;
  refreshRemovedTargetIds();
  refreshUninstallViews();
}

async function loadUninstallTargets() {
  await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));
}

async function loadUninstallHistory() {
  const payload = await requestJson("/api/uninstall/history", {}, "Unable to load uninstall history.");
  state.uninstallHistory = payload.items || [];
  if (state.uninstallTask) {
    const refreshed = state.uninstallHistory.find((task) => task.id === state.uninstallTask.id);
    if (refreshed) {
      state.uninstallTask = refreshed;
    }
  } else if (state.uninstallHistory[0]) {
    state.uninstallTask = state.uninstallHistory[0];
  }
  refreshRemovedTargetIds();
  refreshUninstallViews();
}

async function loadUninstallTask(taskId) {
  const task = await requestJson(`/api/uninstall/${taskId}`, {}, "Unable to load uninstall task details.");
  state.uninstallTask = task;
  renderUninstallPanel();
  syncOperationPanel(state.currentJob);
  if (isTerminalTask(task)) {
    await loadUninstallResult(task.id);
  }
}

async function loadUninstallResult(taskId) {
  const result = await requestJson(
    `/api/uninstall/${taskId}/result`,
    {},
    "Unable to load the uninstall result.",
  );
  state.uninstallResult = result;
  renderUninstallResult();
}

function startPolling(jobId) {
  stopPolling();
  state.pollTimer = window.setInterval(async () => {
    try {
      await Promise.all([loadJob(jobId), loadJobs()]);
      if (!["queued", "running"].includes(state.currentJob?.status)) {
        stopPolling();
        await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));
      }
    } catch (error) {
      stopPolling();
      renderGlobalError(error.message);
    }
  }, 1500);
}

function stopPolling() {
  if (!state.pollTimer) {
    return;
  }
  window.clearInterval(state.pollTimer);
  state.pollTimer = null;
}

function startUninstallPolling(taskId) {
  stopUninstallPolling();
  state.uninstallPollingTaskId = taskId;
  pollUninstallTask(taskId);
}

async function pollUninstallTask(taskId) {
  if (state.uninstallPollInFlight || state.uninstallPollingTaskId !== taskId) {
    return;
  }
  state.uninstallPollInFlight = true;
  try {
    await Promise.all([
      loadUninstallTask(taskId),
      loadUninstallHistory(),
      fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob)),
    ]);
    if (state.uninstallTask?.id !== taskId || isTerminalTask(state.uninstallTask)) {
      stopUninstallPolling();
      return;
    }
    state.uninstallPollTimer = window.setTimeout(() => {
      pollUninstallTask(taskId).catch((error) => renderGlobalError(error.message));
    }, 1200);
  } catch (error) {
    stopUninstallPolling();
    renderGlobalError(error.message);
  } finally {
    state.uninstallPollInFlight = false;
  }
}

function stopUninstallPolling() {
  if (!state.uninstallPollTimer) {
    state.uninstallPollingTaskId = null;
    state.uninstallPollInFlight = false;
    return;
  }
  window.clearTimeout(state.uninstallPollTimer);
  state.uninstallPollTimer = null;
  state.uninstallPollingTaskId = null;
  state.uninstallPollInFlight = false;
}

function renderJob(job) {
  syncButtonState();
  syncOperationPanel(job);
  renderExecutiveSummary(job);
  renderProgress(job);
  renderArtifacts(job);
  renderRuntime(job);
  renderSafetyNotes(job);
  renderHistory();
  renderDomainPortfolio(job);
  renderFindings(job);
  renderEvidencePanel(job);
  renderUninstallPanel();
  renderUninstallResult();
  renderUninstallHistory();
}

function refreshUninstallViews() {
  syncOperationPanel(state.currentJob);
  renderExecutiveSummary(state.currentJob);
  renderFindings(state.currentJob);
  renderEvidencePanel(state.currentJob);
  renderSafetyNotes(state.currentJob);
  renderUninstallPanel();
  renderUninstallResult();
  renderUninstallHistory();
  renderModal();
}

function syncOperationPanel(job) {
  if (PUBLIC_SITE_MODE) {
    document.getElementById("jobStateText").textContent = hasDownloadAsset()
      ? "Public download site"
      : "Release package unavailable";
    document.getElementById("jobMetaText").textContent = hasDownloadAsset()
      ? `Windows installer ${DOWNLOAD_ASSET.version || "--"} is ready for direct download.`
      : "Build a Windows release package to enable direct website downloads.";
    document.getElementById("scanIdLabel").textContent = DOWNLOAD_ASSET.version || "--";
    document.getElementById("scanTimeLabel").textContent = hasDownloadAsset()
      ? formatFileSize(DOWNLOAD_ASSET.sizeBytes)
      : "--";
    document.getElementById("uninstallAvailableLabel").textContent = "--";
    document.getElementById("uninstallLastStatus").textContent = "Local Only";
    document.getElementById("uninstallLastMeta").textContent =
      "Real scan and uninstall remain available after the Windows client is installed.";
    return;
  }

  const stageText = getStageLabel(job?.stage_key, job?.stage_label);
  const statusText = job?.status === "failed"
    ? "Scan failed"
    : stageText || "Waiting for a scan";
  const metaText = job?.report
    ? `${job.report.host || "--"} / ${job.report.os || "--"}`
    : job?.created_at
      ? `Job created at ${formatDate(job.created_at)}`
      : "No active scan job yet";

  document.getElementById("jobStateText").textContent = statusText;
  document.getElementById("jobMetaText").textContent = metaText;
  document.getElementById("scanIdLabel").textContent = job?.scan_id || "--";
  document.getElementById("scanTimeLabel").textContent = job?.report?.timestamp || "--";

  const scopedTargets = getRenderableUninstallTargets(job);
  const directTargets = scopedTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  document.getElementById("uninstallAvailableLabel").textContent = String(directTargets.length);

  const scopedHistory = getScopedUninstallHistory(job);
  const lastTask = scopedHistory[0] || state.uninstallHistory[0];
  document.getElementById("uninstallLastStatus").textContent = lastTask
    ? TASK_STATUS_LABELS[lastTask.status] || lastTask.status
    : "None";
  document.getElementById("uninstallLastMeta").textContent = lastTask
    ? `${lastTask.target_name} / ${formatDate(lastTask.updated_at)}${lastTask.status === "partial" ? " / Manual review required" : ""}`
    : state.uninstallSourceScanId
      ? `Targets sourced from scan ${state.uninstallSourceScanId}`
      : "No uninstall task has run yet";
}

function renderExecutiveSummary(job) {
  const report = job?.report;
  const badge = document.getElementById("reportBadge");
  const headline = document.getElementById("reportHeadline");
  const narrative = document.getElementById("reportNarrative");
  const metaHost = document.getElementById("metaHost");
  const metaOs = document.getElementById("metaOs");
  const metaScanId = document.getElementById("metaScanId");
  const metaScanTime = document.getElementById("metaScanTime");
  const summaryGrid = document.getElementById("summaryGrid");
  const recommendationList = document.getElementById("recommendationList");

  if (PUBLIC_SITE_MODE) {
    badge.className = "report-badge report-badge-info";
    badge.textContent = hasDownloadAsset() ? "Website Download" : "Release Pending";
    headline.textContent = "Download the Windows client to scan and remediate the local machine.";
    narrative.textContent = hasDownloadAsset()
      ? "The hosted site distributes the desktop installer. Real scanning, evidence collection, and uninstall actions still run locally on Windows after installation."
      : "The public site is live, but no installer package is attached yet. Build a Windows release to enable direct client downloads.";
    metaHost.textContent = "Windows Client";
    metaOs.textContent = "Windows 10+";
    metaScanId.textContent = DOWNLOAD_ASSET.version || "--";
    metaScanTime.textContent = hasDownloadAsset() ? formatFileSize(DOWNLOAD_ASSET.sizeBytes) : "--";
    summaryGrid.innerHTML = [
      { value: hasDownloadAsset() ? DOWNLOAD_ASSET.version || "--" : "--", label: "Installer Version" },
      { value: hasDownloadAsset() ? formatFileSize(DOWNLOAD_ASSET.sizeBytes) : "--", label: "Package Size" },
      { value: "Local", label: "Execution Scope" },
      { value: "Conservative", label: "Removal Boundary" },
      { value: "Persisted", label: "History Recovery" },
    ].map((card) => `
      <article class="summary-card">
        <span>${escapeHtml(card.label)}</span>
        <strong>${escapeHtml(String(card.value))}</strong>
      </article>
    `).join("");
    recommendationList.innerHTML = [
      {
        tone: "neutral",
        tag: "Download",
        title: hasDownloadAsset() ? "Install the Windows client" : "Build a release package",
        body: hasDownloadAsset()
          ? "Use the direct installer to deploy the local workbench, then run scans and uninstall tasks on the Windows host."
          : "No installer is published yet. Build dist/release first so the website can serve a Windows client.",
      },
      {
        tone: "warn",
        tag: "Boundary",
        title: "The hosted site does not scan the visitor machine",
        body: "All real scan and uninstall actions still execute inside the installed Windows client, not in the remote browser session.",
      },
      {
        tone: "info",
        tag: "Audit",
        title: "Reports and task history stay local",
        body: "The installed client keeps scan history, uninstall history, and report artifacts under the local runtime root for later review.",
      },
    ].map((item) => `
      <article class="recommendation-item recommendation-${escapeHtml(item.tone || "neutral")}">
        ${item.tag ? `<span class="recommendation-tag recommendation-tag-${escapeHtml(item.tone || "neutral")}">${escapeHtml(item.tag)}</span>` : ""}
        <strong>${escapeHtml(item.title)}</strong>
        <p>${escapeHtml(item.body)}</p>
      </article>
    `).join("");
    renderUninstallTargets();
    return;
  }

  if (!report) {
    badge.className = "report-badge";
    badge.textContent = "Idle";
    headline.textContent = job?.status === "failed" ? "The latest scan failed." : "Waiting for a completed scan";
    narrative.textContent = job?.error || "The report workbench will populate after a successful scan finishes.";
    metaHost.textContent = "--";
    metaOs.textContent = "--";
    metaScanId.textContent = job?.scan_id || "--";
    metaScanTime.textContent = "--";
    summaryGrid.innerHTML = buildEmptyCard("Summary metrics appear after a completed report is available.");
    recommendationList.innerHTML = buildEmptyCard("Recommended actions are generated from the latest completed report.");
    renderUninstallTargets();
    return;
  }

  const posture = getPosture(report);
  badge.className = `report-badge ${posture.badgeClass}`;
  badge.textContent = report.demo_mode ? `${posture.label} / Demo` : posture.label;
  headline.textContent = posture.headline;
  narrative.textContent = report.demo_mode
    ? `Demo fixture loaded. ${buildNarrative(report)}`
    : buildNarrative(report);
  metaHost.textContent = report.host || "--";
  metaOs.textContent = report.os || "--";
  metaScanId.textContent = report.scan_id || "--";
  metaScanTime.textContent = report.timestamp || "--";

  const summaryTargets = getRenderableUninstallTargets(job);
  const supportedTargets = summaryTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const resolvedTargets = supportedTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "removed" || remediation.status === "mitigated";
  });
  const manualReviewTargets = summaryTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "partial" || remediation.status === "manual-review";
  });
  const summaryCards = [
    { value: report.summary.total_risks, label: "Risk Findings" },
    { value: report.summary.max_risk_score, label: "Max Risk Score" },
    { value: report.runtime?.result_overview?.active_signals ?? "--", label: "Active Signals" },
    { value: `${resolvedTargets.length}/${supportedTargets.length}`, label: "Auto-Remediated" },
    { value: manualReviewTargets.length, label: "Residual Review" },
  ];

  summaryGrid.innerHTML = summaryCards.map((card) => `
    <article class="summary-card">
      <span>${escapeHtml(card.label)}</span>
      <strong>${escapeHtml(String(card.value))}</strong>
    </article>
  `).join("");

  const recommendations = renderUninstallRecommendations(report);
  recommendationList.innerHTML = recommendations.map((item) => `
    <article class="recommendation-item recommendation-${escapeHtml(item.tone || "neutral")}">
      ${item.tag ? `<span class="recommendation-tag recommendation-tag-${escapeHtml(item.tone || "neutral")}">${escapeHtml(item.tag)}</span>` : ""}
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.body)}</p>
    </article>
  `).join("");

  renderUninstallTargets();
}

function renderUninstallTargets() {
  const container = document.getElementById("uninstallTargetList");
  const meta = document.getElementById("uninstallTargetMeta");
  const targets = getRenderableUninstallTargets();

  if (PUBLIC_SITE_MODE) {
    meta.textContent = hasDownloadAsset()
      ? "Targets appear after the client completes a local scan"
      : "Publish an installer to activate website downloads";
    container.innerHTML = buildEmptyCard(
      hasDownloadAsset()
        ? "This hosted page distributes the Windows client. Inferred uninstall targets appear only inside the local workbench after installation."
        : "No release package is available yet. Build a Windows installer so the website can hand off to the local client."
    );
    return;
  }

  if (!targets.length) {
    meta.textContent = "No inferred uninstall targets yet";
    container.innerHTML = buildEmptyCard("The backend will infer removable targets from the latest completed scan.");
    return;
  }

  const supported = targets.filter((target) => target.uninstall_supported);
  const sourceLabel = state.uninstallSourceScanId ? ` / Source ${state.uninstallSourceScanId}` : "";
  meta.textContent = `${supported.length} supported / ${targets.length} total${sourceLabel}`;
  const displayTargets = targets.slice(0, 6);

  container.innerHTML = displayTargets.map((target) => {
    const remediation = getRemediationStateForTarget(target);
    const statusClass = remediation.status === "removed" || remediation.status === "mitigated"
      ? "status-success"
      : remediation.status === "partial" || remediation.status === "manual-review"
        ? "status-partial"
        : remediation.status === "running"
          ? "status-running"
          : target.uninstall_supported
            ? "status-running"
            : "status-failed";
    const statusLabel = remediation.label || (
      target.uninstall_supported
        ? target.support_level === "full"
          ? "Urgent"
          : target.support_level === "cleanup"
            ? "Cleanup"
            : "Contain"
        : "Blocked"
    );
    return `
      <article class="target-card">
        <div class="target-card-head">
          <div>
            <strong>${escapeHtml(target.display_name || target.name)}</strong>
            <span>${escapeHtml(target.type)} / Risk ${escapeHtml(String(target.risk_score))} / Confidence ${escapeHtml(formatPercent(target.confidence || 0))}</span>
          </div>
          <span class="status-pill ${statusClass}">${escapeHtml(statusLabel)}</span>
        </div>
        <div class="target-card-body">
          <div>${escapeHtml(target.target_summary || target.evidence_summary || `${target.matched_findings_count} matched finding(s)`)}</div>
          <div>${escapeHtml(target.rationale || target.vendor || "Unknown vendor")}</div>
        </div>
        <div class="finding-actions">
          <button class="action-btn ghost" type="button" data-target-action="scope" data-target-id="${escapeHtml(target.id)}">View Scope</button>
          ${target.uninstall_supported && !["removed", "mitigated"].includes(remediation.status)
            ? `<button class="action-btn danger" type="button" data-target-action="uninstall" data-target-id="${escapeHtml(target.id)}">Uninstall</button>`
            : `<span class="panel-meta">${escapeHtml(remediation.label ? remediation.detail : target.unsupported_reason || "Not removable")}</span>`}
        </div>
      </article>
    `;
  }).join("");
}

function renderProgress(job) {
  const progress = job?.progress ?? 0;
  document.getElementById("progressLabel").textContent = getStageLabel(job?.stage_key, job?.stage_label) || "Ready";
  document.getElementById("progressValue").textContent = `${progress}%`;
  document.getElementById("progressBar").style.width = `${progress}%`;

  const activeIndex = Math.max(0, STAGES.findIndex((stage) => stage.key === (job?.stage_key || "queued")));
  document.getElementById("stageStrip").innerHTML = STAGES.map((stage, index) => {
    const classes = ["stage-pill"];
    if (index < activeIndex || (job?.status === "completed" && stage.key === "completed")) {
      classes.push("is-done");
    }
    if (index === activeIndex && ["queued", "running"].includes(job?.status)) {
      classes.push("is-active");
    }
    return `
      <div class="${classes.join(" ")}">
        <span class="eyebrow">${String(index + 1).padStart(2, "0")}</span>
        <strong>${escapeHtml(stage.label)}</strong>
      </div>
    `;
  }).join("");

  const stageHistory = job?.stage_history || [];
  const historyContainer = document.getElementById("stageHistory");
  if (!stageHistory.length) {
    historyContainer.innerHTML = buildEmptyCard("Stage history appears once a scan has started.");
    return;
  }

  historyContainer.innerHTML = [...stageHistory].reverse().map((item) => `
    <div class="stage-history-item">
      <div>
        <strong>${escapeHtml(getStageLabel(item.key, item.label))}</strong>
        <span>${escapeHtml(formatDate(item.at))}</span>
      </div>
      <strong>${escapeHtml(String(item.progress || 0))}%</strong>
    </div>
  `).join("");
}

function renderArtifacts(job) {
  const container = document.getElementById("artifactRow");
  if (!job?.artifacts?.json && !job?.artifacts?.docx) {
    container.innerHTML = buildEmptyCard("Report downloads appear when the scan completes.");
    return;
  }

  const items = [];
  if (job.artifacts.json_url) {
    items.push({ type: "JSON", label: "Download structured report", href: job.artifacts.json_url });
  }
  if (job.artifacts.docx_url) {
    items.push({ type: "DOCX", label: "Download document report", href: job.artifacts.docx_url });
  }

  container.innerHTML = items.map((item) => `
    <a class="artifact-card" href="${item.href}">
      <span>${escapeHtml(item.type)}</span>
      <strong>${escapeHtml(item.label)}</strong>
    </a>
  `).join("");
}

function renderRuntime(job) {
  const container = document.getElementById("runtimeGrid");
  if (!job) {
    container.innerHTML = buildEmptyCard("No runtime context available yet.");
    return;
  }

  const stats = job.report?.runtime?.stats || job.stats || {};
  const rows = [
    ["Processes", stats.processes],
    ["Connections", stats.connections],
    ["Open Files", stats.open_files],
    ["Env Signals", stats.env_signals],
    ["DNS", Array.isArray(stats.dns_servers) ? stats.dns_servers.join(", ") || "--" : "--"],
    ["Outbound", stats.outbound_count],
    ["Cloud Endpoints", stats.cloud_endpoints],
    ["Model Processes", stats.model_processes],
  ];

  container.innerHTML = rows.map(([label, value]) => `
    <div class="runtime-item">
      <span class="runtime-key">${escapeHtml(String(label))}</span>
      <strong class="runtime-value">${escapeHtml(String(value ?? "--"))}</strong>
    </div>
  `).join("");
}

function renderSafetyNotes(job) {
  const meta = document.getElementById("safetyNotesMeta");
  const container = document.getElementById("safetyNotesList");
  const targets = getRenderableUninstallTargets(job);
  const blocked = targets.filter((target) => !target.uninstall_supported).length;
  const partial = getScopedUninstallHistory(job).filter((task) => task.status === "partial").length;
  const notes = [
    {
      title: "Capability scope",
      body: "Automatic handling is limited to clearly scoped user-level agent footprints, persistence entries, config paths, cache paths, and explicit binaries.",
    },
    {
      title: "Manual review",
      body: "Blocked, terminate-only, and partial outcomes are normal guardrail states. They mean the runner preserved something on purpose or needs a human to verify scope.",
    },
    {
      title: "Deletion boundary",
      body: "The runner will not remove root paths, user home roots, browser profiles, workspace directories, or any broad directory that fails safety validation.",
    },
      {
        title: "History persistence",
        body: `Completed scan and uninstall summaries are stored under ${CLIENT_BOOTSTRAP.runtimeRoot || "the local runtime root"} so the workbench can recover recent history after a restart.`,
      },
    ];

  if (CLIENT_BOOTSTRAP.desktopShell) {
    notes.push({
      title: "Desktop session",
      body: CLIENT_BOOTSTRAP.adminMode
        ? "The client is running in desktop mode with administrator rights, so protected uninstall steps can execute on the local machine."
        : "The client is running in desktop mode without administrator rights. Some uninstall steps may be preserved until the launcher is elevated.",
    });
  }

  if (PUBLIC_SITE_MODE) {
    notes.push({
      title: "Hosted website mode",
      body: hasDownloadAsset()
        ? "This public site only distributes the Windows installer. Real scan, evidence collection, and uninstall still execute after the local client is installed."
        : "This public site is running without an attached installer package. Publish a release build to enable direct downloads.",
    });
  }

  if (job?.report?.demo_mode || job?.demo_mode || job?.source_type === "demo") {
    notes.push({
      title: "Demo fixture",
      body: "The current record was loaded from curated demo data for presentation. It does not represent a live scan or a live uninstall run.",
    });
  }

  meta.textContent = partial
    ? `${partial} residual review item(s) remain in this scope.`
    : blocked
      ? `${blocked} target(s) remain blocked for manual follow-up.`
      : "Automatic handling is conservative and fully logged.";

  container.innerHTML = notes.map((note) => `
    <article class="result-item result-item-note">
      <strong>${escapeHtml(note.title)}</strong>
      <p>${escapeHtml(note.body)}</p>
    </article>
  `).join("");
}

function renderHistory() {
  const container = document.getElementById("historyList");
  if (!state.jobs.length) {
    container.innerHTML = buildEmptyCard("No scan history yet.");
    return;
  }

  container.innerHTML = state.jobs.map((job) => {
    const active = state.currentJob?.id === job.id ? "active" : "";
    const riskCount = job.result_overview?.risk_count ?? job.report?.summary?.total_risks ?? "--";
    const demoSuffix = job.demo_mode || job.source_type === "demo" ? " / Demo fixture" : "";
    return `
      <button class="history-card ${active}" type="button" data-job-id="${job.id}">
        <div class="history-head">
          <h3>${escapeHtml(job.scan_id || job.id.toUpperCase())}</h3>
          <span class="status-pill status-${escapeHtml(job.status)}">${escapeHtml(JOB_STATUS_LABELS[job.status] || job.status)}</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(`${getStageLabel(job.stage_key, job.stage_label)}${demoSuffix}`)}</span>
          <span>Risk ${escapeHtml(String(riskCount))}</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(formatDate(job.updated_at))}</span>
          <span>${escapeHtml(String(job.progress || 0))}%</span>
        </div>
      </button>
    `;
  }).join("");
}

function renderUninstallHistory() {
  const container = document.getElementById("uninstallHistoryList");
  if (!state.uninstallHistory.length) {
    container.innerHTML = buildEmptyCard("No uninstall tasks have been started yet.");
    return;
  }

  container.innerHTML = state.uninstallHistory.slice(0, 5).map((task) => {
    const active = state.uninstallTask?.id === task.id ? "active" : "";
    return `
      <button class="history-card ${active}" type="button" data-uninstall-id="${task.id}">
        <div class="history-head">
          <h3>${escapeHtml(task.target_name)}</h3>
          <span class="status-pill status-${escapeHtml(task.status)}">${escapeHtml(TASK_STATUS_LABELS[task.status] || task.status)}</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(task.current_step || "No step yet")}</span>
          <span>${escapeHtml(String(task.progress || 0))}%</span>
        </div>
        <div class="history-meta">
          <span>${escapeHtml(formatDate(task.updated_at))}</span>
          <span>${escapeHtml(task.target_type || "--")}</span>
        </div>
      </button>
    `;
  }).join("");
}

function renderDomainPortfolio(job) {
  const container = document.getElementById("domainPortfolio");
  const meta = document.getElementById("domainPortfolioMeta");
  const report = job?.report;
  if (!report) {
    container.innerHTML = buildEmptyCard("Security domain cards appear when a completed report is available.");
    meta.textContent = "Waiting for a completed report";
    syncDomainFilterOptions([]);
    return;
  }

  const domains = getDomainEntries(report);
  syncDomainFilterOptions(domains);
  const riskyDomains = domains.filter((domain) => domain.risks > 0).length;
  meta.textContent = `${riskyDomains} / ${domains.length} domains with flagged findings`;

  container.innerHTML = domains.map((domain) => {
    const isSelected = state.filters.domain === domain.id;
    const width = Math.max(4, Number(domain.max_score || 0));
    const topFinding = [...domain.checks].sort((left, right) => right.risk_score - left.risk_score)[0];
    return `
      <button class="domain-tile ${isSelected ? "is-selected" : ""}" type="button" data-domain-filter="${domain.id}">
        <div class="domain-tile-head">
          <div class="domain-title">
            <span class="domain-icon">${escapeHtml(domain.icon || "")}</span>
            <div>
              <strong>${escapeHtml(safeText(domain.name, humanizeSlug(domain.id)))}</strong>
              <span>${escapeHtml(String(domain.risks))} risk / ${escapeHtml(String(domain.total))} checks</span>
            </div>
          </div>
          <strong>${escapeHtml(String(domain.max_score))}</strong>
        </div>
        <div class="domain-meter"><span style="width:${width}%"></span></div>
        <div class="domain-support">${escapeHtml(topFinding ? displayCheckTitle(topFinding) : "No significant risk currently in this domain.")}</div>
      </button>
    `;
  }).join("");
}

function renderFindings(job) {
  const table = document.getElementById("findingsTable");
  const meta = document.getElementById("findingsMeta");
  const report = job?.report;
  if (!report) {
    table.innerHTML = buildEmptyCard("Findings will populate after the scan report is ready.");
    meta.textContent = "0 records";
    return;
  }

  const checks = applyFindingFilters(report.checks || []);
  meta.textContent = `${checks.length} visible / ${(report.checks || []).length} total`;

  if (!checks.length) {
    state.selectedCheckId = null;
    table.innerHTML = buildEmptyCard("No findings match the current filter set.");
    return;
  }

  if (!checks.some((check) => check.id === state.selectedCheckId)) {
    state.selectedCheckId = checks[0].id;
  }

  table.innerHTML = checks.map((check) => {
    const selected = state.selectedCheckId === check.id ? "is-selected" : "";
    const relatedTargets = getRelatedTargets(check.id);
    const primaryTarget = pickPrimaryTarget(relatedTargets);
    const remediation = markRelatedFindingsHandled(check.id);
    const resolved = remediation.status === "removed" || remediation.status === "mitigated";
    const riskStatus = isFlagged(check) ? "status-risk" : "status-clear";
    const riskLabel = isFlagged(check) ? "Risk" : "Clear";
    const width = Math.max(2, Number(check.risk_score || 0));

    return `
      <button class="finding-row ${selected} ${resolved ? "is-resolved" : ""}" type="button" data-check-id="${check.id}">
        <div class="finding-row-grid">
          <div>
            <div class="finding-title">${escapeHtml(displayCheckTitle(check))}</div>
            <div class="finding-support">${escapeHtml(displayCheckDescription(check))}</div>
          </div>
          <div class="finding-domain">
            <span>${escapeHtml(check.domain_icon || "")}</span>
            <span>${escapeHtml(safeText(check.domain_name, humanizeSlug(check.domain)))}</span>
          </div>
          <div>
            <span class="finding-status ${riskStatus}">${escapeHtml(riskLabel)}</span>
            ${remediation.label ? `<span class="finding-tag finding-tag-${escapeHtml(remediation.status)}">${escapeHtml(remediation.label)}</span>` : ""}
          </div>
          <div class="finding-risk">
            <strong>${escapeHtml(String(check.risk_score))}</strong>
            <div class="mini-meter"><span style="width:${width}%"></span></div>
          </div>
          <div>${escapeHtml(formatPercent(check.confidence))}</div>
          <div>${escapeHtml(String(check.evidence_count || 0))}</div>
          <div class="finding-actions">
            ${renderFindingAction(primaryTarget, remediation)}
          </div>
        </div>
      </button>
    `;
  }).join("");
}

function renderFindingAction(target, remediation) {
  if (!target) {
    return `<span class="panel-meta">No target</span>`;
  }
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return `<span class="status-pill status-success">${escapeHtml(remediation.label || "Handled")}</span>`;
  }
  if (remediation.status === "partial") {
    return `
      <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">View Scope</button>
      <span class="panel-meta">Residual review required</span>
    `;
  }
  if (remediation.status === "manual-review") {
    return `
      <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">View Scope</button>
      <span class="panel-meta">${escapeHtml(remediation.detail || "Manual review required")}</span>
    `;
  }
  if (remediation.status === "running") {
    return `<span class="status-pill status-running">In Progress</span>`;
  }
  if (!target.uninstall_supported) {
    return `
      <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">View Scope</button>
      <span class="panel-meta">${escapeHtml(target.unsupported_reason || "Blocked")}</span>
    `;
  }
  return `
    <button class="action-btn ghost" type="button" data-uninstall-action="scope" data-target-id="${escapeHtml(target.id)}">View Scope</button>
    <button class="action-btn danger" type="button" data-uninstall-action="launch" data-target-id="${escapeHtml(target.id)}">Uninstall</button>
  `;
}

function renderEvidencePanel(job) {
  const meta = document.getElementById("evidenceMeta");
  const title = document.getElementById("evidenceTitle");
  const summary = document.getElementById("evidenceSummary");
  const viewer = document.getElementById("evidenceViewer");
  const check = getSelectedCheck(job);

  if (!check) {
    meta.textContent = "No finding selected";
    title.textContent = "Select a finding to inspect evidence details.";
    summary.textContent = "Evidence samples and uninstall scope will appear here.";
    viewer.textContent = "No evidence available.";
    return;
  }

  const relatedTargets = getRelatedTargets(check.id);
  const remediation = markRelatedFindingsHandled(check.id);
  const targetSummary = relatedTargets.length
    ? `Linked targets: ${relatedTargets.map((target) => target.display_name || target.name).join(", ")}`
    : "No removable target was inferred from this finding.";
  const remediationText = remediation.label
    ? ` Current remediation state: ${remediation.label}.`
    : "";

  meta.textContent = `${safeText(check.domain_name, humanizeSlug(check.domain))} / Risk ${check.risk_score} / Confidence ${formatPercent(check.confidence)}`;
  title.textContent = `${displayCheckTitle(check)} (${check.id})`;
  summary.textContent = `${displayCheckDescription(check)} ${targetSummary}${remediationText}`;
  viewer.textContent = (check.evidence && check.evidence.length)
    ? JSON.stringify(check.evidence, null, 2)
    : "This finding did not return evidence samples.";
}

function renderUninstallPanel() {
  const meta = document.getElementById("uninstallTaskMeta");
  const title = document.getElementById("uninstallTaskTitle");
  const summary = document.getElementById("uninstallTaskSummary");
  const bar = document.getElementById("uninstallTaskBar");
  const steps = document.getElementById("uninstallStepList");
  const logs = document.getElementById("uninstallLogList");
  const task = state.uninstallTask;

  if (!task) {
    meta.textContent = "No uninstall task in progress";
    title.textContent = "Select a removable target from Findings or Recommended Actions.";
    summary.textContent = "The uninstall runner uses a background task and reports progress, steps, and logs here.";
    bar.style.width = "0%";
    steps.innerHTML = buildEmptyCard("Removal steps will appear after an uninstall task starts.");
    logs.innerHTML = buildEmptyCard("Task logs will stream here once execution begins.");
    return;
  }

  meta.textContent = `${TASK_STATUS_LABELS[task.status] || task.status} / ${formatDate(task.updated_at)}`;
  title.textContent = `${task.target_name} (${task.target_type})`;
  const durationText = task.duration_ms ? ` / ${formatDuration(task.duration_ms)}` : "";
  summary.textContent = task.result?.summary
    ? `${task.result.summary}${durationText}`
    : `${task.current_step || "Task created, waiting for execution."}${durationText}`;
  bar.style.width = `${task.progress || 0}%`;

  steps.innerHTML = (task.steps || []).map((step) => {
    const classes = ["step-item"];
    if (step.status === "running") {
      classes.push("is-active");
    }
    if (step.status === "completed") {
      classes.push("is-done");
    }
    return `
      <div class="${classes.join(" ")}">
        <strong>${escapeHtml(String(step.index).padStart(2, "0"))}</strong>
        <div>
          <span>${escapeHtml(step.label)}</span>
          <small>${escapeHtml(step.status)}${step.duration_ms ? ` / ${escapeHtml(formatDuration(step.duration_ms))}` : ""}</small>
        </div>
      </div>
    `;
  }).join("") || buildEmptyCard("No steps available.");

  logs.innerHTML = (task.logs && task.logs.length)
    ? task.logs.slice().reverse().map((entry) => `
        <div class="log-item log-${escapeHtml(entry.level || "info")}">
          <span>${escapeHtml(formatDate(entry.at))}</span>
          <strong>${escapeHtml(entry.level || "info")}</strong>
          <p>${escapeHtml(entry.message || "")}</p>
        </div>
      `).join("")
    : buildEmptyCard("No task logs yet.");
}

function renderUninstallResult() {
  const meta = document.getElementById("uninstallResultMeta");
  const summary = document.getElementById("uninstallResultSummary");
  const viewer = document.getElementById("uninstallResultViewer");
  const result = state.uninstallResult || (isTerminalTask(state.uninstallTask) ? state.uninstallTask : null);

  if (!result) {
    meta.textContent = "No uninstall result selected";
    summary.textContent = "Removed, preserved, and leftover items will appear here after a task finishes.";
    viewer.innerHTML = buildEmptyCard("No completed uninstall result yet.");
    return;
  }

  const removed = result.removed_items || [];
  const preserved = result.preserved_items || [];
  const leftovers = result.leftover_items || [];
  const blockedReasons = result.result?.blocked_reasons || [];
  const manualSteps = result.result?.manual_steps || [];
  meta.textContent = `${TASK_STATUS_LABELS[result.status] || result.status} / ${formatDate(result.finished_at || result.updated_at)}${result.duration_ms ? ` / ${formatDuration(result.duration_ms)}` : ""}`;
  const manualReview = result.result?.manual_review_required || preserved.length > 0 || leftovers.length > 0 || blockedReasons.length > 0;
  summary.textContent = manualReview
    ? `${removed.length} removed, ${preserved.length} preserved, ${leftovers.length} leftover. Manual review required.`
    : `${removed.length} removed, ${preserved.length} preserved, ${leftovers.length} leftover.`;

  viewer.innerHTML = [
    buildResultMetrics(result),
    manualReview ? `<div class="result-banner">${escapeHtml(result.result?.summary || "Manual review required for preserved or leftover footprint.")}</div>` : "",
    result.result?.target_summary ? `<div class="result-note">${escapeHtml(result.result.target_summary)}</div>` : "",
    result.result?.rationale ? `<div class="result-note">${escapeHtml(result.result.rationale)}</div>` : "",
    buildStringResultGroup("Blocked Reasons", blockedReasons),
    buildStringResultGroup("Manual Steps", manualSteps),
    buildStepHistoryGroup(result.step_history || []),
    buildResultGroup("Removed", removed),
    buildResultGroup("Preserved", preserved),
    buildResultGroup("Leftovers", leftovers),
    buildLogDetails(result.logs || []),
  ].join("");
}

function buildResultMetrics(result) {
  const stats = [
    ["Duration", formatDuration(result.duration_ms)],
    ["Removed", String((result.removed_items || []).length)],
    ["Preserved", String((result.preserved_items || []).length)],
    ["Leftover", String((result.leftover_items || []).length)],
  ];
  return `
    <div class="result-metric-grid">
      ${stats.map(([label, value]) => `
        <article class="summary-card compact-card result-metric-card">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(value)}</strong>
        </article>
      `).join("")}
    </div>
  `;
}

function buildStringResultGroup(title, items) {
  if (!items || !items.length) {
    return "";
  }
  return `
    <div class="result-group">
      <div class="subsection-head">
        <strong>${escapeHtml(title)}</strong>
        <span class="panel-meta">${escapeHtml(String(items.length))} item(s)</span>
      </div>
      ${items.map((item) => `
        <div class="result-item result-item-note">
          <strong>${escapeHtml(title.slice(0, -1) || "Item")}</strong>
          <p>${escapeHtml(String(item || "--"))}</p>
        </div>
      `).join("")}
    </div>
  `;
}

function buildStepHistoryGroup(stepHistory) {
  if (!stepHistory || !stepHistory.length) {
    return "";
  }
  return `
    <div class="result-group">
      <div class="subsection-head">
        <strong>Step History</strong>
        <span class="panel-meta">${escapeHtml(String(stepHistory.length))} step(s)</span>
      </div>
      ${stepHistory.map((step) => `
        <div class="result-item result-item-note">
          <strong>${escapeHtml(String(step.index).padStart(2, "0"))} / ${escapeHtml(step.label || "--")}</strong>
          <span>${escapeHtml((step.status || "unknown").toUpperCase())}${step.duration_ms ? ` / ${escapeHtml(formatDuration(step.duration_ms))}` : ""}</span>
          <p>${escapeHtml(`${formatDate(step.started_at)} -> ${formatDate(step.finished_at)}`)}</p>
        </div>
      `).join("")}
    </div>
  `;
}

function buildLogDetails(logs) {
  if (!logs || !logs.length) {
    return "";
  }
  return `
    <details class="result-details">
      <summary>Execution logs</summary>
      <div class="log-list">
        ${logs.slice().reverse().map((entry) => `
          <div class="log-item log-${escapeHtml(entry.level || "info")}">
            <span>${escapeHtml(formatDate(entry.at))}</span>
            <strong>${escapeHtml(entry.level || "info")}</strong>
            <p>${escapeHtml(entry.message || "")}</p>
          </div>
        `).join("")}
      </div>
    </details>
  `;
}

function buildResultGroup(title, items) {
  if (!items.length) {
    return `
      <div class="result-group">
        <div class="subsection-head">
          <strong>${escapeHtml(title)}</strong>
          <span class="panel-meta">0 item</span>
        </div>
        ${buildEmptyCard(`No ${title.toLowerCase()} recorded.`)}
      </div>
    `;
  }
  return `
    <div class="result-group">
      <div class="subsection-head">
        <strong>${escapeHtml(title)}</strong>
        <span class="panel-meta">${escapeHtml(String(items.length))} item(s)</span>
      </div>
      ${items.map((item) => `
        <div class="result-item">
          <strong>${escapeHtml(item.type || "item")}</strong>
          <span>${escapeHtml(item.value || item.label || "--")}</span>
          <p>${escapeHtml(item.detail || item.reason || "--")}</p>
        </div>
      `).join("")}
    </div>
  `;
}

function syncButtonState() {
  const running = state.currentJob && ["queued", "running"].includes(state.currentJob.status);
  const button = document.getElementById("startScanBtn");
  if (PUBLIC_SITE_MODE) {
    button.disabled = !hasDownloadAsset();
    button.textContent = hasDownloadAsset() ? "Download Windows Client" : "Release Package Missing";
    return;
  }
  button.disabled = Boolean(running);
  button.textContent = running ? "Scan Running" : "Start Real Scan";
}

function renderEmptyState() {
  syncButtonState();
  syncOperationPanel(null);
  renderExecutiveSummary(null);
  renderProgress({ status: "queued", stage_key: "queued", progress: 0, stage_history: [] });
  renderArtifacts(null);
  renderRuntime(null);
  renderSafetyNotes(null);
  renderHistory();
  renderDomainPortfolio(null);
  renderFindings(null);
  renderEvidencePanel(null);
  renderUninstallPanel();
  renderUninstallResult();
  renderUninstallHistory();
  renderDownloadPanel();
  renderModal();
}

function renderPublicSiteMode() {
  document.title = hasDownloadAsset()
    ? "Police Claw Windows Client Download"
    : "Police Claw Release Package Pending";
  setGlobalNotice(
    hasDownloadAsset() ? "info" : "warn",
    hasDownloadAsset() ? "Download the Windows client" : "Installer package not available",
    hasDownloadAsset()
      ? "The hosted site distributes the installer directly. Real scan and uninstall actions still run locally after the client is installed."
      : "Build dist/release/PoliceClaw-Setup-<version>.exe to enable direct website downloads."
  );
  renderExecutiveSummary(null);
  renderDownloadPanel();
}

function renderGlobalNotice() {
  const node = document.getElementById("globalNotice");
  const notice = state.notice;
  if (!notice) {
    node.className = "inline-notice is-hidden";
    node.innerHTML = "";
    return;
  }
  node.className = `inline-notice notice-${escapeHtml(notice.tone || "info")}`;
  node.innerHTML = `
    <strong>${escapeHtml(notice.title || "Notice")}</strong>
    <p>${escapeHtml(notice.message || "")}</p>
  `;
}

function setGlobalNotice(tone, title, message) {
  state.notice = {
    tone: tone || "info",
    title: title || "Notice",
    message: message || "",
  };
  renderGlobalNotice();
}

function clearGlobalNotice() {
  state.notice = null;
  renderGlobalNotice();
}

function renderGlobalError(message, title = "Workbench Error") {
  setGlobalNotice("error", title, message);
}

function onHistoryClick(event) {
  const card = event.target.closest("[data-job-id]");
  if (!card) {
    return;
  }

  stopPolling();
  loadJob(card.dataset.jobId)
    .then(async () => {
      await fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob));
      if (["queued", "running"].includes(state.currentJob?.status)) {
        startPolling(card.dataset.jobId);
      }
      loadJobs().catch(() => {});
    })
    .catch((error) => renderGlobalError(error.message));
}

function onUninstallHistoryClick(event) {
  const card = event.target.closest("[data-uninstall-id]");
  if (!card) {
    return;
  }

  stopUninstallPolling();
  loadUninstallTask(card.dataset.uninstallId)
    .then(async () => {
      if (isTerminalTask(state.uninstallTask)) {
        await loadUninstallResult(state.uninstallTask.id);
      } else {
        startUninstallPolling(state.uninstallTask.id);
      }
    })
    .catch((error) => renderGlobalError(error.message));
}

function onDomainClick(event) {
  const button = event.target.closest("[data-domain-filter]");
  if (!button) {
    return;
  }

  state.filters.domain = state.filters.domain === button.dataset.domainFilter
    ? "all"
    : button.dataset.domainFilter;
  document.getElementById("domainFilter").value = state.filters.domain;
  renderDomainPortfolio(state.currentJob);
  renderFindings(state.currentJob);
}

function onFindingClick(event) {
  const action = event.target.closest("[data-uninstall-action]");
  if (action) {
    const target = findTargetById(action.dataset.targetId);
    if (!target) {
      return;
    }
    if (action.dataset.uninstallAction === "scope") {
      focusTargetScope(target.id);
    } else {
      openUninstallModal(target.id);
    }
    return;
  }

  const row = event.target.closest("[data-check-id]");
  if (!row || !state.currentJob?.report) {
    return;
  }

  state.selectedCheckId = row.dataset.checkId;
  renderFindings(state.currentJob);
  renderEvidencePanel(state.currentJob);
}

function onTargetActionClick(event) {
  const button = event.target.closest("[data-target-action]");
  if (!button) {
    return;
  }
  if (button.dataset.targetAction === "scope") {
    focusTargetScope(button.dataset.targetId);
  } else {
    openUninstallModal(button.dataset.targetId);
  }
}

function onFilterChange() {
  state.filters.search = document.getElementById("findingsSearch").value.trim();
  state.filters.domain = document.getElementById("domainFilter").value;
  state.filters.status = document.getElementById("statusFilter").value;
  state.filters.sort = document.getElementById("sortFilter").value;
  renderDomainPortfolio(state.currentJob);
  renderFindings(state.currentJob);
}

function onModalShellClick(event) {
  if (event.target.closest("[data-modal-close='true']")) {
    closeUninstallModal();
  }
}

function onModalInputChange() {
  state.uninstallModalState.mode = document.getElementById("uninstallMode").value;
  state.uninstallModalState.remove_startup = document.getElementById("removeStartupToggle").checked;
  state.uninstallModalState.remove_cache = document.getElementById("removeCacheToggle").checked;
  state.uninstallModalState.remove_config = document.getElementById("removeConfigToggle").checked;
  state.uninstallModalState.remove_binary = document.getElementById("removeBinaryToggle").checked;
  state.uninstallModalState.confirmation_text = document.getElementById("confirmationText").value.trim();
  state.uninstallModalState.error = "";
  renderModal();
}

function openUninstallModal(targetId) {
  const target = findTargetById(targetId);
  if (!target) {
    return;
  }
  state.uninstallModalState = {
    open: true,
    targetId,
    mode: "standard",
    remove_startup: Boolean(target.startup_entries?.length),
    remove_cache: Boolean(target.cache_paths?.length),
    remove_config: Boolean(target.config_paths?.length),
    remove_binary: Boolean(target.remove_binary_allowed),
    confirmation_text: "",
    error: target.uninstall_supported ? "" : (target.unsupported_reason || "Target is not safe to uninstall."),
  };
  renderModal();
}

function focusTargetScope(targetId) {
  const target = findTargetById(targetId);
  if (!target) {
    return;
  }
  const nextCheckId = (target.matched_check_ids || []).find((checkId) =>
    state.currentJob?.report?.checks?.some((check) => check.id === checkId)
  );
  if (nextCheckId) {
    state.selectedCheckId = nextCheckId;
    renderFindings(state.currentJob);
    renderEvidencePanel(state.currentJob);
  }
  const relatedTask = getTaskForTarget(target);
  if (relatedTask) {
    state.uninstallTask = relatedTask;
    renderUninstallPanel();
    if (isTerminalTask(relatedTask)) {
      loadUninstallResult(relatedTask.id).catch((error) => renderGlobalError(error.message));
    } else if (!state.uninstallPollingTaskId || state.uninstallPollingTaskId !== relatedTask.id) {
      startUninstallPolling(relatedTask.id);
    }
  }
}

function closeUninstallModal() {
  state.uninstallModalState = buildModalState();
  renderModal();
}

function renderModal() {
  const modal = document.getElementById("uninstallModal");
  const target = findTargetById(state.uninstallModalState.targetId);
  const submitBtn = document.getElementById("uninstallSubmitBtn");
  const errorNode = document.getElementById("uninstallModalError");

  modal.classList.toggle("is-hidden", !state.uninstallModalState.open);
  modal.setAttribute("aria-hidden", String(!state.uninstallModalState.open));

  document.getElementById("uninstallModalTarget").textContent = target?.name || "--";
  document.getElementById("uninstallModalRisk").textContent = target
    ? `${target.risk_level} / ${target.risk_score} / ${target.matched_findings_count} matched findings / ${formatPercent(target.confidence || 0)} confidence`
    : "Risk --";
  document.getElementById("uninstallModalReason").textContent = target?.uninstall_supported
    ? `${target.target_summary || target.evidence_summary || "The backend validates every path again before any file operation happens."}`
    : (target?.unsupported_reason || target?.rationale || "Select a target to review scope.");

  document.getElementById("uninstallMode").value = state.uninstallModalState.mode;
  document.getElementById("removeStartupToggle").checked = Boolean(state.uninstallModalState.remove_startup);
  document.getElementById("removeCacheToggle").checked = Boolean(state.uninstallModalState.remove_cache);
  document.getElementById("removeConfigToggle").checked = Boolean(state.uninstallModalState.remove_config);
  document.getElementById("removeBinaryToggle").checked = Boolean(state.uninstallModalState.remove_binary);
  document.getElementById("removeBinaryToggle").disabled = Boolean(target && !target.remove_binary_allowed);
  document.getElementById("confirmationText").value = state.uninstallModalState.confirmation_text;

  document.getElementById("uninstallScopeList").innerHTML = target
    ? buildTargetScopeCards(target)
    : buildEmptyCard("No target selected.");

  const canSubmit = Boolean(
    state.uninstallModalState.open &&
    target &&
    target.uninstall_supported &&
    state.uninstallModalState.confirmation_text === UNINSTALL_CONFIRMATION_TEXT
  );
  submitBtn.disabled = !canSubmit;
  errorNode.textContent = state.uninstallModalState.error || "";
}

function buildTargetScopeCards(target) {
  const cards = [
    {
      title: "Disposition",
      count: target.planned_actions?.length || 0,
      body: target.planned_actions?.length
        ? `${target.planned_actions.join(" | ")}${target.rationale ? ` | ${target.rationale}` : ""}`
        : (target.rationale || target.unsupported_reason || "No executable scope was inferred."),
    },
    {
      title: "Terminate processes",
      count: target.pids?.length || 0,
      body: target.pids?.length ? target.pids.join(", ") : "No linked active process.",
    },
    {
      title: "Remove startup entries",
      count: target.startup_entries?.length || 0,
      body: target.startup_entries?.length
        ? target.startup_entries.map((entry) => `${entry.kind}: ${entry.label}`).join(" | ")
        : "No user-level persistence discovered.",
    },
    {
      title: "Remove config",
      count: target.config_paths?.length || 0,
      body: target.config_paths?.length ? target.config_paths.join(" | ") : "No explicit config path.",
    },
    {
      title: "Remove cache",
      count: target.cache_paths?.length || 0,
      body: target.cache_paths?.length ? target.cache_paths.join(" | ") : "No explicit cache path.",
    },
    {
      title: "Remove binaries",
      count: target.executable_paths?.length || 0,
      body: target.remove_binary_allowed
        ? (target.executable_paths?.length ? target.executable_paths.join(" | ") : "No explicit binary file.")
        : (target.remove_binary_reason || "Binary path will be preserved for manual review."),
    },
  ];

  return cards.map((card) => `
    <article class="target-card">
      <div class="target-card-head">
        <div>
          <strong>${escapeHtml(card.title)}</strong>
          <span>${escapeHtml(String(card.count))} item(s)</span>
        </div>
      </div>
      <div class="target-card-body">
        <div>${escapeHtml(card.body)}</div>
      </div>
    </article>
  `).join("");
}

async function submitUninstall() {
  const target = findTargetById(state.uninstallModalState.targetId);
  if (!target) {
    return;
  }
  if (state.uninstallModalState.confirmation_text !== UNINSTALL_CONFIRMATION_TEXT) {
    state.uninstallModalState.error = "Confirmation text does not match.";
    renderModal();
    return;
  }

  try {
    clearGlobalNotice();
    const task = await requestJson(
      "/api/uninstall",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: target.id,
          mode: state.uninstallModalState.mode,
          job_id: state.uninstallSourceJobId,
          remove_startup: state.uninstallModalState.remove_startup,
          remove_cache: state.uninstallModalState.remove_cache,
          remove_config: state.uninstallModalState.remove_config,
          remove_binary: state.uninstallModalState.remove_binary,
          confirmation_text: state.uninstallModalState.confirmation_text,
        }),
      },
      "Unable to create the uninstall task.",
    );
    closeUninstallModal();
    state.uninstallTask = task;
    state.uninstallResult = null;
    renderUninstallPanel();
    startUninstallPolling(task.id);
    await Promise.all([loadUninstallHistory(), fetchUninstallTargets(getRequestedUninstallJobId(state.currentJob))]);
  } catch (error) {
    state.uninstallModalState.error = error.message;
    renderGlobalError(error.message, "Uninstall request failed");
    renderModal();
  }
}

function getSelectedCheck(job) {
  const checks = job?.report?.checks || [];
  return checks.find((check) => check.id === state.selectedCheckId) || null;
}

function ensureSelectedCheck(job) {
  const checks = job?.report?.checks || [];
  if (!checks.length) {
    state.selectedCheckId = null;
    return;
  }
  if (checks.some((check) => check.id === state.selectedCheckId)) {
    return;
  }
  const topRisk = [...checks]
    .filter((check) => isFlagged(check))
    .sort((left, right) => right.risk_score - left.risk_score)[0];
  state.selectedCheckId = (topRisk || checks[0]).id;
}

function getRelatedTargets(checkId) {
  return getRenderableUninstallTargets().filter((target) => (target.matched_check_ids || []).includes(checkId));
}

function pickPrimaryTarget(targets) {
  if (!targets.length) {
    return null;
  }
  return [...targets].sort((left, right) => {
    const leftRank = getTargetPriority(left);
    const rightRank = getTargetPriority(right);
    return leftRank - rightRank || right.risk_score - left.risk_score || right.confidence - left.confidence;
  })[0];
}

function findTargetById(targetId) {
  return state.uninstallTargets.find((target) => target.id === targetId) || null;
}

function applyFindingFilters(checks) {
  const filtered = checks.filter((check) => {
    const searchFields = [
      check.id,
      check.label,
      check.description,
      check.domain,
      check.domain_name,
    ];
    const matchesSearch = !state.filters.search || searchFields.some((field) =>
      String(field || "").toLowerCase().includes(state.filters.search.toLowerCase())
    );
    const matchesDomain = state.filters.domain === "all" || check.domain === state.filters.domain;
    const matchesStatus = (
      state.filters.status === "all" ||
      (state.filters.status === "risk" && isFlagged(check)) ||
      (state.filters.status === "clear" && !isFlagged(check)) ||
      (state.filters.status === "evidence" && Number(check.evidence_count || 0) > 0)
    );
    return matchesSearch && matchesDomain && matchesStatus;
  });

  return filtered.sort((left, right) => {
    if (state.filters.sort === "evidence") {
      return (right.evidence_count || 0) - (left.evidence_count || 0) || right.risk_score - left.risk_score;
    }
    if (state.filters.sort === "domain") {
      return String(left.domain_name).localeCompare(String(right.domain_name), "zh-CN") ||
        right.risk_score - left.risk_score;
    }
    if (state.filters.sort === "name") {
      return displayCheckTitle(left).localeCompare(displayCheckTitle(right), "zh-CN");
    }
    return right.risk_score - left.risk_score || (right.evidence_count || 0) - (left.evidence_count || 0);
  });
}

function syncDomainFilterOptions(domains) {
  const select = document.getElementById("domainFilter");
  const current = state.filters.domain;
  const options = ['<option value="all">All Domains</option>'].concat(
    domains.map((domain) => `<option value="${domain.id}">${escapeHtml(safeText(domain.name, humanizeSlug(domain.id)))}</option>`)
  );
  select.innerHTML = options.join("");
  select.value = domains.some((domain) => domain.id === current) || current === "all" ? current : "all";
  state.filters.domain = select.value;
}

function getDomainEntries(report) {
  const checks = report.checks || [];
  return Object.entries(report.summary.domain_summary || {}).map(([id, summary]) => ({
    id,
    ...summary,
    checks: checks.filter((check) => check.domain === id),
  }));
}

function getPosture(report) {
  const visibleTargets = getRenderableUninstallTargets();
  const autoRemediableTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const handledTargets = autoRemediableTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "removed" || remediation.status === "mitigated";
  });
  const blockedHighRisk = visibleTargets.filter((target) => !target.uninstall_supported && Number(target.risk_score || 0) >= HIGH_RISK_THRESHOLD);
  const manualReviewTargets = visibleTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "partial" || remediation.status === "manual-review";
  });

  if (autoRemediableTargets.length && handledTargets.length === autoRemediableTargets.length && !blockedHighRisk.length && !manualReviewTargets.length) {
    return {
      label: "Remediated",
      headline: "All currently supported high-risk targets have completed uninstall handling.",
      badgeClass: "badge-good",
    };
  }
  if (autoRemediableTargets.length && handledTargets.length === autoRemediableTargets.length && (blockedHighRisk.length || manualReviewTargets.length)) {
    return {
      label: "Manual Review",
      headline: "Auto-remediation is complete, but residual review or blocked targets still need manual follow-up.",
      badgeClass: "badge-warn",
    };
  }

  const totalRisks = report.summary?.total_risks || 0;
  const maxRisk = report.summary?.max_risk_score || 0;
  if (totalRisks === 0) {
    return {
      label: "Stable",
      headline: "No high-confidence risk hotspots were detected in the latest report.",
      badgeClass: "badge-good",
    };
  }
  if (totalRisks <= 6 && maxRisk < 70) {
    return {
      label: "Contained",
      headline: "A small number of findings remain, but the overall posture is controlled.",
      badgeClass: "badge-warn",
    };
  }
  if (totalRisks <= 12) {
    return {
      label: "Escalated",
      headline: "Risk exposure is concentrated enough to require formal review and action.",
      badgeClass: "badge-warn",
    };
  }
  return {
    label: "High Pressure",
    headline: "The latest report shows a dense concentration of high-risk findings.",
    badgeClass: "badge-risk",
  };
}

function buildNarrative(report) {
  const domains = getDomainEntries(report)
    .sort((left, right) => right.risks - left.risks || right.max_score - left.max_score);
  const topDomain = domains[0];
  const activeSignals = report.runtime?.result_overview?.active_signals ?? "--";
  const visibleTargets = getRenderableUninstallTargets();
  const targetLine = visibleTargets.length
    ? ` The backend inferred ${visibleTargets.length} uninstall target(s) for this report.`
    : state.uninstallTargets.length && state.uninstallSourceScanId
      ? ` Uninstall targets are currently sourced from completed scan ${state.uninstallSourceScanId}.`
    : "";
  if (!topDomain) {
    return `The scan covered ${report.summary.total_checks} checks and did not form a material risk cluster.${targetLine}`;
  }
  return `The latest scan ran on ${report.host} at ${report.timestamp}. It covered ${report.summary.total_checks} checks, flagged ${report.summary.total_risks} findings, and activated ${activeSignals} runtime signals. The hottest domain is ${safeText(topDomain.name, humanizeSlug(topDomain.id))} with ${topDomain.risks} flagged finding(s) and a peak score of ${topDomain.max_score}.${targetLine}`;
}

function buildRecommendations(report) {
  const flaggedChecks = [...(report.checks || [])]
    .filter((check) => isFlagged(check))
    .sort((left, right) => right.risk_score - left.risk_score || (right.evidence_count || 0) - (left.evidence_count || 0));
  const visibleTargets = getRenderableUninstallTargets();
  const urgentTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level === "full" && getRemediationStateForTarget(target).status === "ready");
  const cleanupTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level === "cleanup" && getRemediationStateForTarget(target).status === "ready");
  const terminateTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level === "terminate_only" && getRemediationStateForTarget(target).status === "ready");
  const partialTargets = visibleTargets.filter((target) => getRemediationStateForTarget(target).status === "partial");
  const blockedTargets = visibleTargets.filter((target) => !target.uninstall_supported && Number(target.risk_score || 0) >= HIGH_RISK_THRESHOLD);
  const autoRemediableTargets = visibleTargets.filter((target) => target.uninstall_supported && target.support_level !== "terminate_only");
  const handledTargets = autoRemediableTargets.filter((target) => {
    const remediation = getRemediationStateForTarget(target);
    return remediation.status === "removed" || remediation.status === "mitigated";
  });

  if (!flaggedChecks.length) {
    return [
      {
        tag: "Baseline",
        tone: "neutral",
        title: "Archive the baseline report",
        body: "No significant findings remain. Keep the JSON or DOCX export as the current workstation baseline.",
      },
      {
        tag: "Cadence",
        tone: "neutral",
        title: "Keep the cadence",
        body: "Run the same scan flow again after meaningful environment or tooling changes.",
      },
    ];
  }

  const recommendations = [];
  if (autoRemediableTargets.length && handledTargets.length === autoRemediableTargets.length) {
    recommendations.push({
      tag: blockedTargets.length || partialTargets.length ? "Review Remaining" : "Complete",
      tone: blockedTargets.length || partialTargets.length ? "warn" : "good",
      title: "High-priority remediation is complete",
      body: blockedTargets.length || partialTargets.length
        ? "All directly supported targets were processed. Review residual items and blocked targets before closing the report."
        : "All currently supported removable targets for this report have been handled. Review residual notes and export the audit trail.",
    });
  }
  if (urgentTargets[0]) {
    recommendations.push({
      tag: "Urgent uninstall",
      tone: "risk",
      title: `Review ${urgentTargets[0].display_name || urgentTargets[0].name} first`,
      body: urgentTargets[0].target_summary || `This target is the highest-priority removable footprint with a risk score of ${urgentTargets[0].risk_score} and ${formatPercent(urgentTargets[0].confidence || 0)} confidence.`,
    });
  }
  if (cleanupTargets[0]) {
    recommendations.push({
      tag: "Cleanup available",
      tone: "warn",
      title: `Clean residual footprint for ${cleanupTargets[0].display_name || cleanupTargets[0].name}`,
      body: cleanupTargets[0].rationale || "The runner can remove persistence, config, and cache, but the binary path remains protected.",
    });
  }
  if (terminateTargets[0]) {
    recommendations.push({
      tag: "Terminate only",
      tone: "neutral",
      title: `Contain ${terminateTargets[0].display_name || terminateTargets[0].name}`,
      body: terminateTargets[0].rationale || "Only the active process can be safely terminated with the current footprint.",
    });
  }
  if (partialTargets[0]) {
    recommendations.push({
      tag: "Manual review",
      tone: "warn",
      title: `Finish manual review for ${partialTargets[0].display_name || partialTargets[0].name}`,
      body: "A previous uninstall run preserved or left behind some items. Review the residual panel before rerunning anything.",
    });
  }
  if (blockedTargets[0]) {
    recommendations.push({
      tag: "Blocked",
      tone: "risk",
      title: `Review blocked target ${blockedTargets[0].display_name || blockedTargets[0].name}`,
      body: blockedTargets[0].unsupported_reason || blockedTargets[0].rationale || "The inferred target is real enough to review, but not safe enough to auto-remove.",
    });
  }
  if (flaggedChecks[0]) {
    recommendations.push({
      tag: "Validate",
      tone: "neutral",
      title: `Validate ${displayCheckTitle(flaggedChecks[0])}`,
      body: "Start with the top finding, confirm the evidence, and then decide whether to use the uninstall flow or manual containment.",
    });
  }
  if (!visibleTargets.length || urgentTargets.length || cleanupTargets.length || blockedTargets.length) {
    recommendations.push({
      tag: "Audit",
      tone: "neutral",
      title: "Export the report trail",
      body: "Keep the JSON or DOCX report with the uninstall task logs so the containment path remains auditable.",
    });
  }
  return recommendations.slice(0, 4);
}

function renderUninstallRecommendations(report) {
  return buildRecommendations(report);
}

function getRequestedUninstallJobId(job) {
  if (!job || job.status !== "completed") {
    return null;
  }
  return job.id;
}

function getRenderableUninstallTargets(job = state.currentJob) {
  if (!state.uninstallTargets.length) {
    return [];
  }
  if (!job) {
    return state.uninstallTargets;
  }
  if (job.status === "completed" && state.uninstallSourceJobId !== job.id) {
    return [];
  }
  return state.uninstallTargets;
}

function getCurrentUninstallScope(job = state.currentJob) {
  if (job?.status === "completed") {
    return {
      jobId: job.id,
      scanId: job.report?.scan_id || job.scan_id || null,
    };
  }
  return {
    jobId: state.uninstallSourceJobId,
    scanId: state.uninstallSourceScanId,
  };
}

function taskMatchesSource(task, scope = getCurrentUninstallScope()) {
  if (!task) {
    return false;
  }
  if (!scope.jobId && !scope.scanId) {
    return true;
  }
  if (scope.jobId && task.source_job_id) {
    return task.source_job_id === scope.jobId;
  }
  if (scope.scanId && task.source_scan_id) {
    return task.source_scan_id === scope.scanId;
  }
  return true;
}

function getScopedUninstallHistory(job = state.currentJob) {
  const scope = getCurrentUninstallScope(job);
  return state.uninstallHistory.filter((task) => taskMatchesSource(task, scope));
}

function getRemediationStateForTarget(target) {
  const task = getTaskForTarget(target);
  if (task) {
    if (task.status === "success") {
      return target.support_level === "full"
        ? { status: "removed", label: "Removed", detail: "Target uninstall completed." }
        : { status: "mitigated", label: "Mitigated", detail: "Controlled cleanup or containment completed." };
    }
    if (task.status === "partial") {
      return { status: "partial", label: "Partial", detail: "Residual review is still required." };
    }
    if (task.status === "failed") {
      return { status: "manual-review", label: "Manual Review", detail: "The last uninstall run failed and needs review." };
    }
    if (["pending", "running"].includes(task.status)) {
      return { status: "running", label: "In Progress", detail: "Removal task is currently active." };
    }
  }
  if (target.resolved || state.removedTargetIds.has(target.id)) {
    return target.support_level === "full"
      ? { status: "removed", label: "Removed", detail: "Linked target completed uninstall handling." }
      : { status: "mitigated", label: "Mitigated", detail: "Linked target received controlled cleanup or containment." };
  }
  if (!target.uninstall_supported) {
    if (MANUAL_REVIEW_BLOCK_CODES.has(target.blocked_reason_code)) {
      return { status: "manual-review", label: "Manual Review", detail: target.unsupported_reason || "Manual review is required." };
    }
    return { status: "blocked", label: "Blocked", detail: target.unsupported_reason || "Auto-removal is blocked." };
  }
  return { status: "ready", label: "", detail: "" };
}

function refreshRemovedTargetIds() {
  const resolvedIds = state.uninstallTargets
    .filter((target) => target.resolved)
    .map((target) => target.id);
  const historyIds = getScopedUninstallHistory()
    .filter((task) => task.status === "success")
    .map((task) => task.target_id);
  state.removedTargetIds = new Set([...resolvedIds, ...historyIds]);
}

function getTargetPriority(target) {
  const remediation = getRemediationStateForTarget(target);
  if (remediation.status === "running") {
    return 0;
  }
  if (target.support_level === "full" && remediation.status === "ready") {
    return 1;
  }
  if (target.support_level === "cleanup" && remediation.status === "ready") {
    return 2;
  }
  if (target.support_level === "terminate_only" && remediation.status === "ready") {
    return 3;
  }
  if (remediation.status === "removed" || remediation.status === "mitigated") {
    return 4;
  }
  if (remediation.status === "partial") {
    return 5;
  }
  if (remediation.status === "manual-review") {
    return 6;
  }
  if (!target.uninstall_supported) {
    return 7;
  }
  return 8;
}

function getTaskForTarget(target) {
  if (!target) {
    return null;
  }
  const scopedHistory = getScopedUninstallHistory();
  const direct = scopedHistory.find((task) => task.target_id === target.id);
  if (direct) {
    return direct;
  }
  return scopedHistory.find((task) => task.target_name === (target.display_name || target.name)) || null;
}

function markRelatedFindingsHandled(checkId) {
  const relatedTargets = getRelatedTargets(checkId);
  if (!relatedTargets.length) {
    return { status: "none", label: "", detail: "" };
  }
  const remediations = relatedTargets.map((target) => getRemediationStateForTarget(target));
  if (remediations.some((item) => item.status === "running")) {
    return { status: "running", label: "In Progress", detail: "Removal task is currently active." };
  }
  if (remediations.some((item) => item.status === "partial")) {
    return { status: "partial", label: "Partial", detail: "A previous uninstall pass needs manual follow-up." };
  }
  if (remediations.some((item) => item.status === "manual-review")) {
    return { status: "manual-review", label: "Manual Review", detail: "Only manual follow-up remains for this finding." };
  }
  if (remediations.some((item) => item.status === "removed")) {
    return { status: "removed", label: "Removed", detail: "Linked target completed uninstall handling." };
  }
  if (remediations.some((item) => item.status === "mitigated")) {
    return { status: "mitigated", label: "Mitigated", detail: "Linked target received controlled cleanup or containment." };
  }
  if (relatedTargets.every((target) => !target.uninstall_supported)) {
    return { status: "blocked", label: "Blocked", detail: "Only blocked targets were inferred for this finding." };
  }
  return { status: "ready", label: "", detail: "" };
}

function isFlagged(check) {
  return Number(check?.risk_score || 0) > 0;
}

function isTerminalTask(task) {
  return Boolean(task) && TASK_TERMINAL_STATUSES.has(task.status);
}

function displayCheckTitle(check) {
  return safeText(check.label, humanizeSlug(check.id));
}

function displayCheckDescription(check) {
  return safeText(check.description, `Check identifier: ${check.id}`);
}

function getStageLabel(stageKey, stageLabel) {
  const stage = STAGES.find((item) => item.key === stageKey);
  if (stage) {
    return stage.label;
  }
  return safeText(stageLabel, "Queued");
}

function safeText(value, fallback) {
  const text = String(value || "").trim();
  if (!text) {
    return fallback;
  }
  return looksBrokenText(text) ? fallback : text;
}

function looksBrokenText(text) {
  return /[�鈥馃锛€]/.test(text);
}

function humanizeSlug(value) {
  return String(value || "")
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatPercent(value) {
  const numeric = Number(value || 0);
  return `${Math.round(numeric * 100)}%`;
}

function formatFileSize(value) {
  const numeric = Number(value || 0);
  if (!numeric) {
    return "--";
  }
  const units = ["B", "KB", "MB", "GB"];
  let size = numeric;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const precision = unitIndex === 0 ? 0 : size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function formatDuration(value) {
  const numeric = Number(value || 0);
  if (!numeric) {
    return "--";
  }
  if (numeric < 1000) {
    return `${numeric} ms`;
  }
  const seconds = numeric / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)} s`;
  }
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

function formatDate(value) {
  if (!value) {
    return "--";
  }
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function buildEmptyCard(text) {
  return `<div class="empty-card">${escapeHtml(text)}</div>`;
}

function renderDownloadPanel() {
  const topLink = document.getElementById("downloadTopLink");
  const heroLink = document.getElementById("heroDownloadLink");
  const heroMeta = document.getElementById("heroDownloadMeta");
  const panelMeta = document.getElementById("downloadPanelMeta");
  const panelSummary = document.getElementById("downloadPanelSummary");
  const factList = document.getElementById("downloadFactList");
  const button = document.getElementById("downloadClientBtn");
  const available = hasDownloadAsset();
  const url = available ? DOWNLOAD_ASSET.url : "#";
  const label = available
    ? `Windows installer ${DOWNLOAD_ASSET.version || ""}`.trim()
    : "No installer package attached";

  [topLink, heroLink].forEach((link) => {
    link.href = url;
    link.classList.toggle("is-hidden", !available);
  });

  heroMeta.textContent = available
    ? `${label} / ${formatFileSize(DOWNLOAD_ASSET.sizeBytes)}`
    : "Build dist/release/PoliceClaw-Setup-<version>.exe to expose a direct website download.";

  panelMeta.textContent = available
    ? `${DOWNLOAD_ASSET.filename} / ${formatFileSize(DOWNLOAD_ASSET.sizeBytes)}`
    : "No release package detected yet";
  panelSummary.textContent = available
    ? "The hosted site can hand off the installer directly. After installation, the Windows client opens the same local workbench for scan and uninstall."
    : "Build the Windows release first. Once the installer exists under dist/release, the website can serve it directly.";
  factList.innerHTML = [
    ["Version", DOWNLOAD_ASSET.version || "--"],
    ["Package", DOWNLOAD_ASSET.filename || "--"],
    ["Size", available ? formatFileSize(DOWNLOAD_ASSET.sizeBytes) : "--"],
    ["Scope", "Local Windows client"],
  ].map(([labelText, value]) => `
    <div class="runtime-item">
      <span class="runtime-key">${escapeHtml(String(labelText))}</span>
      <strong class="runtime-value">${escapeHtml(String(value))}</strong>
    </div>
  `).join("");

  button.href = url;
  button.setAttribute("aria-disabled", available ? "false" : "true");
  button.classList.toggle("is-disabled", !available);
  button.textContent = available ? "Download Windows Client" : "Installer Unavailable";
}

function hasDownloadAsset() {
  return Boolean(DOWNLOAD_ASSET.available && DOWNLOAD_ASSET.url);
}

function openDownloadAsset() {
  if (!hasDownloadAsset()) {
    renderGlobalError("No Windows installer package is attached to the hosted site yet.", "Download Unavailable");
    return;
  }
  window.location.href = DOWNLOAD_ASSET.url;
}

async function requestJson(url, options = {}, fallbackMessage = "Request failed.") {
  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers: buildRequestHeaders(options.headers || {}),
    });
  } catch (error) {
    throw new Error(fallbackMessage);
  }
  return parseJson(response, fallbackMessage);
}

function buildRequestHeaders(headers = {}) {
  const merged = new Headers(headers);
  merged.set("Accept", "application/json");
  if (API_TOKEN) {
    merged.set(API_HEADER_NAME, API_TOKEN);
  }
  return merged;
}

async function parseJson(response, fallbackMessage = "Request failed.") {
  const rawText = await response.text();
  let payload = {};
  if (rawText) {
    try {
      payload = JSON.parse(rawText);
    } catch (error) {
      payload = {};
    }
  }
  if (!response.ok) {
    const message = payload.message || payload.error || `${fallbackMessage} (${response.status})`;
    throw new Error(message);
  }
  if (payload && typeof payload === "object" && !Array.isArray(payload) && Object.prototype.hasOwnProperty.call(payload, "ok")) {
    const { ok, ...rest } = payload;
    return rest;
  }
  return payload;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
