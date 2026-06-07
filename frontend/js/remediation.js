const API_BASE = "/api/remediation";

document.addEventListener("DOMContentLoaded", function () {
  loadRemediations();
  loadRemediationHistory();
});

async function loadRemediations() {
  const container = document.getElementById("remediation-container");

  try {
    const scanId = localStorage.getItem("lastScanId");
    let url = API_BASE + "/latest";
    if (scanId) {
      url = API_BASE + "/scan/" + scanId;
    }

    const response = await fetch(url);
    if (!response.ok) {
      const text = await response.text();
      let detail = response.statusText;
      try {
        const errBody = JSON.parse(text);
        detail = errBody.detail || detail;
      } catch (e) {
        if (text) detail = text.substring(0, 200);
      }
      throw new Error(detail);
    }
    const remediations = await response.json();

    if (!remediations.length) {
      container.innerHTML =
        '<div class="empty-state"><p>No failed services requiring remediation. ' +
        "All services passed the security gate, or run a scan first.</p></div>";
      return;
    }

    container.innerHTML = remediations.map(renderRemediationCard).join("");
    bindCopyButtons();
    bindDependencyCopyButtons();

    if (window.location.hash) {
      var target = document.querySelector(window.location.hash);
      if (target) {
        setTimeout(function () {
          target.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 300);
      }
    }
  } catch (error) {
    container.innerHTML =
      '<div class="alert alert-error">Failed to load remediations: ' +
      escapeHtml(error.message) + "</div>";
  }
}

async function loadRemediationHistory() {
  const panel = document.getElementById("history-panel");
  const tbody = document.getElementById("history-table-body");

  try {
    const scanId = localStorage.getItem("lastScanId");
    let url = API_BASE + "/history/latest";
    if (scanId) {
      url = API_BASE + "/history/scan/" + scanId;
    }

    const response = await fetch(url);
    if (!response.ok) {
      panel.style.display = "none";
      return;
    }
    const history = await response.json();

    if (!history.length) {
      panel.style.display = "none";
      return;
    }

    panel.style.display = "block";
    tbody.innerHTML = history.map(function (h) {
      const remaining = h.remaining_critical + h.remaining_high +
        h.remaining_medium + h.remaining_low;
      const stateClass = h.remediation_state.toLowerCase().replace(/_/g, "-");
      const date = new Date(h.created_at).toLocaleString();

      return (
        "<tr>" +
        "<td><strong>" + escapeHtml(h.service_name) + "</strong><br>" +
        "<small style='color:var(--text-muted)'>" + escapeHtml(h.dockerfile_path) + "</small></td>" +
        '<td><span class="state-badge ' + stateClass + '">' + formatState(h.remediation_state) + "</span></td>" +
        "<td>" + h.original_score + "</td>" +
        "<td>" + h.score_after_remediation + "</td>" +
        "<td>" + remaining + " (C:" + h.remaining_critical + " H:" + h.remaining_high +
        " M:" + h.remaining_medium + " L:" + h.remaining_low + ")</td>" +
        "<td><strong>" + h.improvement_percentage + "%</strong></td>" +
        "<td>" + date + "</td>" +
        "</tr>"
      );
    }).join("");
  } catch (error) {
    panel.style.display = "none";
  }
}

function formatState(state) {
  return state.replace("REMEDIATION_", "").replace(/_/g, " ");
}

function formatDecision(decision) {
  return decision === "PASS_WITH_RISK" ? "PASS WITH RISK" : decision;
}

function decisionClass(decision) {
  return decision.toLowerCase().replace(/_/g, "-");
}

function renderRemediationCard(rem) {
  const isAvailable = rem.remediation_state === "REMEDIATION_AVAILABLE";
  const isApplied = rem.remediation_state === "REMEDIATION_APPLIED";
  const isExhausted = rem.remediation_state === "REMEDIATION_EXHAUSTED";

  const stateClass = rem.remediation_state.toLowerCase().replace(/_/g, "-");
  const statusBannerClass = isApplied ? "applied" : isExhausted ? "exhausted" : "available";

  const vulnRows = rem.vulnerabilities_found
    .map(function (v) {
      const source = v.remediation_source || (v.classification === "FIXABLE" ? "Dockerfile" : "-");
      return (
        "<tr>" +
        "<td>" + escapeHtml(v.cve_id) + "</td>" +
        '<td><span class="severity-badge ' + v.severity.toLowerCase() + '">' + v.severity + "</span></td>" +
        "<td>" + escapeHtml(v.package_name) + "</td>" +
        "<td>" + escapeHtml(v.installed_version || "-") + "</td>" +
        "<td>" + escapeHtml(v.fixed_version || "-") + "</td>" +
        "<td>" + escapeHtml(source) + "</td>" +
        "<td>" + escapeHtml(v.classification || "-") + "</td>" +
        "</tr>"
      );
    })
    .join("");

  const rootCauses = rem.root_cause_analysis
    .map(function (c) { return "<li>" + escapeHtml(c) + "</li>"; })
    .join("");

  const fixes = rem.recommended_fixes
    .map(function (f) { return "<li>" + escapeHtml(f) + "</li>"; })
    .join("");

  var dependencySection = "";
  const pendingDeps = (rem.dependency_fixes || []).filter(function (f) { return !f.applied; });
  if (pendingDeps.length) {
    const grouped = {};
    pendingDeps.forEach(function (fix) {
      if (!grouped[fix.source_file]) grouped[fix.source_file] = [];
      grouped[fix.source_file].push(fix);
    });

    const depCards = Object.keys(grouped).map(function (sourceFile) {
      const fixes = grouped[sourceFile];
      const items = fixes.map(function (fix, idx) {
        const fixId = "dep-fix-" + rem.service_id + "-" + idx;
        return (
          '<div class="dependency-fix-item">' +
          "<div><strong>" + escapeHtml(fix.package_name) + "</strong></div>" +
          '<div class="dependency-fix-row"><span class="label">Current:</span><code>' + escapeHtml(fix.current) + "</code></div>" +
          '<div class="dependency-fix-row"><span class="label">Recommended:</span><code class="recommended" id="' + fixId + '">' + escapeHtml(fix.recommended) + "</code></div>" +
          '<div class="dependency-fix-row"><span class="label">Reason:</span><span>' + escapeHtml(fix.reason) + "</span></div>" +
          '<button class="btn btn-secondary btn-sm copy-dep-btn" data-target="' + fixId + '">Copy Fix</button>' +
          "</div>"
        );
      }).join("");

      return (
        '<div class="dependency-file-card">' +
        "<h4>" + escapeHtml(sourceFile) + "</h4>" + items +
        "</div>"
      );
    }).join("");

    dependencySection =
      '<div class="remediation-section">' +
      "<h3>4. Dependency Fixes</h3>" +
      '<p class="dependency-intro">Update dependency files in your repository. Deployment remains <strong>FAIL</strong> until these fixes are applied and the image is re-scanned.</p>' +
      '<div class="dependency-fixes-grid">' + depCards + "</div></div>";
  }

  var dockerfileSection = "";
  const dockerfileSectionNum = pendingDeps.length ? "5" : "4";
  if (isAvailable && rem.show_generate_fix && rem.updated_dockerfile) {
    dockerfileSection =
      '<div class="remediation-section">' +
      "<h3>" + dockerfileSectionNum + ". Updated Dockerfile</h3>" +
      '<div class="dockerfile-compare">' +
      '<div class="dockerfile-panel">' +
      "<h4>Current Dockerfile</h4>" +
      '<pre class="code-block"><code>' + escapeHtml(rem.current_dockerfile) + "</code></pre>" +
      "</div>" +
      '<div class="dockerfile-panel updated-panel">' +
      '<h4>Updated Dockerfile <span class="panel-badge">Complete Replacement</span></h4>' +
      '<pre class="code-block updated-code" id="updated-dockerfile-' + rem.service_id + '"><code>' +
      escapeHtml(rem.updated_dockerfile) + "</code></pre>" +
      '<div class="btn-group">' +
      '<button class="btn btn-primary copy-btn" data-service-id="' + rem.service_id + '">Copy Updated Dockerfile</button>' +
      '<a href="' + API_BASE + "/service/" + rem.service_id + '/download" class="btn btn-secondary download-btn" download>Download Updated Dockerfile</a>' +
      "</div></div></div></div>";
  } else if (rem.show_generate_fix || rem.updated_dockerfile || isApplied || isExhausted) {
    dockerfileSection =
      '<div class="remediation-section">' +
      "<h3>" + dockerfileSectionNum + ". Dockerfile Status</h3>" +
      '<div class="dockerfile-panel">' +
      "<h4>Current Dockerfile</h4>" +
      '<pre class="code-block"><code>' + escapeHtml(rem.current_dockerfile) + "</code></pre>" +
      '<p class="no-fix-message">' + escapeHtml(rem.status_message) + "</p>" +
      (isExhausted
        ? '<p class="exhausted-message">No further Dockerfile remediation available. Dockerfile already optimized. Remaining findings require newer upstream base images or package maintainer fixes.</p>'
        : "") +
      "</div></div>";
  }

  const remainingTotal = rem.remaining_critical + rem.remaining_high +
    rem.remaining_medium + rem.remaining_low;

  const improvementsTitle = isAvailable ? "Security Improvements (Estimated)" : "Remediation Results";
  const rightPanelTitle = isAvailable ? "Estimated After Fix" : "Remaining After Remediation";
  const leftCritical = isAvailable ? rem.current_critical : (rem.original_critical || rem.current_critical);
  const leftHigh = isAvailable ? rem.current_high : (rem.original_high || rem.current_high);
  const leftMedium = isAvailable ? rem.current_medium : (rem.original_medium || rem.current_medium);
  const leftLow = isAvailable ? rem.current_low : (rem.original_low || rem.current_low);
  const rightCritical = isAvailable ? rem.estimated_critical : rem.remaining_critical;
  const rightHigh = isAvailable ? rem.estimated_high : rem.remaining_high;
  const rightMedium = isAvailable ? rem.estimated_medium : rem.remaining_medium;
  const rightLow = isAvailable ? rem.estimated_low : rem.remaining_low;
  const rightDecision = isAvailable ? rem.estimated_decision : rem.current_decision;
  const leftPanelTitle = isAvailable ? "Current" : "Original (Before Fix)";

  return (
    '<div class="remediation-card card" id="remediation-' + rem.service_id + '">' +
    '<div class="remediation-header">' +
    "<div>" +
    "<h2>" + escapeHtml(rem.service_name) + "</h2>" +
    '<p class="remediation-path">' + escapeHtml(rem.dockerfile_path) + "</p>" +
    "</div>" +
    '<div class="header-badges">' +
    '<span class="state-badge ' + stateClass + '">' + formatState(rem.remediation_state) + "</span>" +
    '<span class="status-badge ' + decisionClass(rem.current_decision) + '">' + formatDecision(rem.current_decision) + "</span>" +
    "</div></div>" +

    '<div class="status-banner ' + statusBannerClass + '">' +
    "<strong>" + escapeHtml(rem.status_message) + "</strong>" +
    (isExhausted && rem.current_decision === "PASS_WITH_RISK"
      ? "<p><strong>Deployment Approved</strong> — No additional remediation available. All Dockerfile fixes applied. Waiting for vendor security updates.</p>"
      : "") +
    (isApplied || isExhausted
      ? '<p>Fixable: <strong>' + (rem.fixable_count || 0) + "</strong> | Unfixable: <strong>" + (rem.unfixable_count || 0) + "</strong></p>"
      : '<p>Fixable: <strong>' + (rem.fixable_count || 0) + "</strong> | Unfixable: <strong>" + (rem.unfixable_count || 0) + "</strong></p>") +
    (rem.status_reason ? "<p>" + escapeHtml(rem.status_reason) + "</p>" : "") +
    "</div>" +

    '<div class="remediation-section">' +
    "<h3>1. " + (isAvailable ? "Vulnerabilities Found" : "Remaining Vulnerabilities") + "</h3>" +
    '<div class="table-container">' +
    "<table><thead><tr>" +
    "<th>CVE ID</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed Version</th><th>Source</th><th>Type</th>" +
    "</tr></thead><tbody>" +
    (vulnRows || '<tr><td colspan="7" style="text-align:center;color:var(--text-muted)">No vulnerabilities</td></tr>') +
    "</tbody></table></div></div>" +

    '<div class="remediation-section">' +
    "<h3>2. " + (isAvailable ? "Root Cause Analysis" : "Root Cause — Why Vulnerabilities Still Exist") + "</h3>" +
    '<ul class="remediation-list">' + rootCauses + "</ul></div>" +

    '<div class="remediation-section">' +
    "<h3>3. " + (isAvailable ? "Recommended Fixes" : "Guidance") + "</h3>" +
    '<ul class="remediation-list fixes-list">' + fixes + "</ul>" +
    (isExhausted ? '<p class="exhausted-message">No additional Dockerfile remediation available.</p>' : "") +
    "</div>" +

    dependencySection +
    dockerfileSection +

    '<div class="remediation-section security-improvements">' +
    "<h3>" + improvementsTitle + "</h3>" +
    '<div class="history-stats">' +
    '<div class="history-stat"><span class="label">Original Score</span><span class="value">' + rem.original_score + "</span></div>" +
    '<div class="history-stat"><span class="label">Score After Remediation</span><span class="value score">' + rem.score_after_remediation + "</span></div>" +
    '<div class="history-stat"><span class="label">Improvement</span><span class="value success">' + rem.improvement_percentage + "%</span></div>" +
    "</div>" +
    '<div class="improvements-grid" style="margin-top:1rem;">' +
    '<div class="improvement-panel">' +
    "<h4>" + leftPanelTitle + "</h4>" +
    '<div class="improvement-stat"><span class="label">Critical</span><span class="value critical">' + leftCritical + "</span></div>" +
    '<div class="improvement-stat"><span class="label">High</span><span class="value high">' + leftHigh + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Medium</span><span class="value medium">' + leftMedium + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Low</span><span class="value low">' + leftLow + "</span></div>" +
    "</div>" +
    '<div class="improvement-arrow">→</div>' +
    '<div class="improvement-panel estimated">' +
    "<h4>" + rightPanelTitle + "</h4>" +
    '<div class="improvement-stat"><span class="label">Critical</span><span class="value critical">' + rightCritical + "</span></div>" +
    '<div class="improvement-stat"><span class="label">High</span><span class="value high">' + rightHigh + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Medium</span><span class="value medium">' + rightMedium + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Low</span><span class="value low">' + rightLow + "</span></div>" +
    '<div class="improvement-decision"><span class="label">Decision</span><span class="status-badge ' + decisionClass(rightDecision) + '">' + formatDecision(rightDecision) + "</span></div>" +
    "</div></div></div>" +

    "</div>"
  );
}

function bindDependencyCopyButtons() {
  document.querySelectorAll(".copy-dep-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const targetId = btn.getAttribute("data-target");
      const el = targetId ? document.getElementById(targetId) : null;
      const text = el ? el.textContent : "";
      navigator.clipboard.writeText(text).then(function () {
        const original = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = original; }, 2000);
      });
    });
  });
}

function bindCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const serviceId = btn.getAttribute("data-service-id");
      const pre = document.getElementById("updated-dockerfile-" + serviceId);
      const text = pre ? pre.textContent : "";

      navigator.clipboard.writeText(text).then(function () {
        const original = btn.textContent;
        btn.textContent = "Copied!";
        btn.style.background = "var(--success)";
        setTimeout(function () {
          btn.textContent = original;
          btn.style.background = "";
        }, 2000);
      }).catch(function () {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = "Copy Updated Dockerfile"; }, 2000);
      });
    });
  });
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
