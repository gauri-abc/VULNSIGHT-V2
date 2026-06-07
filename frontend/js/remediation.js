const API_BASE = "/api/remediation";

document.addEventListener("DOMContentLoaded", function () {
  loadRemediations();
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
    const remediations = await response.json();

    if (!remediations.length) {
      container.innerHTML =
        '<div class="empty-state"><p>No failed services requiring remediation. ' +
        "All services passed the security gate, or run a scan first.</p></div>";
      return;
    }

    container.innerHTML = remediations.map(renderRemediationCard).join("");
    bindCopyButtons();

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

function renderRemediationCard(rem) {
  const vulnRows = rem.vulnerabilities_found
    .map(function (v) {
      return (
        "<tr>" +
        "<td>" + escapeHtml(v.cve_id) + "</td>" +
        '<td><span class="severity-badge ' + v.severity.toLowerCase() + '">' + v.severity + "</span></td>" +
        "<td>" + escapeHtml(v.package_name) + "</td>" +
        "<td>" + escapeHtml(v.installed_version || "-") + "</td>" +
        "<td>" + escapeHtml(v.fixed_version || "-") + "</td>" +
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

  return (
    '<div class="remediation-card card" id="remediation-' + rem.service_id + '">' +
    '<div class="remediation-header">' +
    "<div>" +
    "<h2>" + escapeHtml(rem.service_name) + "</h2>" +
    '<p class="remediation-path">' + escapeHtml(rem.dockerfile_path) + "</p>" +
    "</div>" +
    '<span class="status-badge fail">' + rem.current_decision + "</span>" +
    "</div>" +

    '<div class="remediation-section">' +
    "<h3>1. Vulnerabilities Found</h3>" +
    '<div class="table-container">' +
    "<table><thead><tr>" +
    "<th>CVE ID</th><th>Severity</th><th>Package</th><th>Installed</th><th>Fixed Version</th>" +
    "</tr></thead><tbody>" +
    (vulnRows || '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No vulnerabilities</td></tr>') +
    "</tbody></table></div></div>" +

    '<div class="remediation-section">' +
    "<h3>2. Root Cause Analysis</h3>" +
    '<ul class="remediation-list">' + rootCauses + "</ul></div>" +

    '<div class="remediation-section">' +
    "<h3>3. Recommended Fixes</h3>" +
    '<ul class="remediation-list fixes-list">' + fixes + "</ul></div>" +

    '<div class="remediation-section">' +
    "<h3>4. Updated Dockerfile</h3>" +
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
    "</div></div></div></div>" +

    '<div class="remediation-section security-improvements">' +
    "<h3>Security Improvements</h3>" +
    '<div class="improvements-grid">' +
    '<div class="improvement-panel">' +
    "<h4>Current</h4>" +
    '<div class="improvement-stat"><span class="label">Critical</span><span class="value critical">' + rem.current_critical + "</span></div>" +
    '<div class="improvement-stat"><span class="label">High</span><span class="value high">' + rem.current_high + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Medium</span><span class="value medium">' + rem.current_medium + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Low</span><span class="value low">' + rem.current_low + "</span></div>" +
    '<div class="improvement-decision"><span class="label">Decision</span><span class="status-badge ' + rem.current_decision.toLowerCase() + '">' + rem.current_decision + "</span></div>" +
    "</div>" +
    '<div class="improvement-arrow">→</div>' +
    '<div class="improvement-panel estimated">' +
    "<h4>Estimated After Fix</h4>" +
    '<div class="improvement-stat"><span class="label">Critical</span><span class="value critical">' + rem.estimated_critical + "</span></div>" +
    '<div class="improvement-stat"><span class="label">High</span><span class="value high">' + rem.estimated_high + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Medium</span><span class="value medium">' + rem.estimated_medium + "</span></div>" +
    '<div class="improvement-stat"><span class="label">Low</span><span class="value low">' + rem.estimated_low + "</span></div>" +
    '<div class="improvement-decision"><span class="label">Decision</span><span class="status-badge ' + rem.estimated_decision.toLowerCase() + '">' + rem.estimated_decision + "</span></div>" +
    "</div></div></div>" +

    "</div>"
  );
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
