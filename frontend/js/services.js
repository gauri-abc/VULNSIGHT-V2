const API_BASE = "/api/services";

document.addEventListener("DOMContentLoaded", function () {
  loadServices();
});

async function loadServices() {
  const tbody = document.getElementById("services-table-body");

  try {
    const scanId = localStorage.getItem("lastScanId");
    let url = API_BASE + "/latest";

    if (scanId) {
      url = API_BASE + "/scan/" + scanId;
    }

    const response = await fetch(url);
    const services = await response.json();

    if (!services.length) {
      tbody.innerHTML =
        '<tr><td colspan="13" style="text-align:center;color:var(--text-muted);padding:2rem;">' +
        "No services found. Run a security scan first.</td></tr>";
      return;
    }

    tbody.innerHTML = services
      .map(function (svc) {
        var remediateBtn = "";
        if (svc.status === "FAIL") {
          remediateBtn =
            ' <a href="remediation.html#remediation-' + svc.id + '" class="btn btn-secondary btn-remediate">Fix</a>';
        }

        var reasonHtml = "";
        if (svc.status_reason) {
          reasonHtml =
            '<br><small style="color:var(--text-muted);max-width:280px;display:inline-block;">' +
            escapeHtml(svc.status_reason) + "</small>";
        }

        return (
          "<tr>" +
          "<td><strong>" + escapeHtml(svc.service_name) + "</strong></td>" +
          "<td><code>" + escapeHtml(svc.dockerfile_path) + "</code></td>" +
          "<td><code>" + escapeHtml(svc.image_name) + "</code></td>" +
          '<td><span class="severity-dot critical"></span>' + svc.critical + "</td>" +
          '<td><span class="severity-dot high"></span>' + svc.high + "</td>" +
          '<td><span class="severity-dot medium"></span>' + svc.medium + "</td>" +
          '<td><span class="severity-dot low"></span>' + svc.low + "</td>" +
          "<td>" + (svc.dependency_findings || 0) + "</td>" +
          "<td>" + (svc.dockerfile_findings || 0) + "</td>" +
          "<td>" + (svc.image_findings || 0) + "</td>" +
          "<td>" + svc.score + "</td>" +
          "<td>" + renderDecisionBadges(svc.status, isRiskAccepted(svc)) + reasonHtml + remediateBtn + "</td>" +
          '<td><button class="btn btn-secondary btn-sm view-breakdown-btn" data-service-id="' + svc.id + '">Details</button></td>' +
          "</tr>"
        );
      })
      .join("");

    document.querySelectorAll(".view-breakdown-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        loadSecurityBreakdown(btn.getAttribute("data-service-id"));
      });
    });
  } catch (error) {
    tbody.innerHTML =
      '<tr><td colspan="13" style="text-align:center;color:var(--danger);padding:2rem;">' +
      "Failed to load services: " + escapeHtml(error.message) + "</td></tr>";
  }
}

async function loadSecurityBreakdown(serviceId) {
  const container = document.getElementById("security-breakdown-container");

  try {
    const response = await fetch(API_BASE + "/" + serviceId + "/security-breakdown");
    if (!response.ok) {
      throw new Error("Failed to load security breakdown");
    }
    const data = await response.json();

    container.innerHTML =
      '<div class="card security-breakdown-card" id="service-breakdown-' + serviceId + '">' +
      "<h2>Security Breakdown</h2>" +
      '<div class="breakdown-scores">' +
      scorePill("Combined Score", data.combined_score) +
      scorePill("Dependency Score", data.dependency_score) +
      scorePill("Dockerfile Score", data.dockerfile_score) +
      scorePill("Image Score", data.image_score) +
      "</div>" +
      renderFindingSection(
        "1. Dependency Vulnerabilities",
        "dependency",
        data.dependency_vulnerabilities,
        ["CVE ID", "Severity", "Package", "Installed", "Fixed Version", "Type"],
        function (item) {
          return (
            "<tr>" +
            "<td>" + escapeHtml(item.cve_id) + "</td>" +
            '<td><span class="severity-badge ' + item.severity.toLowerCase() + '">' + item.severity + "</span></td>" +
            "<td>" + escapeHtml(item.package_name) + "</td>" +
            "<td>" + escapeHtml(item.installed_version || "-") + "</td>" +
            "<td>" + escapeHtml(item.fixed_version || "-") + "</td>" +
            "<td>" + escapeHtml(item.classification || "-") + "</td>" +
            "</tr>"
          );
        }
      ) +
      renderDockerSection(data.dockerfile_security_findings) +
      renderFindingSection(
        "3. Container Image Vulnerabilities",
        "image",
        data.image_vulnerabilities,
        ["CVE ID", "Severity", "Package", "Installed", "Fixed Version", "Type"],
        function (item) {
          return (
            "<tr>" +
            "<td>" + escapeHtml(item.cve_id) + "</td>" +
            '<td><span class="severity-badge ' + item.severity.toLowerCase() + '">' + item.severity + "</span></td>" +
            "<td>" + escapeHtml(item.package_name) + "</td>" +
            "<td>" + escapeHtml(item.installed_version || "-") + "</td>" +
            "<td>" + escapeHtml(item.fixed_version || "-") + "</td>" +
            "<td>" + escapeHtml(item.classification || "-") + "</td>" +
            "</tr>"
          );
        }
      ) +
      "</div>";

    document.getElementById("service-breakdown-" + serviceId).scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  } catch (error) {
    container.innerHTML =
      '<div class="alert alert-error">Failed to load security breakdown: ' +
      escapeHtml(error.message) + "</div>";
  }
}

function scorePill(label, score) {
  return (
    '<div class="breakdown-score-pill">' +
    '<span class="label">' + label + "</span>" +
    '<span class="value">' + score + "</span></div>"
  );
}

function renderFindingSection(title, key, items, headers, rowRenderer) {
  const rows = (items || []).map(rowRenderer).join("");
  const headerHtml = headers.map(function (h) { return "<th>" + h + "</th>"; }).join("");

  return (
    '<div class="remediation-section">' +
    "<h3>" + title + " <span class='finding-count'>(" + (items || []).length + ")</span></h3>" +
    '<div class="table-container">' +
    "<table><thead><tr>" + headerHtml + "</tr></thead><tbody>" +
    (rows || '<tr><td colspan="' + headers.length + '" style="text-align:center;color:var(--text-muted)">No findings</td></tr>') +
    "</tbody></table></div></div>"
  );
}

function renderDockerSection(findings) {
  const rows = (findings || []).map(function (item) {
    return (
      "<tr>" +
      '<td><span class="severity-badge ' + item.severity.toLowerCase() + '">' + item.severity + "</span></td>" +
      "<td><strong>" + escapeHtml(item.rule) + "</strong></td>" +
      "<td>" + escapeHtml(item.description || "-") + "</td>" +
      "<td>" + escapeHtml(item.recommendation || "-") + "</td>" +
      "</tr>"
    );
  }).join("");

  return (
    '<div class="remediation-section">' +
    "<h3>2. Docker Security Findings <span class='finding-count'>(" + (findings || []).length + ")</span></h3>" +
    '<div class="table-container">' +
    "<table><thead><tr>" +
    "<th>Severity</th><th>Rule</th><th>Description</th><th>Recommendation</th>" +
    "</tr></thead><tbody>" +
    (rows || '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No Dockerfile security findings</td></tr>') +
    "</tbody></table></div></div>"
  );
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
