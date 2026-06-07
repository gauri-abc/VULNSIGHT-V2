const API_BASE = "/api/reports";

document.addEventListener("DOMContentLoaded", function () {
  loadReports();
});

async function loadReports() {
  const container = document.getElementById("reports-list");

  try {
    const response = await fetch(API_BASE + "/history");
    const reports = await response.json();

    if (!reports.length) {
      container.innerHTML =
        '<div class="empty-state"><p>No scan reports available. Run a security assessment to generate reports.</p></div>';
      return;
    }

    container.innerHTML = reports
      .map(function (report) {
        const date = new Date(report.created_at).toLocaleString();
        return (
          '<div class="report-item">' +
          '<div class="report-info">' +
          "<h4>" + escapeHtml(report.repository_name) + "</h4>" +
          "<p>" + escapeHtml(report.repo_url) + "</p>" +
          "<p>Scanned: " + date +
          " | Score: " + report.security_score +
          " | " + renderDecisionBadges(report.decision, isRiskAccepted(report)) + "</p>" +
          "<p>Critical: " + report.critical +
          " | High: " + report.high +
          " | Medium: " + report.medium +
          " | Low: " + report.low + "</p>" +
          "<p>Fixable: " + (report.fixable_count || 0) +
          " | Unfixable: " + (report.unfixable_count || 0) + "</p>" +
          "</div>" +
          '<div class="report-actions">' +
          '<a href="' + API_BASE + "/" + report.id + '/json" class="btn btn-secondary" download>JSON</a>' +
          '<a href="' + API_BASE + "/" + report.id + '/csv" class="btn btn-secondary" download>CSV</a>' +
          '<a href="' + API_BASE + "/" + report.id + '/pdf" class="btn btn-secondary" download>PDF</a>' +
          "</div>" +
          "</div>"
        );
      })
      .join("");
  } catch (error) {
    container.innerHTML =
      '<div class="alert alert-error">Failed to load reports: ' + escapeHtml(error.message) + "</div>";
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
