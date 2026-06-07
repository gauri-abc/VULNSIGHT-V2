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
        '<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:2rem;">' +
        "No services found. Run a security scan first.</td></tr>";
      return;
    }

    tbody.innerHTML = services
      .map(function (svc) {
        const statusClass = svc.status.toLowerCase();
        var remediateBtn = "";
        if (svc.status === "FAIL") {
          remediateBtn =
            ' <a href="remediation.html#remediation-' + svc.id + '" class="btn btn-secondary btn-remediate">Fix</a>';
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
          "<td>" + svc.score + "</td>" +
          '<td><span class="status-badge ' + statusClass + '">' + svc.status + "</span>" + remediateBtn + "</td>" +
          "</tr>"
        );
      })
      .join("");
  } catch (error) {
    tbody.innerHTML =
      '<tr><td colspan="9" style="text-align:center;color:var(--danger);padding:2rem;">' +
      "Failed to load services: " + escapeHtml(error.message) + "</td></tr>";
  }
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
