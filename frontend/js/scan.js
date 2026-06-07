const API_BASE = "/api";

const WORKFLOW_STEPS = [
  "Repository Received",
  "Cloning Repository",
  "Finding Dockerfiles",
  "Building Images",
  "Running Trivy",
  "Calculating Security Score",
  "Applying Security Policies",
  "Generating Report",
];

let workflowInterval = null;

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("scan-form");
  form.addEventListener("submit", handleScan);
});

function showAlert(message, type) {
  const container = document.getElementById("alert-container");
  container.innerHTML =
    '<div class="alert alert-' + type + '">' + message + "</div>";
  setTimeout(function () {
    container.innerHTML = "";
  }, 8000);
}

function startWorkflowAnimation() {
  const section = document.getElementById("workflow-section");
  const steps = document.querySelectorAll(".workflow-step");
  const progressBar = document.getElementById("progress-bar");
  let currentStep = 0;

  section.classList.add("active");
  steps.forEach(function (step) {
    step.classList.remove("active", "completed");
  });
  progressBar.style.width = "0%";

  steps[0].classList.add("active");
  progressBar.style.width = "5%";

  workflowInterval = setInterval(function () {
    if (currentStep < steps.length - 1) {
      steps[currentStep].classList.remove("active");
      steps[currentStep].classList.add("completed");
      currentStep++;
      steps[currentStep].classList.add("active");
      progressBar.style.width =
        Math.round(((currentStep + 1) / steps.length) * 90) + "%";
    }
  }, 2500);
}

function completeWorkflowAnimation() {
  if (workflowInterval) {
    clearInterval(workflowInterval);
    workflowInterval = null;
  }

  const steps = document.querySelectorAll(".workflow-step");
  const progressBar = document.getElementById("progress-bar");

  steps.forEach(function (step) {
    step.classList.remove("active");
    step.classList.add("completed");
  });
  progressBar.style.width = "100%";
}

function displayResults(data) {
  const section = document.getElementById("results-section");
  section.classList.add("active");

  document.getElementById("result-repo-name").textContent = data.repository;
  document.getElementById("result-repository").textContent = data.repository;
  document.getElementById("result-dockerfiles").textContent = data.dockerfiles_found;
  document.getElementById("result-images").textContent = data.images_built;
  document.getElementById("result-critical").textContent = data.critical;
  document.getElementById("result-high").textContent = data.high;
  document.getElementById("result-medium").textContent = data.medium;
  document.getElementById("result-low").textContent = data.low;
  document.getElementById("result-score").textContent = data.score;

  const decisionEl = document.getElementById("result-decision");
  decisionEl.textContent = data.decision;
  decisionEl.className = "decision-badge " + data.decision.toLowerCase();

  localStorage.setItem("lastScanId", data.scan_id);
  localStorage.setItem("lastScanResult", JSON.stringify(data));

  var remediationLink = document.getElementById("remediation-link");
  if (remediationLink && (data.decision === "FAIL" || data.critical > 0)) {
    remediationLink.style.display = "inline-flex";
  } else if (remediationLink) {
    remediationLink.style.display = "none";
  }

  section.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function handleScan(event) {
  event.preventDefault();

  const repoUrl = document.getElementById("repo-url").value.trim();
  const scanBtn = document.getElementById("scan-btn");
  const resultsSection = document.getElementById("results-section");

  if (!repoUrl) {
    showAlert("Please enter a valid GitHub repository URL.", "error");
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning in Progress...";
  resultsSection.classList.remove("active");
  startWorkflowAnimation();

  try {
    const response = await fetch(API_BASE + "/repository-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url: repoUrl }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Scan failed");
    }

    completeWorkflowAnimation();
    displayResults(data);
    showAlert(
      "Security assessment completed. Decision: " + data.decision,
      data.decision === "PASS" ? "success" : "error"
    );
  } catch (error) {
    if (workflowInterval) {
      clearInterval(workflowInterval);
      workflowInterval = null;
    }
    document.getElementById("workflow-section").classList.remove("active");
    showAlert("Scan failed: " + error.message, "error");
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Start Security Assessment";
  }
}
