const API_BASE = "/api/dashboard";

document.addEventListener("DOMContentLoaded", function () {
  loadDashboard();
});

async function loadDashboard() {
  try {
    const [stats, severity, topServices, scoreTrend] = await Promise.all([
      fetch(API_BASE + "/stats").then(function (r) { return r.json(); }),
      fetch(API_BASE + "/severity-chart").then(function (r) { return r.json(); }),
      fetch(API_BASE + "/top-vulnerable-services").then(function (r) { return r.json(); }),
      fetch(API_BASE + "/score-trend").then(function (r) { return r.json(); }),
    ]);

    renderStats(stats);
    drawSeverityChart(severity);
    drawTopServicesChart(topServices);
    drawScoreTrendChart(scoreTrend);
  } catch (error) {
    console.error("Failed to load dashboard:", error);
  }
}

function renderStats(stats) {
  document.getElementById("stat-repos").textContent = stats.repositories_scanned;
  document.getElementById("stat-images").textContent = stats.images_scanned;
  document.getElementById("stat-critical").textContent = stats.critical_vulnerabilities;
  document.getElementById("stat-high").textContent = stats.high_vulnerabilities;
  document.getElementById("stat-medium").textContent = stats.medium_vulnerabilities;
  document.getElementById("stat-low").textContent = stats.low_vulnerabilities;
  document.getElementById("stat-pass").textContent = stats.pass_count;
  document.getElementById("stat-pass-risk").textContent = stats.pass_with_risk_count || 0;
  document.getElementById("stat-fail").textContent = stats.fail_count;
  document.getElementById("stat-avg-score").textContent = stats.average_security_score;
}

function drawSeverityChart(data) {
  const canvas = document.getElementById("severity-chart");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const width = rect.width;
  const height = rect.height;
  const padding = { top: 20, right: 20, bottom: 50, left: 50 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const colors = {
    CRITICAL: "#dc2626",
    HIGH: "#ea580c",
    MEDIUM: "#d97706",
    LOW: "#2563eb",
  };

  const maxVal = Math.max.apply(null, data.map(function (d) { return d.count; }).concat([1]));
  const barWidth = chartWidth / data.length * 0.6;
  const gap = chartWidth / data.length * 0.4;

  ctx.clearRect(0, 0, width, height);

  data.forEach(function (item, i) {
    const barHeight = (item.count / maxVal) * chartHeight;
    const x = padding.left + i * (barWidth + gap) + gap / 2;
    const y = padding.top + chartHeight - barHeight;

    ctx.fillStyle = colors[item.severity] || "#3b82f6";
    ctx.beginPath();
    ctx.roundRect(x, y, barWidth, barHeight, 4);
    ctx.fill();

    ctx.fillStyle = "#64748b";
    ctx.font = "11px Segoe UI, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(item.severity, x + barWidth / 2, height - padding.bottom + 20);
    ctx.fillStyle = "#0f172a";
    ctx.fillText(String(item.count), x + barWidth / 2, y - 8);
  });
}

function drawTopServicesChart(data) {
  const canvas = document.getElementById("top-services-chart");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const width = rect.width;
  const height = rect.height;
  const padding = { top: 20, right: 20, bottom: 20, left: 140 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  ctx.clearRect(0, 0, width, height);

  if (!data.length) {
    ctx.fillStyle = "#64748b";
    ctx.font = "14px Segoe UI, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No service data available", width / 2, height / 2);
    return;
  }

  const maxVal = Math.max.apply(
    null,
    data.map(function (d) { return d.total_vulnerabilities; }).concat([1])
  );
  const barHeight = chartHeight / data.length * 0.6;
  const gap = chartHeight / data.length * 0.4;

  data.forEach(function (item, i) {
    const barW = (item.total_vulnerabilities / maxVal) * chartWidth;
    const x = padding.left;
    const y = padding.top + i * (barHeight + gap) + gap / 2;

    const gradient = ctx.createLinearGradient(x, y, x + barW, y);
    gradient.addColorStop(0, "#2563eb");
    gradient.addColorStop(1, "#6366f1");
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.roundRect(x, y, barW, barHeight, 4);
    ctx.fill();

    ctx.fillStyle = "#475569";
    ctx.font = "11px Segoe UI, sans-serif";
    ctx.textAlign = "right";
    ctx.fillText(item.service_name, padding.left - 10, y + barHeight / 2 + 4);

    ctx.fillStyle = "#0f172a";
    ctx.textAlign = "left";
    ctx.fillText(String(item.total_vulnerabilities), x + barW + 8, y + barHeight / 2 + 4);
  });
}

function drawScoreTrendChart(data) {
  const canvas = document.getElementById("score-trend-chart");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const width = rect.width;
  const height = rect.height;
  const padding = { top: 30, right: 30, bottom: 60, left: 50 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  ctx.clearRect(0, 0, width, height);

  if (!data.length) {
    ctx.fillStyle = "#64748b";
    ctx.font = "14px Segoe UI, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No trend data available", width / 2, height / 2);
    return;
  }

  const points = data.map(function (d, i) {
    return {
      x: padding.left + (i / Math.max(data.length - 1, 1)) * chartWidth,
      y: padding.top + chartHeight - (d.score / 100) * chartHeight,
      label: d.date,
      score: d.score,
      repo: d.repository_name,
    };
  });

  ctx.strokeStyle = "#e2e8f0";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartHeight / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartWidth, y);
    ctx.stroke();

    ctx.fillStyle = "#64748b";
    ctx.font = "10px Segoe UI, sans-serif";
    ctx.textAlign = "right";
    ctx.fillText(String(100 - i * 25), padding.left - 8, y + 4);
  }

  ctx.beginPath();
  ctx.strokeStyle = "#2563eb";
  ctx.lineWidth = 2;
  points.forEach(function (p, i) {
    if (i === 0) ctx.moveTo(p.x, p.y);
    else ctx.lineTo(p.x, p.y);
  });
  ctx.stroke();

  const gradient = ctx.createLinearGradient(0, padding.top, 0, padding.top + chartHeight);
  gradient.addColorStop(0, "rgba(37, 99, 235, 0.15)");
  gradient.addColorStop(1, "rgba(37, 99, 235, 0)");
  ctx.lineTo(points[points.length - 1].x, padding.top + chartHeight);
  ctx.lineTo(points[0].x, padding.top + chartHeight);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  points.forEach(function (p) {
    ctx.beginPath();
    ctx.arc(p.x, p.y, 5, 0, Math.PI * 2);
    ctx.fillStyle = "#2563eb";
    ctx.fill();
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = 2;
    ctx.stroke();
  });

  ctx.fillStyle = "#64748b";
  ctx.font = "9px Segoe UI, sans-serif";
  ctx.textAlign = "center";
  points.forEach(function (p, i) {
    if (i % Math.max(1, Math.floor(points.length / 6)) === 0 || i === points.length - 1) {
      ctx.save();
      ctx.translate(p.x, height - padding.bottom + 15);
      ctx.rotate(-0.4);
      ctx.fillText(p.label, 0, 0);
      ctx.restore();
    }
  });
}

window.addEventListener("resize", function () {
  loadDashboard();
});
