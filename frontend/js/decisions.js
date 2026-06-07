function normalizeDecision(decision) {
  if (decision === "PASS_WITH_RISK") {
    return "PASS";
  }
  return decision || "PASS";
}

function isRiskAccepted(record) {
  if (!record) {
    return false;
  }
  if (record.risk_accepted) {
    return true;
  }
  return record.decision === "PASS_WITH_RISK" || record.status === "PASS_WITH_RISK";
}

function formatDecision(decision) {
  return normalizeDecision(decision);
}

function primaryDecisionClass(decision) {
  return normalizeDecision(decision).toLowerCase();
}

function renderDecisionBadges(decision, riskAccepted, badgeClass) {
  badgeClass = badgeClass || "status-badge";
  var primary = formatDecision(decision);
  var html =
    '<span class="' + badgeClass + " " + primaryDecisionClass(decision) + '">' +
    primary +
    "</span>";
  if (riskAccepted) {
    html += ' <span class="risk-accepted-badge">RISK ACCEPTED</span>';
  }
  return html;
}
