from sqlalchemy.orm import Session

from models import Alert


class AlertService:
    def create_alerts(
        self,
        db: Session,
        repository_id: int,
        counts: dict,
        decision: str,
        repository_name: str,
        risk_accepted: bool = False,
    ) -> list[Alert]:
        alerts = []

        if decision == "FAIL":
            alerts.append(
                Alert(
                    repository_id=repository_id,
                    message=(
                        f"Security gate FAILED for {repository_name}: "
                        f"fixable critical or high vulnerabilities require remediation."
                    ),
                    severity="CRITICAL",
                )
            )

        if decision == "PASS":
            if risk_accepted:
                alerts.append(
                    Alert(
                        repository_id=repository_id,
                        message=(
                            f"Security gate PASSED for {repository_name}. "
                            f"Risk accepted — remaining vulnerabilities have no vendor fix."
                        ),
                        severity="INFO",
                    )
                )
            else:
                alerts.append(
                    Alert(
                        repository_id=repository_id,
                        message=f"Security gate PASSED for {repository_name}.",
                        severity="INFO",
                    )
                )

        for alert in alerts:
            db.add(alert)

        db.commit()
        return alerts
