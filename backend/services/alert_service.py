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
    ) -> list[Alert]:
        alerts = []

        if counts.get("CRITICAL", 0) > 0:
            alerts.append(
                Alert(
                    repository_id=repository_id,
                    message=(
                        f"Security gate FAILED for {repository_name}: "
                        f"{counts['CRITICAL']} critical vulnerabilities detected."
                    ),
                    severity="CRITICAL",
                )
            )

        if counts.get("HIGH", 0) > 5:
            alerts.append(
                Alert(
                    repository_id=repository_id,
                    message=(
                        f"Security gate FAILED for {repository_name}: "
                        f"{counts['HIGH']} high vulnerabilities exceed threshold of 5."
                    ),
                    severity="HIGH",
                )
            )

        if counts.get("MEDIUM", 0) > 20:
            alerts.append(
                Alert(
                    repository_id=repository_id,
                    message=(
                        f"Security gate WARNING for {repository_name}: "
                        f"{counts['MEDIUM']} medium vulnerabilities exceed threshold of 20."
                    ),
                    severity="MEDIUM",
                )
            )

        if decision == "PASS":
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
