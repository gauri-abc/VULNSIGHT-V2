from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

import json

from database import get_db
from models import Repository, Service, Vulnerability, ScanHistory, Remediation, RemediationHistory
from schemas import RepositoryScanRequest, RepositoryScanResponse
from services.github_service import GitHubService
from services.docker_service import DockerService
from services.trivy_service import TrivyService
from services.scoring_service import ScoringService
from services.policy_service import PolicyService
from services.alert_service import AlertService
from services.remediation_service import RemediationService

router = APIRouter(prefix="/api", tags=["scan"])

github_service = GitHubService()
docker_service = DockerService()
trivy_service = TrivyService()
scoring_service = ScoringService()
policy_service = PolicyService()
alert_service = AlertService()
remediation_service = RemediationService()


@router.post("/repository-scan", response_model=RepositoryScanResponse)
def repository_scan(request: RepositoryScanRequest, db: Session = Depends(get_db)):
    clone_path = None
    built_images = []

    try:
        clone_path, repo_name = github_service.clone_repository(request.repo_url)

        dockerfiles = docker_service.discover_dockerfiles(clone_path)
        if not dockerfiles:
            raise HTTPException(
                status_code=400,
                detail="No Dockerfiles found in the repository.",
            )

        built_images = docker_service.build_all_images(clone_path, dockerfiles)

        repository = Repository(name=repo_name, repo_url=request.repo_url)
        db.add(repository)
        db.flush()

        total_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        all_vulnerabilities = []
        service_policy_data = []
        pending_remediation_history = []

        for image_info in built_images:
            vulnerabilities = trivy_service.scan_image(image_info["image_name"])
            counts = trivy_service.count_by_severity(vulnerabilities)
            classification = policy_service.classify_vulnerabilities(vulnerabilities)

            for key in total_counts:
                total_counts[key] += counts.get(key, 0)

            all_vulnerabilities.extend(vulnerabilities)

            dockerfile_content = ""
            dockerfile_full = image_info.get("dockerfile_full_path", "")
            if dockerfile_full:
                with open(dockerfile_full, "r", encoding="utf-8", errors="replace") as df:
                    dockerfile_content = df.read()

            service = Service(
                repository_id=repository.id,
                service_name=image_info["service_name"],
                dockerfile_path=image_info["dockerfile_path"],
                image_name=image_info["image_name"],
            )
            db.add(service)
            db.flush()

            for vuln in vulnerabilities:
                db.add(
                    Vulnerability(
                        service_id=service.id,
                        cve_id=vuln["cve_id"],
                        severity=vuln["severity"],
                        package_name=vuln["package_name"],
                        installed_version=vuln["installed_version"],
                        fixed_version=vuln["fixed_version"],
                        description=vuln["description"],
                    )
                )

            remediation_state = None
            remediation_data = None
            service_decision = policy_service.evaluate_deployment(vulnerabilities)

            if remediation_service.needs_remediation_record(vulnerabilities, service_decision):
                prev_record = remediation_service.find_previous_remediation(
                    db, request.repo_url, image_info["dockerfile_path"]
                )
                previous_remediation = None
                if prev_record and prev_record.updated_dockerfile:
                    previous_remediation = {
                        "updated_dockerfile": prev_record.updated_dockerfile,
                    }

                baseline = remediation_service.find_baseline(
                    db, request.repo_url, image_info["dockerfile_path"]
                )

                remediation_data = remediation_service.generate_remediation(
                    dockerfile_content=dockerfile_content,
                    vulnerabilities=vulnerabilities,
                    service_name=image_info["service_name"],
                    dockerfile_path=image_info["dockerfile_path"],
                    previous_remediation=previous_remediation,
                    baseline=baseline,
                    build_context=image_info.get("build_context", clone_path),
                )

                remediation_state = remediation_data["remediation_state"]
                service_decision = remediation_data["current_decision"]

                db.add(
                    Remediation(
                        service_id=service.id,
                        remediation_state=remediation_data["remediation_state"],
                        status_message=remediation_data["status_message"],
                        show_generate_fix=1 if remediation_data["show_generate_fix"] else 0,
                        current_dockerfile=remediation_data["current_dockerfile"],
                        updated_dockerfile=remediation_data["updated_dockerfile"],
                        previous_updated_dockerfile=remediation_data["previous_updated_dockerfile"],
                        root_cause_analysis=json.dumps(remediation_data["root_cause_analysis"]),
                        recommended_fixes=json.dumps(remediation_data["recommended_fixes"]),
                        vulnerabilities_json=json.dumps(remediation_data["vulnerabilities_found"]),
                        dependency_fixes_json=json.dumps(remediation_data.get("dependency_fixes", [])),
                        dependency_patches_json=json.dumps(remediation_data.get("dependency_patches", [])),
                        current_critical=remediation_data["current_critical"],
                        current_high=remediation_data["current_high"],
                        current_medium=remediation_data["current_medium"],
                        current_low=remediation_data["current_low"],
                        estimated_critical=remediation_data["estimated_critical"],
                        estimated_high=remediation_data["estimated_high"],
                        estimated_medium=remediation_data["estimated_medium"],
                        estimated_low=remediation_data["estimated_low"],
                        remaining_critical=remediation_data["remaining_critical"],
                        remaining_high=remediation_data["remaining_high"],
                        remaining_medium=remediation_data["remaining_medium"],
                        remaining_low=remediation_data["remaining_low"],
                        current_decision=remediation_data["current_decision"],
                        estimated_decision=remediation_data["estimated_decision"],
                        original_score=remediation_data["original_score"],
                        score_after_remediation=remediation_data["score_after_remediation"],
                        improvement_percentage=remediation_data["improvement_percentage"],
                        original_critical=remediation_data["original_critical"],
                        original_high=remediation_data["original_high"],
                        original_medium=remediation_data["original_medium"],
                        original_low=remediation_data["original_low"],
                    )
                )
                pending_remediation_history.append(
                    {
                        "service_name": image_info["service_name"],
                        "dockerfile_path": image_info["dockerfile_path"],
                        "data": remediation_data,
                    }
                )

            pending_deps = []
            if remediation_data:
                pending_deps = [
                    f for f in remediation_data.get("dependency_fixes", [])
                    if not f.get("applied")
                ]

            service_policy_data.append(
                {
                    "vulnerabilities": vulnerabilities,
                    "remediation_state": remediation_state,
                    "pending_dependency_fixes": pending_deps,
                }
            )

        repo_classification = policy_service.classify_vulnerabilities(all_vulnerabilities)
        security_score = scoring_service.calculate_score(total_counts)
        decision = policy_service.evaluate_repository(service_policy_data)
        all_pending_deps = []
        for svc_data in service_policy_data:
            all_pending_deps.extend(svc_data.get("pending_dependency_fixes", []))
        status_reason = policy_service.get_status_reason(
            all_vulnerabilities,
            decision,
            service_policy_data[0].get("remediation_state") if len(service_policy_data) == 1 else None,
            pending_dependency_fixes=all_pending_deps,
        )

        if decision == "PASS_WITH_RISK":
            status_reason = (
                f"Deployment Approved. {repo_classification['unfixable_count']} vulnerabilities "
                f"have no vendor-provided fix. All fixes applied. "
                f"Waiting for upstream vendor security updates."
            )

        scan_record = ScanHistory(
            repository_id=repository.id,
            critical=total_counts["CRITICAL"],
            high=total_counts["HIGH"],
            medium=total_counts["MEDIUM"],
            low=total_counts["LOW"],
            security_score=security_score,
            decision=decision,
            fixable_count=repo_classification["fixable_count"],
            unfixable_count=repo_classification["unfixable_count"],
        )
        db.add(scan_record)
        db.flush()

        for history_item in pending_remediation_history:
            data = history_item["data"]
            db.add(
                RemediationHistory(
                    repository_id=repository.id,
                    scan_id=scan_record.id,
                    service_name=history_item["service_name"],
                    dockerfile_path=history_item["dockerfile_path"],
                    remediation_state=data["remediation_state"],
                    original_score=data["original_score"],
                    score_after_remediation=data["score_after_remediation"],
                    remaining_critical=data["remaining_critical"],
                    remaining_high=data["remaining_high"],
                    remaining_medium=data["remaining_medium"],
                    remaining_low=data["remaining_low"],
                    improvement_percentage=data["improvement_percentage"],
                )
            )

        db.commit()
        db.refresh(scan_record)

        alert_service.create_alerts(
            db=db,
            repository_id=repository.id,
            counts=total_counts,
            decision=decision,
            repository_name=repo_name,
        )

        return RepositoryScanResponse(
            scan_id=scan_record.id,
            repository=repo_name,
            dockerfiles_found=len(dockerfiles),
            images_built=len(built_images),
            critical=total_counts["CRITICAL"],
            high=total_counts["HIGH"],
            medium=total_counts["MEDIUM"],
            low=total_counts["LOW"],
            score=security_score,
            decision=decision,
            fixable_count=repo_classification["fixable_count"],
            unfixable_count=repo_classification["unfixable_count"],
            status_reason=status_reason,
        )

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    finally:
        for image_info in built_images:
            docker_service.remove_image(image_info.get("image_name", ""))
        if clone_path:
            github_service.cleanup_scan_directory(clone_path)
