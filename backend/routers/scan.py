from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Repository, Service, Vulnerability, ScanHistory
from schemas import RepositoryScanRequest, RepositoryScanResponse
from services.github_service import GitHubService
from services.docker_service import DockerService
from services.trivy_service import TrivyService
from services.scoring_service import ScoringService
from services.policy_service import PolicyService
from services.alert_service import AlertService

router = APIRouter(prefix="/api", tags=["scan"])

github_service = GitHubService()
docker_service = DockerService()
trivy_service = TrivyService()
scoring_service = ScoringService()
policy_service = PolicyService()
alert_service = AlertService()


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

        for image_info in built_images:
            vulnerabilities = trivy_service.scan_image(image_info["image_name"])
            counts = trivy_service.count_by_severity(vulnerabilities)
            service_score = scoring_service.calculate_service_score(vulnerabilities)

            for key in total_counts:
                total_counts[key] += counts.get(key, 0)

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

        security_score = scoring_service.calculate_score(total_counts)
        decision = policy_service.evaluate(total_counts)

        scan_record = ScanHistory(
            repository_id=repository.id,
            critical=total_counts["CRITICAL"],
            high=total_counts["HIGH"],
            medium=total_counts["MEDIUM"],
            low=total_counts["LOW"],
            security_score=security_score,
            decision=decision,
        )
        db.add(scan_record)
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
