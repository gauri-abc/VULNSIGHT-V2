from datetime import datetime

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from database import Base


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    repo_url = Column(String(512), nullable=False)
    scan_date = Column(DateTime, default=datetime.utcnow)

    services = relationship("Service", back_populates="repository", cascade="all, delete-orphan")
    scan_history = relationship("ScanHistory", back_populates="repository", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="repository", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    service_name = Column(String(255), nullable=False)
    dockerfile_path = Column(String(512), nullable=False)
    image_name = Column(String(512), nullable=False)

    repository = relationship("Repository", back_populates="services")
    vulnerabilities = relationship("Vulnerability", back_populates="service", cascade="all, delete-orphan")
    docker_security_findings = relationship(
        "DockerSecurityFinding", back_populates="service", cascade="all, delete-orphan"
    )
    remediation = relationship("Remediation", back_populates="service", uselist=False, cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    cve_id = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    package_name = Column(String(255), nullable=False)
    installed_version = Column(String(128), default="")
    fixed_version = Column(String(128), default="")
    description = Column(Text, default="")
    category = Column(String(32), default="image")

    service = relationship("Service", back_populates="vulnerabilities")


class DockerSecurityFinding(Base):
    __tablename__ = "docker_security_findings"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False)
    severity = Column(String(32), nullable=False)
    rule = Column(String(255), nullable=False)
    description = Column(Text, default="")
    recommendation = Column(Text, default="")
    source = Column(String(64), default="trivy")
    rule_id = Column(String(64), default="")

    service = relationship("Service", back_populates="docker_security_findings")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    security_score = Column(Float, default=100.0)
    decision = Column(String(32), default="PASS")
    fixable_count = Column(Integer, default=0)
    unfixable_count = Column(Integer, default=0)
    risk_accepted = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="scan_history")


class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)
    service_id = Column(Integer, ForeignKey("services.id"), nullable=False, unique=True)
    remediation_state = Column(String(32), default="REMEDIATION_AVAILABLE")
    status_message = Column(Text, default="")
    show_generate_fix = Column(Integer, default=1)
    current_dockerfile = Column(Text, nullable=False)
    updated_dockerfile = Column(Text, default="")
    previous_updated_dockerfile = Column(Text, default="")
    root_cause_analysis = Column(Text, nullable=False)
    recommended_fixes = Column(Text, nullable=False)
    vulnerabilities_json = Column(Text, default="[]")
    dependency_fixes_json = Column(Text, default="[]")
    dependency_patches_json = Column(Text, default="[]")
    dockerfile_findings_json = Column(Text, default="[]")
    current_critical = Column(Integer, default=0)
    current_high = Column(Integer, default=0)
    current_medium = Column(Integer, default=0)
    current_low = Column(Integer, default=0)
    estimated_critical = Column(Integer, default=0)
    estimated_high = Column(Integer, default=0)
    estimated_medium = Column(Integer, default=0)
    estimated_low = Column(Integer, default=0)
    remaining_critical = Column(Integer, default=0)
    remaining_high = Column(Integer, default=0)
    remaining_medium = Column(Integer, default=0)
    remaining_low = Column(Integer, default=0)
    current_decision = Column(String(32), default="FAIL")
    estimated_decision = Column(String(32), default="PASS")
    original_score = Column(Float, default=0.0)
    score_after_remediation = Column(Float, default=0.0)
    improvement_percentage = Column(Float, default=0.0)
    original_critical = Column(Integer, default=0)
    original_high = Column(Integer, default=0)
    original_medium = Column(Integer, default=0)
    original_low = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    service = relationship("Service", back_populates="remediation")


class RemediationHistory(Base):
    __tablename__ = "remediation_history"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scan_history.id"), nullable=False)
    service_name = Column(String(255), nullable=False)
    dockerfile_path = Column(String(512), nullable=False)
    remediation_state = Column(String(32), default="REMEDIATION_AVAILABLE")
    original_score = Column(Float, default=0.0)
    score_after_remediation = Column(Float, default=0.0)
    remaining_critical = Column(Integer, default=0)
    remaining_high = Column(Integer, default=0)
    remaining_medium = Column(Integer, default=0)
    remaining_low = Column(Integer, default=0)
    improvement_percentage = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="alerts")
