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

    service = relationship("Service", back_populates="vulnerabilities")


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
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="scan_history")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="alerts")
