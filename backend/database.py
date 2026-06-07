import os
import time

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://vulnsight:vulnsight@postgres:5432/vulnsight",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

VULNERABILITY_COLUMN_MIGRATIONS = [
    ("category", "VARCHAR(32) DEFAULT 'image'"),
]

SCAN_HISTORY_COLUMN_MIGRATIONS = [
    ("fixable_count", "INTEGER DEFAULT 0"),
    ("unfixable_count", "INTEGER DEFAULT 0"),
    ("risk_accepted", "INTEGER DEFAULT 0"),
]

REMEDIATION_COLUMN_MIGRATIONS = [
    ("dependency_patches_json", "TEXT DEFAULT '[]'"),
    ("dependency_fixes_json", "TEXT DEFAULT '[]'"),
    ("remediation_state", "VARCHAR(32) DEFAULT 'REMEDIATION_AVAILABLE'"),
    ("status_message", "TEXT DEFAULT ''"),
    ("show_generate_fix", "INTEGER DEFAULT 1"),
    ("previous_updated_dockerfile", "TEXT DEFAULT ''"),
    ("remaining_critical", "INTEGER DEFAULT 0"),
    ("remaining_high", "INTEGER DEFAULT 0"),
    ("remaining_medium", "INTEGER DEFAULT 0"),
    ("remaining_low", "INTEGER DEFAULT 0"),
    ("original_score", "DOUBLE PRECISION DEFAULT 0"),
    ("score_after_remediation", "DOUBLE PRECISION DEFAULT 0"),
    ("improvement_percentage", "DOUBLE PRECISION DEFAULT 0"),
    ("original_critical", "INTEGER DEFAULT 0"),
    ("original_high", "INTEGER DEFAULT 0"),
    ("original_medium", "INTEGER DEFAULT 0"),
    ("original_low", "INTEGER DEFAULT 0"),
]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def wait_for_db(max_retries=30, delay=2):
    for attempt in range(max_retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            if attempt == max_retries - 1:
                raise
            time.sleep(delay)
    return False


def migrate_schema():
    inspector = inspect(engine)
    table_names = inspector.get_table_names()

    if "remediations" in table_names:
        existing_cols = {col["name"] for col in inspector.get_columns("remediations")}

        with engine.begin() as conn:
            for col_name, col_def in REMEDIATION_COLUMN_MIGRATIONS:
                if col_name not in existing_cols:
                    conn.execute(
                        text(f"ALTER TABLE remediations ADD COLUMN {col_name} {col_def}")
                    )

            if "updated_dockerfile" in existing_cols:
                conn.execute(
                    text(
                        "ALTER TABLE remediations "
                        "ALTER COLUMN updated_dockerfile DROP NOT NULL"
                    )
                )

            conn.execute(
                text(
                    "UPDATE remediations SET remediation_state = 'REMEDIATION_AVAILABLE' "
                    "WHERE remediation_state IS NULL"
                )
            )
            conn.execute(
                text(
                    "UPDATE remediations SET show_generate_fix = 1 "
                    "WHERE show_generate_fix IS NULL"
                )
            )
            conn.execute(
                text(
                    "UPDATE remediations SET "
                    "remaining_critical = current_critical, "
                    "remaining_high = current_high, "
                    "remaining_medium = current_medium, "
                    "remaining_low = current_low, "
                    "original_critical = current_critical, "
                    "original_high = current_high, "
                    "original_medium = current_medium, "
                    "original_low = current_low "
                    "WHERE original_score IS NULL OR original_score = 0"
                )
            )

    if "scan_history" in table_names:
        existing_cols = {col["name"] for col in inspector.get_columns("scan_history")}
        with engine.begin() as conn:
            for col_name, col_def in SCAN_HISTORY_COLUMN_MIGRATIONS:
                if col_name not in existing_cols:
                    conn.execute(
                        text(f"ALTER TABLE scan_history ADD COLUMN {col_name} {col_def}")
                    )

            conn.execute(
                text(
                    "UPDATE scan_history SET decision = 'PASS', risk_accepted = 1 "
                    "WHERE decision = 'PASS_WITH_RISK'"
                )
            )

    if "vulnerabilities" in table_names:
        existing_cols = {col["name"] for col in inspector.get_columns("vulnerabilities")}
        with engine.begin() as conn:
            for col_name, col_def in VULNERABILITY_COLUMN_MIGRATIONS:
                if col_name not in existing_cols:
                    conn.execute(
                        text(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_def}")
                    )
            conn.execute(
                text(
                    "UPDATE vulnerabilities SET category = 'image' "
                    "WHERE category IS NULL OR category = ''"
                )
            )


def init_db():
    wait_for_db()
    from models import (  # noqa: F401
        Repository,
        Service,
        Vulnerability,
        DockerSecurityFinding,
        ScanHistory,
        Remediation,
        RemediationHistory,
        Alert,
    )

    Base.metadata.create_all(bind=engine)
    migrate_schema()
