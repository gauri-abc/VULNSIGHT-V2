import os
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://vulnsight:vulnsight@postgres:5432/vulnsight",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


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
                conn.execute(__import__("sqlalchemy").text("SELECT 1"))
            return True
        except Exception:
            if attempt == max_retries - 1:
                raise
            time.sleep(delay)
    return False


def init_db():
    wait_for_db()
    from models import Repository, Service, Vulnerability, ScanHistory, Alert  # noqa: F401

    Base.metadata.create_all(bind=engine)
