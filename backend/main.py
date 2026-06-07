from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from routers import scan, dashboard, reports, services

app = FastAPI(
    title="VULNSIGHT-V2",
    description="DevSecOps Security Gate Platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(dashboard.router)
app.include_router(reports.router)
app.include_router(services.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "vulnsight-v2"}
