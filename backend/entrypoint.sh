#!/bin/bash
set -e

echo "Updating Trivy vulnerability database..."
trivy image --download-db-only --quiet || echo "Trivy DB update skipped, will retry on scan"

echo "Starting VULNSIGHT-V2 backend..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
