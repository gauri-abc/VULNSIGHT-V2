#!/bin/bash
set -e

echo "Updating Trivy vulnerability database..."
trivy image --download-db-only --quiet || echo "Trivy DB update skipped, will retry on scan"

echo "Configuring Docker BuildKit builder..."
docker buildx inspect vulnsight-builder >/dev/null 2>&1 \
  || docker buildx create --name vulnsight-builder --use \
  || docker buildx use vulnsight-builder \
  || echo "Buildx setup skipped, will use default builder"

echo "Starting VULNSIGHT-V2 backend..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
