#!/bin/bash
set -e

echo "Updating Trivy vulnerability database..."
trivy image --download-db-only --quiet || echo "Trivy DB update skipped, will retry on scan"

if docker buildx version >/dev/null 2>&1; then
  echo "Configuring Docker BuildKit builder..."
  docker buildx inspect vulnsight-builder >/dev/null 2>&1 \
    || docker buildx create --name vulnsight-builder --use \
    || docker buildx use vulnsight-builder \
    || echo "Buildx builder setup skipped, will use default builder"
else
  echo "Docker buildx not available, scans will fall back to legacy docker build"
fi

echo "Starting VULNSIGHT-V2 backend..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
