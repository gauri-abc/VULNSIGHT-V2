# VULNSIGHT-V2

**DevSecOps Security Gate Platform** — scan GitHub repositories for container vulnerabilities, enforce security policies, and visualize results.

## Overview

VULNSIGHT-V2 automates the full container security pipeline:

1. Clone a GitHub repository
2. Discover all Dockerfiles
3. Build Docker images
4. Scan images with Trivy
5. Parse and store vulnerabilities in PostgreSQL
6. Calculate security scores and apply gate policies (PASS / WARNING / FAIL)
7. Display results on a web dashboard and in Grafana

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML, CSS, Vanilla JavaScript, Nginx |
| Backend | FastAPI, Python |
| Database | PostgreSQL |
| Scanning | Trivy |
| Git | GitPython |
| Monitoring | Grafana |
| Orchestration | Docker Compose |

## Quick Start

### Prerequisites

- Docker Desktop (with Docker Compose)
- 4 GB+ free RAM (image builds are resource-intensive)
- Internet access (clone repos, Trivy DB updates)

### Run the Platform

```bash
docker compose up --build
```

Wait for all services to start, then open:

| Service | URL |
|---------|-----|
| **Scan UI** | http://localhost |
| **API Docs** | http://localhost:8000/docs |
| **Grafana** | http://localhost:3000 (admin / vulnsight) |
| **PostgreSQL** | localhost:5432 |

### First Test Scan

1. Open http://localhost
2. Enter repository URL: `https://github.com/gauri-abc/QuicKart`
3. Click **Start Security Assessment**
4. Wait for the pipeline to complete (clone → build → Trivy scan)
5. Review results: Dockerfiles found, images built, vulnerability counts, security score, and PASS/FAIL decision

Expected for QuicKart: **5 Dockerfiles**, **5 images built**.

## API Endpoints

### Scan

```http
POST /api/repository-scan
Content-Type: application/json

{
  "repo_url": "https://github.com/gauri-abc/QuicKart"
}
```

**Response:**

```json
{
  "scan_id": 1,
  "repository": "QuicKart",
  "dockerfiles_found": 5,
  "images_built": 5,
  "critical": 1,
  "high": 4,
  "medium": 8,
  "low": 12,
  "score": 63,
  "decision": "FAIL"
}
```

### Dashboard

- `GET /api/dashboard/stats` — aggregate statistics
- `GET /api/dashboard/severity-chart` — vulnerability breakdown
- `GET /api/dashboard/top-vulnerable-services` — ranked services
- `GET /api/dashboard/score-trend` — score history

### Services

- `GET /api/services/latest` — services from latest scan
- `GET /api/services/scan/{scan_id}` — services for a specific scan

### Reports

- `GET /api/reports/history` — all scan reports
- `GET /api/reports/{scan_id}/json` — JSON download
- `GET /api/reports/{scan_id}/csv` — CSV download
- `GET /api/reports/{scan_id}/pdf` — PDF download

## Security Scoring

Starting score: **100**

| Severity | Deduction |
|----------|-----------|
| Critical | -20 |
| High | -10 |
| Medium | -5 |
| Low | -1 |

Minimum score: **0**

## Security Gate Policies

| Condition | Decision |
|-----------|----------|
| Critical > 0 | **FAIL** |
| High > 5 | **FAIL** |
| Medium > 20 | **WARNING** |
| Otherwise | **PASS** |

## Project Structure

```
VULNSIGHT-V2/
├── frontend/          # Static web UI (Nginx)
├── backend/           # FastAPI application
├── grafana/           # Grafana provisioning & dashboards
├── docker-compose.yml
└── README.md
```

## Database Schema

- **repositories** — scanned repo metadata
- **services** — per-Dockerfile service records
- **vulnerabilities** — CVE findings per service
- **scan_history** — scan summaries with scores and decisions
- **alerts** — policy violation notifications

## GitHub Actions Integration (Future)

The scan API is designed for CI/CD integration:

```yaml
- name: VULNSIGHT Security Gate
  run: |
    RESULT=$(curl -s -X POST http://vulnsight:8000/api/repository-scan \
      -H "Content-Type: application/json" \
      -d '{"repo_url": "${{ github.server_url }}/${{ github.repository }}"}')
    DECISION=$(echo $RESULT | jq -r .decision)
    if [ "$DECISION" = "FAIL" ]; then exit 1; fi
```

## Stopping the Platform

```bash
docker compose down
```

To remove all data volumes:

```bash
docker compose down -v
```

## License

MIT
