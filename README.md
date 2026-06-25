# ASM Asset Management System

Attack Surface Monitoring (ASM) API for:

- bulk asset import/upsert
- filtered asset inventory queries
- AI-powered ASM analysis using LangChain + OpenAI

Tech stack: FastAPI, SQLAlchemy, PostgreSQL, LangChain, OpenAI.

## Features

- Multi-tenant data isolation using X-Organization-ID
- Idempotent bulk import with per-record error handling
- Relationship mapping between assets (parent, covers, resolves, hosts, belongs_to)
- Asset filtering by type, status, source, tag, and ID
- AI analysis endpoint with prompt-injection validation
- Dockerized deployment with health checks

## Project Structure

.
|- ai_layer.py
|- database.py
|- docker-compose.yml
|- Dockerfile
|- main.py
|- models.py
|- requirements.txt
|- requirements-lock.txt
|- .env.example
`- README.md

## API Endpoints

- GET /health
  - Readiness/liveness check
- POST /import
  - Bulk import/upsert assets
- GET /assets
  - Query paginated asset inventory
- POST /analyze
  - Run natural-language ASM analysis using AI

Swagger docs: http://localhost:8000/docs

## Environment Variables

Required:

- POSTGRES_PASSWORD
- OPENAI_API_KEY

Common optional values (with defaults):

- POSTGRES_HOST=localhost
- POSTGRES_PORT=5432
- POSTGRES_USER=assetuser
- POSTGRES_DB=assetdb
- APP_PORT=8000
- LLM_MODEL=gpt-4o
- AGENT_MAX_ITERATIONS=10
- AGENT_TIMEOUT_SECONDS=120
- ALLOWED_HOSTS=*

## Quick Start (Docker)

1) Create env file:

```bash
cp .env.example .env
```

2) Edit .env and set:

- POSTGRES_PASSWORD
- OPENAI_API_KEY

3) Start stack:

```bash
docker compose up --build
```

4) Verify:

```bash
curl http://localhost:8000/health
```

## Quick Start (Local Python)

1) Create and activate venv (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Install dependencies:

```powershell
pip install -r requirements.txt
```

3) Start PostgreSQL (Docker):

```bash
docker run -d --name asm-pg -e POSTGRES_USER=assetuser -e POSTGRES_PASSWORD=your_password -e POSTGRES_DB=assetdb -p 5432:5432 postgres:16-alpine
```

4) Start API:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Sample API Usage

### 1) Import sample assets

```bash
curl -X POST http://localhost:8000/import \
  -H "Content-Type: application/json" \
  -H "X-Organization-ID: my-org" \
  -d '[
    {"id":"a1","type":"domain","value":"example.com","status":"active","source":"scan","tags":["root"],"metadata":{}},
    {"id":"a2","type":"subdomain","value":"api.example.com","status":"active","source":"scan","tags":["prod"],"metadata":{},"parent":"a1"},
    {"id":"a3","type":"certificate","value":"CN=api.example.com","status":"active","source":"scan","tags":["prod"],"metadata":{"issuer":"Lets Encrypt","expires":"2025-01-02"},"covers":"a2"},
    {"id":"a4","type":"service","value":"https","status":"active","source":"scan","tags":["external"],"metadata":{"port":443,"protocol":"tcp"},"hosts":"a2"}
  ]'
```

Example response:

```json
{
  "total": 4,
  "imported": 4,
  "updated": 0,
  "failed": 0,
  "errors": []
}
```

### 2) Query assets

```bash
curl "http://localhost:8000/assets?type=subdomain&page=1&page_size=10" \
  -H "X-Organization-ID: my-org"
```

Example response (truncated):

```json
{
  "total": 1,
  "page": 1,
  "page_size": 10,
  "pages": 1,
  "assets": [
    {
      "id": "a2",
      "organization_id": "my-org",
      "type": "subdomain",
      "value": "api.example.com",
      "status": "active",
      "source": "scan",
      "tags": ["prod"],
      "metadata": {}
    }
  ]
}
```

## Example Prompts Used In This Project (with Outputs)

These are natural-language prompts sent to POST /analyze.
Outputs below are example response styles from this system.

### Prompt 1

Are there any expired certificates in my inventory? Provide a risk score.

Example output:

```markdown
## Certificate Risk Analysis

Risk Score: 9/10 (Critical)

- Certificate: a3 (CN=api.example.com)
- Expires: 2025-01-02
- Status: expired relative to June 2026 reference date
- Risk reason: Expired certificate can break trust and enable security incidents.
- Action: Renew certificate immediately and verify deployment across endpoints.
```

### Prompt 2

List all active subdomains and explain their risk score.

Example output:

```markdown
## Active Subdomains

1) id: a2
   - value: api.example.com
   - status: active
   - Risk Score: 4/10 (Medium)
   - Risk reason: External production-facing subdomain should be continuously monitored.
```

### Prompt 3

Show me assets tagged prod and summarize overall risk.

Example output:

```markdown
## Assets Tagged prod

- a2 (subdomain): api.example.com
- a3 (certificate): CN=api.example.com

Risk Score: 7/10 (High)

Summary:
- Production assets are present and internet-facing.
- At least one certificate is expired.
- Immediate remediation focus should be certificate lifecycle and exposure review.
```

### Prompt 4

Generate a short attack surface report in Markdown.

Example output:

```markdown
## Executive Summary

The organization has externally visible assets across domain, subdomain, certificate, and service categories.

## Key Findings

- Expired certificate detected (critical priority).
- Production-tagged assets require tighter operational controls.
- Exposed service metadata indicates externally reachable endpoints.

## Recommendations

1. Renew expired certificates and automate renewal checks.
2. Review exposure of production assets and restrict unnecessary access.
3. Add continuous monitoring for service and certificate drift.
```

## Security Notes

- ORM-based queries with input validation reduce SQL injection risk.
- Prompt-injection pattern checks are applied to analyze requests.
- AI responses are grounded through tool-based retrieval patterns.
- Tenant isolation is enforced through organization header filtering.

## Ready For GitHub Push Checklist

- Update .env values locally (do not commit secrets).
- Ensure OPENAI_API_KEY and POSTGRES_PASSWORD are set.
- Verify docker compose up --build works on your machine.
- Verify /health, /import, /assets, and /analyze endpoints.
- Commit code and README together.