# Asset Management System (AMS)

A comprehensive **Attack Surface Monitoring (ASM)** platform for managing, analyzing, and securing your digital assets. This system provides a powerful API combined with an AI-powered analysis layer to help organizations maintain visibility and control over their asset inventory.

**Key Capabilities:**
- 📦 Bulk asset import/upsert with validation
- 🔍 Filtered asset inventory queries with advanced filtering
- 🤖 AI-powered ASM analysis using LangChain + OpenAI
- 🔐 Multi-tenant data isolation with API-key authentication
- 📊 Attack surface risk scoring and analysis

**Tech Stack:** FastAPI, SQLAlchemy, PostgreSQL, LangChain, OpenAI, Docker

## ✨ Features

- **Multi-Tenant Architecture:** Data isolation using API-key authentication (`X-API-Key` header)
- **Bulk Asset Operations:** Idempotent import/upsert with per-record error handling
- **Relationship Mapping:** Establish connections between assets (parent, covers, resolves, hosts, belongs_to)
- **Advanced Filtering:** Query by type, status, source, tag, and ID
- **AI-Powered Analysis:** Natural-language queries with prompt-injection protection
- **Risk Scoring:** Automated assessment of attack surface risk
- **Container-Ready:** Dockerized deployment with health checks and orchestration

## 🏗️ Project Architecture

```
Asset-Management-System/
├── ai_layer.py              # LangChain agent tools and analysis orchestration
├── auth.py                  # API-key authentication, hashing, rate limiting
├── database.py              # SQLAlchemy engine, session, and DB helpers
├── models.py                # ORM models and Pydantic schemas/validators
├── services.py              # Shared business logic (FastAPI + LangChain)
├── main.py                  # FastAPI routes: import, assets, analyze, health
├── manage_api_keys.py       # Admin CLI for organizations and API key management
├── admin_app.py             # Streamlit admin dashboard
├── admin_service.py         # Admin service business logic
├── customer_app.py          # Streamlit customer dashboard
├── customer_service.py      # Customer service business logic
├── docker-compose.yml       # Multi-container orchestration
├── Dockerfile               # Multi-stage container build
├── requirements.txt         # Python dependencies
├── requirements-lock.txt    # Fully locked dependency snapshot
├── .env.example             # Environment variable template
├── .gitignore               # Git ignore rules
└── README.md                # This file
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI application with REST endpoints |
| `models.py` | SQLAlchemy ORM models and Pydantic schemas |
| `database.py` | Database connection and session management |
| `services.py` | Core business logic used by API and AI layer |
| `auth.py` | API key authentication and rate limiting |
| `ai_layer.py` | LangChain integration for natural language analysis |
| `manage_api_keys.py` | CLI for administrative key provisioning |
| `admin_app.py` | Admin dashboard for system management |
| `customer_app.py` | Customer-facing dashboard |

## 📡 API Endpoints

### Health & Status

```http
GET /health
```
Readiness and liveness check. Returns `200 OK` with status when healthy.

### Asset Import

```http
POST /import
Content-Type: application/json
X-API-Key: <your-api-key>
```
Bulk import or update assets with idempotent handling and per-record error reporting.

### Asset Queries

```http
GET /assets?type=subdomain&status=active&page=1&page_size=10
X-API-Key: <your-api-key>
```
Query paginated asset inventory with filtering options.

### AI Analysis

```http
POST /analyze
Content-Type: application/json
X-API-Key: <your-api-key>
```
Run natural-language ASM analysis on your asset inventory using AI.

**📚 Interactive API Documentation:**
- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

## ⚙️ Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | `your_secure_password` |
| `OPENAI_API_KEY` | OpenAI API key for AI analysis | `sk-proj-...` |
| `API_KEY_PEPPER` | Secret pepper for API key hashing | `your-secret-pepper` |

### Optional Configuration (with defaults)

| Variable | Default | Purpose |
|----------|---------|---------|
| `POSTGRES_HOST` | localhost | Database host |
| `POSTGRES_PORT` | 5432 | Database port |
| `POSTGRES_USER` | assetuser | Database user |
| `POSTGRES_DB` | assetdb | Database name |
| `APP_PORT` | 8080 | API server port |
| `LLM_MODEL` | gpt-4o | LangChain LLM model |
| `AGENT_MAX_ITERATIONS` | 10 | Max AI agent iterations |
| `AGENT_TIMEOUT_SECONDS` | 120 | AI agent timeout |
| `ALLOWED_HOSTS` | * | CORS allowed hosts |
| `ASM_API_BASE_URL` | http://localhost:8080 | Self-referential API URL |

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

**Prerequisites:** Docker and Docker Compose installed

```bash
# 1. Clone and navigate to the project
git clone https://github.com/Norhanzeid/Asset-Management-System.git
cd Asset-Management-System

# 2. Create environment file
cp .env.example .env

# 3. Edit .env and update these variables:
# - POSTGRES_PASSWORD (use a strong password)
# - OPENAI_API_KEY (your OpenAI API key)
# - API_KEY_PEPPER (generate a random secret)

# 4. Start the stack
docker compose up --build

# 5. Verify the service is running
curl http://localhost:8080/health
# Response: {"status": "healthy"}

# 6. Access API documentation
# Visit: http://localhost:8080/docs
```

### Option 2: Local Python Environment

**Prerequisites:** Python 3.10+, PostgreSQL

```bash
# 1. Create and activate virtual environment (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux/macOS
python -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up PostgreSQL
# Option A: Use Docker
docker run -d --name asm-pg \
  -e POSTGRES_USER=assetuser \
  -e POSTGRES_PASSWORD=your_password \
  -e POSTGRES_DB=assetdb \
  -p 5432:5432 \
  postgres:16-alpine

# Option B: Use existing PostgreSQL server
# Update POSTGRES_HOST, POSTGRES_PORT in .env

# 4. Configure .env (copy .env.example first)
cp .env.example .env
# Edit .env with your PostgreSQL password and OpenAI API key

# 5. Start the API server
uvicorn main:app --reload --host 0.0.0.0 --port 8080

# 6. Access API at http://localhost:8080/docs
```

## 🔑 Authentication & API Key Management

Every request to protected endpoints requires a valid `X-API-Key` header. The API key resolves to an organization, preventing clients from overriding the organization identifier.

### Creating Organizations and API Keys

Use the bundled CLI tool for administrative provisioning:

```bash
# Create a new organization
python manage_api_keys.py create-org "Acme Corp"
# Output: organization_id: org-uuid-here

# Generate an API key for the organization
python manage_api_keys.py create-key org-uuid-here --name "CI Pipeline Key"
# Output: raw_api_key (printed once, not stored in DB)

# Store the raw API key securely (e.g., in environment/secrets manager)
```

### Authentication Details

- Raw keys are printed **only once** at creation time
- Only hashed versions are stored in the database
- Failed authentication attempts return generic `401 Unauthorized` responses
- Repeated failed attempts from the same client are rate-limited for security

## 💡 API Usage Examples

### Example 1: Import Assets

```bash
curl -X POST http://localhost:8080/import \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '[
    {
      "id": "a1",
      "type": "domain",
      "value": "example.com",
      "status": "active",
      "source": "scan",
      "tags": ["root"],
      "metadata": {}
    },
    {
      "id": "a2",
      "type": "subdomain",
      "value": "api.example.com",
      "status": "active",
      "source": "scan",
      "tags": ["prod"],
      "parent": "a1"
    },
    {
      "id": "a3",
      "type": "certificate",
      "value": "CN=api.example.com",
      "status": "active",
      "source": "scan",
      "tags": ["prod"],
      "metadata": {
        "issuer": "Let'\''s Encrypt",
        "expires": "2025-01-02"
      },
      "covers": "a2"
    }
  ]'
```

**Response:**
```json
{
  "total": 3,
  "imported": 3,
  "updated": 0,
  "failed": 0,
  "errors": []
}
```

### Example 2: Query Assets

```bash
curl "http://localhost:8080/assets?type=subdomain&status=active&page=1&page_size=10" \
  -H "X-API-Key: your-api-key-here"
```

**Response:**
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

### Example 3: AI Analysis Query

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key-here" \
  -d '{
    "query": "Are there any expired certificates in my inventory?"
  }'
```

**Response:**
```markdown
## Certificate Risk Analysis

Risk Score: 9/10 (Critical)

- Certificate: a3 (CN=api.example.com)
- Expires: 2025-01-02
- Status: Expired

Risk Reason: Expired certificates can break trust and enable security incidents.
Action Required: Renew certificate immediately and verify deployment.
```

## 🤖 AI Analysis Examples

These examples show natural-language prompts sent to `/analyze` with response styles:

### Prompt 1: Expired Certificate Detection

**Query:** "Are there any expired certificates in my inventory? Provide a risk score."

**Response:**
```markdown
## Certificate Risk Analysis

Risk Score: 9/10 (Critical)

Findings:
- Certificate: a3 (CN=api.example.com)
- Status: Expired as of current date
- Issuer: Let's Encrypt

Action Items:
1. Renew certificate immediately
2. Verify deployment across endpoints
3. Update certificate tracking procedures
```

### Prompt 2: Production Asset Review

**Query:** "List all active subdomains and explain their risk score."

**Response:**
```markdown
## Active Subdomains Risk Assessment

1) api.example.com (id: a2)
   - Status: active
   - Tags: prod
   - Risk Score: 4/10 (Medium)
   - Reason: External production-facing subdomain requires continuous monitoring

Recommendations:
- Enable threat monitoring
- Implement rate limiting
- Review access controls
```

### Prompt 3: Tag-Based Analysis

**Query:** "Show me assets tagged 'prod' and summarize overall risk."

**Response:**
```markdown
## Production Assets Summary

Assets:
- a2 (subdomain): api.example.com
- a3 (certificate): CN=api.example.com

Overall Risk Score: 7/10 (High)

Key Findings:
- Production assets are internet-facing
- Certificate requires immediate renewal
- Production access controls need review

Priority Actions:
1. Renew expired certificate (CRITICAL)
2. Audit production asset exposure
3. Implement enhanced monitoring
```

### Prompt 4: Attack Surface Report

**Query:** "Generate a comprehensive attack surface report."

**Response:**
```markdown
## Attack Surface Report

### Executive Summary
Organization has visible digital footprint across multiple asset categories.

### Asset Inventory
- Domains: 1 (example.com)
- Subdomains: 1 (api.example.com)
- Certificates: 1 (expired)
- Services: 1 (https on port 443)

### Critical Issues
1. **Expired Certificate** (CRITICAL)
   - CN=api.example.com expired 2025-01-02
   - Impact: Trust breakage, potential SSL errors

### Recommendations
1. Immediate: Renew expired certificates
2. Short-term: Review exposure of production assets
3. Ongoing: Implement certificate lifecycle automation
```

## 🔒 Security Features

- **ORM-Based Queries:** SQLAlchemy parameterized queries reduce SQL injection risk
- **Prompt Injection Protection:** Pattern-based validation for analyze endpoint requests
- **Multi-Tenant Isolation:** Organization-level data separation enforced at API level
- **API Key Hashing:** Raw keys never stored; only cryptographic hashes in database
- **Rate Limiting:** Failed authentication attempts are rate-limited per client
- **Generic Error Responses:** Authentication failures return `401 Unauthorized` without details
- **Input Validation:** Pydantic schemas validate all incoming data
- **CORS Configuration:** Configurable allowed hosts to prevent cross-origin abuse

## 🧪 Testing & Validation

Before pushing to production:

1. **Docker Compose Verification**
   ```bash
   docker compose up --build
   curl http://localhost:8080/health
   ```

2. **API Endpoint Testing**
   ```bash
   # Test import endpoint
   curl -X POST http://localhost:8080/import \
     -H "X-API-Key: your-key" \
     -d '[{"id":"test","type":"domain","value":"test.com","status":"active"}]'
   
   # Test query endpoint
   curl "http://localhost:8080/assets?type=domain" \
     -H "X-API-Key: your-key"
   
   # Test analyze endpoint
   curl -X POST http://localhost:8080/analyze \
     -H "X-API-Key: your-key" \
     -d '{"query":"List all assets"}'
   ```

3. **Environment Verification**
   - [ ] `.env` file created with strong passwords
   - [ ] `OPENAI_API_KEY` set to valid key
   - [ ] `POSTGRES_PASSWORD` changed from example value
   - [ ] `API_KEY_PEPPER` set to random value
   - [ ] Database connectivity verified
   - [ ] OpenAI API connectivity verified
