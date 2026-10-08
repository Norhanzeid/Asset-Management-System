"""
main.py — FastAPI application: routing, upsert business logic, multi-tenancy.

Architectural decisions:
- Sync routes (`def`, not `async def`) let FastAPI automatically offload each
  request to AnyIO's thread pool. This keeps the event loop unblocked while
  SQLAlchemy (psycopg2, sync driver) performs blocking I/O.
- Multi-tenancy is enforced via `get_organization_id()` dependency (see
  `auth.py`). Every query hard-filters on `organization_id` — the LLM never
  controls this value, and neither does the caller.
- The bulk-import uses nested transactions (SAVEPOINT) per record so a bad
  record cannot roll back the entire batch.
- Two-pass import: assets are flushed first, relationships second, so forward
  references within a single batch resolve correctly.

Security:
- Requests authenticate via the mandatory `X-API-Key` header (see `auth.py`).
  The organization is resolved server-side from the hashed key — clients
  cannot supply or override the organization identifier.
- Pydantic v2 validates every incoming field at the boundary; raw dicts never
  reach the database layer.
- Individual record errors are caught and reported without leaking stack traces
  to the caller.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load .env before ANY import that reads os.environ at module level
# (database.py creates the engine at import time and reads POSTGRES_PASSWORD)
load_dotenv()

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.orm import Session

from ai_layer import run_agent
from auth import get_organization_id, limiter
from database import create_all_tables, get_db, verify_connectivity
from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    Asset,
    AssetImportRecord,
    AssetRelationship,
    ImportLog,
    ImportResponse,
    Organization,
    OrganizationResponse,
    RelationshipType,
)
from services import AssetService

# ---------------------------------------------------------------------------
# Logging — structured, never emits secrets
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s [%(funcName)s]: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

_ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "*").split(",")]

app = FastAPI(
    title="ASM Asset Management API",
    version="1.0.0",
    description=(
        "Attack Surface Monitoring — bulk asset ingestion, queryable inventory, "
        "and AI-powered risk analysis."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

if _ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS)

# SlowAPI rate limiting — scoped to API-key validation only (see auth.py).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.on_event("startup")
def on_startup() -> None:
    create_all_tables()
    logger.info("ASM Asset Management API started successfully.")


# ---------------------------------------------------------------------------
# Auth / Multi-Tenancy dependency
# ---------------------------------------------------------------------------
#
# `get_organization_id` now lives in auth.py: it authenticates the mandatory
# `X-API-Key` header and resolves the organization server-side from the
# hashed key. It is imported above and used unchanged as a FastAPI dependency
# in every route below.


# ---------------------------------------------------------------------------
# Upsert helpers
# ---------------------------------------------------------------------------


def _upsert_asset(
    db: Session,
    record: AssetImportRecord,
    org_id: str,
    now: datetime,
) -> tuple[Asset, bool]:
    """
    Insert or update a single Asset within the current transaction.

    On INSERT:  sets first_seen = last_seen = now.
    On UPDATE:  updates last_seen, merges tags (union, deduped), merges metadata
                (shallow merge — record values overwrite existing keys).

    Returns (asset_orm_object, was_created: bool).

    Multi-tenancy: the SELECT filter includes `organization_id == org_id`
    unconditionally, so a record with the same ID in a different org is treated
    as a new asset (correct isolation behaviour).
    """
    existing: Optional[Asset] = (
        db.query(Asset)
        .filter(
            Asset.id == record.id,
            Asset.organization_id == org_id,  # HARD tenant filter — non-negotiable
        )
        .first()
    )

    if existing is not None:
        # --- UPDATE path ---
        existing.last_seen = now
        existing.status = record.status
        if record.source:
            existing.source = record.source
        # Merge tags: union of existing and incoming, deduplicated, preserving order
        existing_tags: List[str] = existing.tags or []
        merged_tags = list(dict.fromkeys(existing_tags + record.tags))
        existing.tags = merged_tags
        # Shallow-merge metadata: incoming keys overwrite, new keys are added
        merged_meta: Dict[str, Any] = {**(existing.metadata_ or {}), **record.metadata}
        existing.metadata_ = merged_meta
        return existing, False
    else:
        # --- INSERT path ---
        asset = Asset(
            id=record.id,
            organization_id=org_id,
            type=record.type,
            value=record.value,
            status=record.status,
            first_seen=now,
            last_seen=now,
            source=record.source,
            tags=record.tags,
            metadata_=record.metadata,
        )
        db.add(asset)
        return asset, True


def _upsert_relationship(
    db: Session,
    source_id: str,
    target_id: str,
    rel_type: RelationshipType,
    org_id: str,
) -> None:
    """
    Insert a directed relationship edge if one does not already exist.
    The UniqueConstraint on (org, source, target, type) handles race conditions.
    Silently no-ops on duplicates.
    """
    existing = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.organization_id == org_id,
            AssetRelationship.source_asset_id == source_id,
            AssetRelationship.target_asset_id == target_id,
            AssetRelationship.relationship_type == rel_type,
        )
        .first()
    )
    if existing is None:
        rel = AssetRelationship(
            id=str(uuid.uuid4()),
            organization_id=org_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            relationship_type=rel_type,
        )
        db.add(rel)


def _relationship_fields(
    record: AssetImportRecord,
) -> List[tuple[Optional[str], RelationshipType]]:
    """Extract all relationship shorthand fields from a record as (target_id, type) pairs."""
    return [
        (record.parent, RelationshipType.parent),
        (record.covers, RelationshipType.covers),
        (record.resolves, RelationshipType.resolves),
        (record.hosts, RelationshipType.hosts),
        (record.belongs_to, RelationshipType.belongs_to),
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post(
    "/import",
    response_model=ImportResponse,
    status_code=status.HTTP_200_OK,
    summary="Bulk import / upsert assets (idempotent)",
    tags=["Ingestion"],
)
def bulk_import(
    payload: List[Dict[str, Any]],
    org_id: str = Depends(get_organization_id),
    db: Session = Depends(get_db),
) -> ImportResponse:
    """
    Accepts a raw JSON array of asset objects. Idempotent upsert semantics:

    - **New asset** (ID not yet in DB for this org): inserted with `first_seen = now`.
    - **Existing asset**: `last_seen` refreshed, `tags` union-merged,
      `metadata` shallow-merged.
    - Relationship shorthand fields (`parent`, `covers`, `resolves`, `hosts`,
      `belongs_to`) are persisted as directed edges in `asset_relationships`.

    **Error handling**: each record is processed inside an individual SAVEPOINT.
    A failure on one record does not abort the rest of the batch. Failures are
    collected and returned in the response body.

    **Two-pass strategy**: all asset upserts are flushed first; relationships are
    created in a second pass so forward references within a single batch work.
    """
    if len(payload) > 10_000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size exceeds the 10,000 asset limit per request.",
        )

    now = datetime.now(timezone.utc)
    imported = 0
    updated = 0
    failed = 0
    errors: List[Dict[str, Any]] = []

    # Track successfully upserted records for the relationship pass.
    valid_records: List[AssetImportRecord] = []

    # ── Pass 1: validate and upsert assets ──────────────────────────────────
    for raw in payload:
        raw_id = str(raw.get("id", "unknown"))[:50] if isinstance(raw, dict) else "unknown"

        # Validate the record with Pydantic — catch per-record validation errors.
        try:
            record = AssetImportRecord.model_validate(raw)
        except ValidationError as exc:
            failed += 1
            # Return only the first error message to avoid verbose leakage.
            first_error = exc.errors()[0] if exc.errors() else {}
            errors.append(
                {
                    "id": raw_id,
                    "error": f"Validation: {first_error.get('msg', str(exc))}",
                    "field": str(first_error.get("loc", "")),
                }
            )
            continue

        # Upsert inside a SAVEPOINT — a DB error rolls back only this record.
        try:
            with db.begin_nested():
                _, created = _upsert_asset(db, record, org_id, now)
                db.flush()  # push SQL; FK / constraint errors surface here

            valid_records.append(record)
            if created:
                imported += 1
            else:
                updated += 1

        except Exception as exc:
            failed += 1
            # Log detail internally; return only a safe summary to the caller.
            logger.warning(
                "Asset upsert failed for id=%s org=%s: %s",
                record.id,
                org_id[:20],
                str(exc)[:200],
            )
            errors.append({"id": record.id, "error": "Database constraint violation."})

    # ── Pass 2: create relationships ────────────────────────────────────────
    for record in valid_records:
        for target_id, rel_type in _relationship_fields(record):
            if not target_id:
                continue
            try:
                with db.begin_nested():
                    _upsert_relationship(db, record.id, target_id, rel_type, org_id)
                    db.flush()
            except Exception as exc:
                # Relationship failures are non-fatal — log and continue.
                logger.warning(
                    "Relationship %s→%s (%s) failed: %s",
                    record.id,
                    target_id,
                    rel_type.value,
                    str(exc)[:200],
                )

    # Audit trail for the admin console's "Import History" page. Written once
    # per batch, inside the same session/transaction as the import itself.
    db.add(
        ImportLog(
            organization_id=org_id,
            total=len(payload),
            imported=imported,
            updated=updated,
            failed=failed,
        )
    )

    # get_db dependency calls session.commit() after this function returns.
    return ImportResponse(
        total=len(payload),
        imported=imported,
        updated=updated,
        failed=failed,
        errors=errors,
    )


@app.get(
    "/assets",
    response_model=Dict[str, Any],
    summary="List / query assets with pagination and filtering",
    tags=["Query"],
)
def list_assets(
    type: Optional[str] = Query(None, description="Filter by asset type"),
    asset_status: Optional[str] = Query(None, description="Filter by asset status"),
    source: Optional[str] = Query(None, max_length=255, description="Filter by source"),
    tag: Optional[str] = Query(None, max_length=128, description="Filter by tag value"),
    id: Optional[str] = Query(None, max_length=255, description="Exact asset ID lookup"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page (max 100)"),
    org_id: str = Depends(get_organization_id),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Returns a paginated, filtered list of assets scoped to the authenticated org.

    All query parameters are validated through `AssetsQueryParams` before touching
    the database. The `organization_id` filter is unconditionally applied — it
    cannot be overridden by any query parameter.

    Business logic lives in `AssetService.list_assets` — this route is a thin
    orchestration layer shared with the LangChain tools in `ai_layer.py`.
    """
    try:
        return AssetService.list_assets(
            db,
            org_id,
            type=type,
            status=asset_status,
            source=source,
            tag=tag,
            id=id,
            page=page,
            page_size=page_size,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(),
        )


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="AI-powered asset analysis via natural-language query",
    tags=["AI Analysis"],
)
def analyze(
    body: AnalyzeRequest,
    org_id: str = Depends(get_organization_id),
    db: Session = Depends(get_db),
) -> AnalyzeResponse:
    """
    Dispatches the natural-language query to the LangChain ReAct Agent.

    **Multi-tenancy guarantee**: the `org_id` extracted from the authenticated
    request header is injected *programmatically* into the agent's tools via a
    factory closure. The LLM has no mechanism to override or inspect it.

    **Anti-hallucination**: agent temperature is 0.0; the system prompt mandates
    strict grounding to tool-returned data only.

    The agent's tools query the database directly through the shared
    `AssetService` (same as `/assets`) — there is no internal HTTP hop.
    """
    try:
        result = run_agent(query=body.query, org_id=org_id, db=db)
    except RuntimeError as exc:
        # Configuration errors (e.g. missing API key) — return 503.
        logger.error("Agent configuration error for org=%s: %s", org_id[:20], str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI analysis is not available. Check server configuration.",
        )
    except Exception as exc:
        logger.error("Agent execution failed for org=%s: %s", org_id[:20], str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Agent execution failed. Please retry.",
        )

    return AnalyzeResponse(result=result, organization_id=org_id)


@app.get(
    "/organizations/me",
    response_model=OrganizationResponse,
    summary="Get the authenticated organization's profile",
    tags=["Query"],
)
def get_current_organization(
    org_id: str = Depends(get_organization_id),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    """
    Returns safe, non-sensitive profile information for the organization
    resolved from the authenticated `X-API-Key` header.

    **Multi-tenancy guarantee**: `org_id` comes exclusively from
    `get_organization_id` (see auth.py) — it is never accepted from headers,
    query parameters, or the request body, so a caller can only ever see
    their own organization's profile.

    Never exposes API keys, key hashes, or other internal identifiers.
    """
    organization: Optional[Organization] = (
        db.query(Organization)
        .filter(Organization.id == org_id, Organization.is_active.is_(True))
        .first()
    )
    if organization is None:
        # Should be unreachable — get_organization_id already validated the
        # org is active — but fail safely with the same generic shape.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found.")

    return OrganizationResponse(
        id=organization.id,
        name=organization.name,
        status="active" if organization.is_active else "inactive",
        created_at=organization.created_at,
    )


# ---------------------------------------------------------------------------
# Health check (excluded from OpenAPI schema)
# ---------------------------------------------------------------------------


@app.get("/health", include_in_schema=False)
def health_check() -> JSONResponse:
    """Liveness + readiness probe for container orchestration."""
    db_ok = verify_connectivity()
    body = {
        "status": "healthy" if db_ok else "degraded",
        "db": "connected" if db_ok else "unreachable",
    }
    http_status = 200 if db_ok else 503
    return JSONResponse(content=body, status_code=http_status)
