"""
auth.py — API-key based multi-tenant authentication (Phase 1).

Security Design:
- Clients authenticate via the mandatory `X-API-Key` header. Raw keys are
  NEVER stored — only a peppered HMAC-SHA256 digest lives in `api_keys.key_hash`.
- The organization scope is resolved *server-side* by looking up the hashed
  key. The client never supplies (and can never override) `organization_id`.
- Every authentication failure — missing header, unknown key, revoked key,
  or a disabled organization — returns the exact same generic 401 response.
  This prevents an attacker from distinguishing "key doesn't exist" from
  "key is revoked" from "org is disabled" (enumeration / oracle prevention).
- SlowAPI rate-limits calls to this dependency (keyed by client IP) to slow
  down brute-force / credential-stuffing attempts against API keys. This is
  the ONLY place rate limiting is applied in Phase 1.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple

from fastapi import Depends, Header, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from database import get_db
from models import ApiKey, Organization

logger = logging.getLogger(__name__)

API_KEY_HEADER_NAME = "X-API-Key"
_KEY_PREFIX = "asm_"

# ---------------------------------------------------------------------------
# Pepper — a server-side secret mixed into the HMAC digest. Without it, a
# leaked database alone is insufficient to brute-force/guess raw API keys.
# ---------------------------------------------------------------------------
_API_KEY_PEPPER = os.environ.get("API_KEY_PEPPER", "")
if not _API_KEY_PEPPER:
    raise RuntimeError(
        "API_KEY_PEPPER environment variable is not set. "
        "The application refuses to start without a pepper for API key hashing."
    )

# ---------------------------------------------------------------------------
# Rate limiter — applied ONLY to the API-key validation dependency below.
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)


def hash_api_key(raw_key: str) -> str:
    """Peppered HMAC-SHA256 digest of a raw API key, hex-encoded."""
    return hmac.new(
        _API_KEY_PEPPER.encode("utf-8"),
        raw_key.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_api_key() -> Tuple[str, str, str]:
    """
    Generates a brand-new random API key.

    Returns (raw_key, key_hash, prefix):
    - raw_key must be shown to the caller exactly once and never stored.
    - key_hash is what gets persisted in the database.
    - prefix is a short, non-secret slice used for display/identification only.
    """
    raw_key = f"{_KEY_PREFIX}{secrets.token_urlsafe(32)}"
    key_hash = hash_api_key(raw_key)
    prefix = raw_key[: len(_KEY_PREFIX) + 8]
    return raw_key, key_hash, prefix


def _generic_unauthorized() -> HTTPException:
    """
    A single, generic 401 used for every authentication failure mode so that
    no information about *why* auth failed is ever leaked to the caller.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "ApiKey"},
    )


@limiter.limit("20/minute")
def get_organization_id(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias=API_KEY_HEADER_NAME),
    db: Session = Depends(get_db),
) -> str:
    """
    FastAPI dependency: authenticates the request via `X-API-Key` and resolves
    the organization ID server-side.

    The header is declared as optional at the FastAPI level (default `None`)
    so a missing key falls through to the same generic 401 response as any
    other invalid key, instead of FastAPI's default 422 "field required"
    validation error — every authentication failure mode must look identical
    to the caller.

    Replaces the old header-trusting `X-Organization-ID` stub. The returned
    `organization_id` comes exclusively from the database record matched by
    the hashed key — it is never taken from client-supplied input, so it is
    safe to use directly as the hard tenant filter on every query.
    """
    raw_key = (x_api_key or "").strip()
    if not raw_key:
        raise _generic_unauthorized()

    key_hash = hash_api_key(raw_key)

    record: Optional[ApiKey] = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
        .first()
    )
    if record is None:
        raise _generic_unauthorized()

    organization: Optional[Organization] = (
        db.query(Organization)
        .filter(
            Organization.id == record.organization_id,
            Organization.is_active.is_(True),
        )
        .first()
    )
    if organization is None:
        raise _generic_unauthorized()

    record.last_used_at = datetime.now(timezone.utc)
    db.flush()

    return organization.id
