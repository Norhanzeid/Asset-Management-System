"""
admin_service.py — Business logic shared by the Streamlit admin console.

This module never touches the customer-facing FastAPI routes or LangChain
tools in `ai_layer.py` / `services.py` — it is a separate, admin-only data
access layer that talks directly to the database via SQLAlchemy, exactly the
way `manage_api_keys.py` already does.

Security:
- Raw API keys are generated here (via `auth.generate_api_key`) and returned
  to the caller exactly once, at creation time. They are never persisted,
  logged, or re-displayed afterward — only `prefix` and `key_hash` live in
  the database.
- All admin-console access must be gated by `verify_admin_password()` before
  any function in this module is invoked (enforced in `admin_app.py`).
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from auth import generate_api_key
from models import ApiKey, Asset, ImportLog, Organization


# ---------------------------------------------------------------------------
# Admin authentication
# ---------------------------------------------------------------------------


def verify_admin_password(candidate: str) -> bool:
    """
    Timing-safe comparison of the supplied password against `ADMIN_PASSWORD`.

    Raises RuntimeError at call time (not import time) if the env var is
    unset, so importing this module in a non-admin context never fails.
    """
    expected = os.environ.get("ADMIN_PASSWORD", "")
    if not expected:
        raise RuntimeError(
            "ADMIN_PASSWORD environment variable is not set. "
            "The admin console refuses to start without an admin password."
        )
    return hmac.compare_digest(candidate or "", expected)


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------


@dataclass
class OrgStats:
    id: str
    name: str
    is_active: bool
    created_at: Any
    asset_count: int
    active_key_count: int
    total_key_count: int
    last_import_at: Optional[Any]


def list_organizations_with_stats(db: Session) -> List[OrgStats]:
    """Returns every organization with aggregate asset/key/import stats."""
    orgs = db.query(Organization).order_by(Organization.created_at).all()

    results: List[OrgStats] = []
    for org in orgs:
        asset_count = (
            db.query(func.count(Asset.id))
            .filter(Asset.organization_id == org.id)
            .scalar()
            or 0
        )
        active_key_count = (
            db.query(func.count(ApiKey.id))
            .filter(ApiKey.organization_id == org.id, ApiKey.is_active.is_(True))
            .scalar()
            or 0
        )
        total_key_count = (
            db.query(func.count(ApiKey.id))
            .filter(ApiKey.organization_id == org.id)
            .scalar()
            or 0
        )
        last_import_at = (
            db.query(func.max(ImportLog.created_at))
            .filter(ImportLog.organization_id == org.id)
            .scalar()
        )
        results.append(
            OrgStats(
                id=org.id,
                name=org.name,
                is_active=org.is_active,
                created_at=org.created_at,
                asset_count=asset_count,
                active_key_count=active_key_count,
                total_key_count=total_key_count,
                last_import_at=last_import_at,
            )
        )
    return results


def create_organization(db: Session, name: str) -> Organization:
    """Creates a new organization. Raises ValueError on a duplicate name."""
    name = (name or "").strip()
    if not name:
        raise ValueError("Organization name cannot be empty.")
    if len(name) > 255:
        raise ValueError("Organization name exceeds 255 characters.")

    existing = db.query(Organization).filter(Organization.name == name).first()
    if existing is not None:
        raise ValueError(f"An organization named '{name}' already exists.")

    org = Organization(name=name)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def set_organization_active(db: Session, organization_id: str, is_active: bool) -> Organization:
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if org is None:
        raise ValueError("Organization not found.")
    org.is_active = is_active
    db.commit()
    db.refresh(org)
    return org


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def list_api_keys(db: Session, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns API key metadata only — `key_hash` and the raw key are never
    included. Each row is joined with its organization name for display.
    """
    query = db.query(ApiKey, Organization.name).join(
        Organization, ApiKey.organization_id == Organization.id
    )
    if organization_id:
        query = query.filter(ApiKey.organization_id == organization_id)

    rows = query.order_by(ApiKey.created_at.desc()).all()
    return [
        {
            "id": key.id,
            "organization_id": key.organization_id,
            "organization_name": org_name,
            "prefix": key.prefix,
            "name": key.name,
            "is_active": key.is_active,
            "created_at": key.created_at,
            "last_used_at": key.last_used_at,
        }
        for key, org_name in rows
    ]


def create_api_key(db: Session, organization_id: str, name: Optional[str]) -> Dict[str, Any]:
    """
    Creates a new API key. Returns the raw key ONCE in the result dict — the
    caller (Streamlit UI) must display it to the operator immediately and
    must not persist it anywhere itself.
    """
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if org is None:
        raise ValueError("Organization not found.")

    raw_key, key_hash, prefix = generate_api_key()
    api_key = ApiKey(
        organization_id=org.id,
        key_hash=key_hash,
        prefix=prefix,
        name=(name or "").strip() or None,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return {
        "id": api_key.id,
        "organization_id": org.id,
        "organization_name": org.name,
        "prefix": api_key.prefix,
        "name": api_key.name,
        "raw_key": raw_key,  # shown once — never persisted
    }


def revoke_api_key(db: Session, api_key_id: str) -> ApiKey:
    key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()
    if key is None:
        raise ValueError("API key not found.")
    key.is_active = False
    db.commit()
    db.refresh(key)
    return key


# ---------------------------------------------------------------------------
# Import history
# ---------------------------------------------------------------------------


def list_import_logs(
    db: Session, organization_id: Optional[str] = None, limit: int = 200
) -> List[Dict[str, Any]]:
    query = db.query(ImportLog, Organization.name).join(
        Organization, ImportLog.organization_id == Organization.id
    )
    if organization_id:
        query = query.filter(ImportLog.organization_id == organization_id)

    rows = query.order_by(ImportLog.created_at.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "organization_id": log.organization_id,
            "organization_name": org_name,
            "created_at": log.created_at,
            "total": log.total,
            "imported": log.imported,
            "updated": log.updated,
            "failed": log.failed,
        }
        for log, org_name in rows
    ]


# ---------------------------------------------------------------------------
# Dashboard summary
# ---------------------------------------------------------------------------


def dashboard_summary(db: Session) -> Dict[str, Any]:
    org_count = db.query(func.count(Organization.id)).scalar() or 0
    active_org_count = (
        db.query(func.count(Organization.id))
        .filter(Organization.is_active.is_(True))
        .scalar()
        or 0
    )
    asset_count = db.query(func.count(Asset.id)).scalar() or 0
    active_key_count = (
        db.query(func.count(ApiKey.id)).filter(ApiKey.is_active.is_(True)).scalar() or 0
    )
    total_key_count = db.query(func.count(ApiKey.id)).scalar() or 0
    import_count = db.query(func.count(ImportLog.id)).scalar() or 0

    return {
        "org_count": org_count,
        "active_org_count": active_org_count,
        "asset_count": asset_count,
        "active_key_count": active_key_count,
        "total_key_count": total_key_count,
        "import_count": import_count,
    }
