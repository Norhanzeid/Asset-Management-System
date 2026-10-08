"""
services.py — Shared business logic layer for asset retrieval.

Both the FastAPI HTTP routes (main.py) and the LangChain agent tools
(ai_layer.py) call into `AssetService` so there is exactly one implementation
of the tenant-scoped querying/pagination/serialization logic. This keeps
main.py and ai_layer.py as thin orchestration layers — neither talks to the
ORM directly for asset reads anymore.

Security:
- Every method requires an explicit `org_id` argument and hard-filters every
  query on it. Callers must resolve `org_id` via the existing auth flow
  (API key → organization) before calling into this service — this module
  does not authenticate anything itself and never trusts a client-supplied
  organization identifier.
- Query parameters are re-validated through `AssetsQueryParams` before
  touching the database, exactly as the original route-level validation did.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from models import Asset, AssetsQueryParams


class AssetService:
    """Tenant-scoped read access to the asset inventory."""

    @staticmethod
    def _serialize(asset: Asset) -> Dict[str, Any]:
        return {
            "id": asset.id,
            "organization_id": asset.organization_id,
            "type": asset.type.value,
            "value": asset.value,
            "status": asset.status.value,
            "first_seen": asset.first_seen.isoformat(),
            "last_seen": asset.last_seen.isoformat(),
            "source": asset.source,
            "tags": asset.tags or [],
            "metadata": asset.metadata_ or {},
        }

    @classmethod
    def list_assets(
        cls,
        db: Session,
        org_id: str,
        *,
        type: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        tag: Optional[str] = None,
        id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """
        Returns a paginated, filtered list of assets scoped to `org_id`.

        All parameters are re-validated through `AssetsQueryParams` before
        touching the database (raises `pydantic.ValidationError` on bad
        input — callers are responsible for translating that into whatever
        error shape is appropriate for their context, e.g. HTTP 422 or a
        tool-safe error payload).

        The `organization_id` filter is unconditionally applied and cannot be
        overridden by any parameter.
        """
        params = AssetsQueryParams(
            type=type,
            status=status,
            source=source,
            tag=tag,
            id=id,
            page=page,
            page_size=page_size,
        )

        query = db.query(Asset).filter(
            Asset.organization_id == org_id  # HARD tenant filter — always applied
        )

        if params.id:
            query = query.filter(Asset.id == params.id)
        if params.type:
            query = query.filter(Asset.type == params.type)
        if params.status:
            query = query.filter(Asset.status == params.status)
        if params.source:
            query = query.filter(Asset.source == params.source)
        if params.tag:
            # JSONB containment operator — fully parameterised, no injection risk.
            query = query.filter(Asset.tags.contains([params.tag]))

        total: int = query.count()
        assets: List[Asset] = (
            query.order_by(Asset.last_seen.desc())
            .offset((params.page - 1) * params.page_size)
            .limit(params.page_size)
            .all()
        )

        return {
            "total": total,
            "page": params.page,
            "page_size": params.page_size,
            "pages": max(1, (total + params.page_size - 1) // params.page_size),
            "assets": [cls._serialize(a) for a in assets],
        }
