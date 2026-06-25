"""
models.py — SQLAlchemy ORM models and Pydantic validation schemas.

Security Design:
- All string IDs are validated against a strict allowlist regex before touching the DB.
- SQL keyword blocklist prevents injection through free-text fields.
- Metadata and tags have size caps to prevent resource exhaustion.
- The Python attribute `metadata_` maps to the DB column `metadata` to avoid
  shadowing SQLAlchemy's class-level MetaData object.
"""

from __future__ import annotations

import enum
import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import (
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


# ---------------------------------------------------------------------------
# SQLAlchemy Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AssetType(str, enum.Enum):
    domain = "domain"
    subdomain = "subdomain"
    ip_address = "ip_address"
    certificate = "certificate"
    service = "service"
    technology = "technology"
    url = "url"
    email = "email"
    cidr = "cidr"
    asn = "asn"


class AssetStatus(str, enum.Enum):
    active = "active"
    inactive = "inactive"
    archived = "archived"


class RelationshipType(str, enum.Enum):
    parent = "parent"          # subdomain → domain
    covers = "covers"          # certificate → domain/subdomain
    resolves = "resolves"      # subdomain ↔ ip_address (DNS resolution)
    hosts = "hosts"            # ip_address → service
    belongs_to = "belongs_to"  # technology → service/subdomain


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------


class Asset(Base):
    """
    Central asset entity. `metadata_` maps to the DB column `metadata` to avoid
    colliding with SQLAlchemy's Base.metadata class attribute.
    """

    __tablename__ = "assets"

    id = Column(String(255), primary_key=True, nullable=False)
    organization_id = Column(String(255), nullable=False)
    type = Column(SAEnum(AssetType, name="assettype"), nullable=False)
    value = Column(String(4096), nullable=False)
    status = Column(
        SAEnum(AssetStatus, name="assetstatus"),
        nullable=False,
        default=AssetStatus.active,
    )
    first_seen = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    source = Column(String(255), nullable=True)
    tags = Column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    # 'metadata' is a reserved name on Base; use metadata_ → column "metadata"
    metadata_ = Column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    outgoing_rels = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.source_asset_id",
        back_populates="source_asset",
        cascade="all, delete-orphan",
        lazy="select",
    )
    incoming_rels = relationship(
        "AssetRelationship",
        foreign_keys="AssetRelationship.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        Index("ix_assets_org_id", "organization_id"),
        Index("ix_assets_org_type", "organization_id", "type"),
        Index("ix_assets_org_status", "organization_id", "status"),
        Index("ix_assets_org_source", "organization_id", "source"),
    )


class AssetRelationship(Base):
    """
    Directed edge between two assets. The relationship_type encodes semantics.
    A UniqueConstraint prevents duplicate edges of the same type within an org.
    """

    __tablename__ = "asset_relationships"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    organization_id = Column(String(255), nullable=False)
    source_asset_id = Column(
        String(255),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_asset_id = Column(
        String(255),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type = Column(
        SAEnum(RelationshipType, name="relationshiptype"),
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    source_asset = relationship(
        "Asset",
        foreign_keys=[source_asset_id],
        back_populates="outgoing_rels",
    )
    target_asset = relationship(
        "Asset",
        foreign_keys=[target_asset_id],
        back_populates="incoming_rels",
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationship",
        ),
        Index("ix_rels_org", "organization_id"),
        Index("ix_rels_source", "source_asset_id"),
        Index("ix_rels_target", "target_asset_id"),
    )


# ---------------------------------------------------------------------------
# Security helpers — shared by all Pydantic schemas
# ---------------------------------------------------------------------------

# Allowlist for IDs: alphanumeric, hyphens, underscores, dots — no shell chars.
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,255}$")

# Rough SQL keyword blocklist for free-text fields. ORM parameterisation is the
# primary defense; this is defence-in-depth.
_SQL_INJECTION_RE = re.compile(
    r"(--|;|/\*|\*/|xp_|union\s+select|drop\s+table|"
    r"insert\s+into|delete\s+from|update\s+.*\s+set|exec\s*\()",
    re.IGNORECASE,
)

# Prompt-injection phrases that must not appear in natural-language fields.
_PROMPT_INJECTION_PHRASES: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard the above",
    "you are now",
    "pretend you are",
    "act as if",
    "jailbreak",
    "forget your instructions",
    "new instructions:",
    "system prompt:",
    "override instructions",
)


def _validate_safe_id(value: Optional[str]) -> Optional[str]:
    """Validate that an ID contains only safe characters."""
    if value is None:
        return None
    value = value.strip()
    if not _SAFE_ID_RE.match(value):
        raise ValueError(
            f"ID '{value[:30]}' contains invalid characters. "
            "Only alphanumerics, hyphens, underscores, and dots are allowed."
        )
    if _SQL_INJECTION_RE.search(value):
        raise ValueError("ID contains forbidden SQL keywords.")
    return value


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------


class AssetImportRecord(BaseModel):
    """
    Schema for a single asset record in the bulk-import payload.
    Validates and sanitises all incoming fields before any DB interaction.
    """

    id: str = Field(..., min_length=1, max_length=255)
    type: AssetType
    value: str = Field(..., min_length=1, max_length=4096)
    status: AssetStatus = AssetStatus.active
    source: Optional[str] = Field(None, max_length=255)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Relationship shorthand fields (mirrors the sample JSON format)
    parent: Optional[str] = Field(None, max_length=255)
    covers: Optional[str] = Field(None, max_length=255)
    resolves: Optional[str] = Field(None, max_length=255)
    hosts: Optional[str] = Field(None, max_length=255)
    belongs_to: Optional[str] = Field(None, max_length=255)

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        result = _validate_safe_id(v)
        if result is None:
            raise ValueError("id is required and cannot be empty.")
        return result

    @field_validator("parent", "covers", "resolves", "hosts", "belongs_to", mode="before")
    @classmethod
    def validate_rel_ids(cls, v: Optional[str]) -> Optional[str]:
        return _validate_safe_id(v)

    @field_validator("source", mode="before")
    @classmethod
    def validate_source(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if _SQL_INJECTION_RE.search(v):
            raise ValueError("source field contains forbidden SQL keywords.")
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: List[str]) -> List[str]:
        if len(v) > 100:
            raise ValueError("Maximum 100 tags per asset.")
        # Truncate individual tag strings and strip whitespace
        return [str(t).strip()[:128] for t in v if str(t).strip()]

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        try:
            serialized = json.dumps(v)
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serialisable.") from exc
        if len(serialized) > 65_536:
            raise ValueError("metadata payload exceeds the 64 KB limit.")
        return v

    @field_validator("value")
    @classmethod
    def sanitize_value(cls, v: str) -> str:
        # Value is stored verbatim but must not contain SQL injection sequences.
        if _SQL_INJECTION_RE.search(v):
            raise ValueError("value field contains forbidden SQL keywords.")
        return v.strip()


class AssetResponse(BaseModel):
    """
    Serialisation schema for a single asset returned by the API.
    Uses AliasChoices to bridge the ORM `metadata_` attribute name to the
    JSON key `metadata`.
    """

    id: str
    organization_id: str
    type: str
    value: str
    status: str
    first_seen: datetime
    last_seen: datetime
    source: Optional[str]
    tags: List[str]
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("metadata_", "metadata"),
    )

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ImportResponse(BaseModel):
    total: int
    imported: int
    updated: int
    failed: int
    errors: List[Dict[str, Any]]


class AssetsQueryParams(BaseModel):
    """Query parameters for GET /assets — validated before any DB access."""

    type: Optional[AssetType] = None
    status: Optional[AssetStatus] = None
    source: Optional[str] = Field(None, max_length=255)
    tag: Optional[str] = Field(None, max_length=128)
    id: Optional[str] = Field(None, max_length=255)
    page: int = Field(1, ge=1, le=100_000)
    page_size: int = Field(20, ge=1, le=100)

    @field_validator("source")
    @classmethod
    def validate_source(cls, v: Optional[str]) -> Optional[str]:
        if v and _SQL_INJECTION_RE.search(v):
            raise ValueError("source contains forbidden SQL keywords.")
        return v

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: Optional[str]) -> Optional[str]:
        return _validate_safe_id(v)

    @field_validator("tag")
    @classmethod
    def validate_tag(cls, v: Optional[str]) -> Optional[str]:
        if v and _SQL_INJECTION_RE.search(v):
            raise ValueError("tag contains forbidden SQL keywords.")
        return v


class AnalyzeRequest(BaseModel):
    """
    Request body for POST /analyze.
    Applies prompt-injection detection before the query reaches the LLM.
    """

    query: str = Field(..., min_length=1, max_length=2000)

    @field_validator("query")
    @classmethod
    def block_prompt_injection(cls, v: str) -> str:
        v = v.strip()
        v_lower = v.lower()
        for phrase in _PROMPT_INJECTION_PHRASES:
            if phrase in v_lower:
                raise ValueError(
                    "Query contains content that may attempt to subvert system "
                    "instructions and has been rejected."
                )
        return v


class AnalyzeResponse(BaseModel):
    result: str
    organization_id: str
