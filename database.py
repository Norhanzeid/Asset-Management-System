"""
database.py — PostgreSQL connection, session factory, and lifecycle helpers.

Security Design:
- Database credentials are read from individual environment variables, never
  from a single DATABASE_URL string (which is easier to leak via logs).
- SQL echo is disabled globally — query logs may contain sensitive data.
- Connection-level query timeout (30 s) prevents runaway queries.
- pool_pre_ping=True validates connections on checkout, preventing stale
  connection errors under load.
"""

from __future__ import annotations

import logging
import os
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DSN construction from individual env vars
# ---------------------------------------------------------------------------


def _build_database_url() -> str:
    """
    Build the PostgreSQL DSN from discrete environment variables.

    Using separate vars (POSTGRES_HOST, POSTGRES_USER, etc.) rather than a
    single DATABASE_URL avoids accidentally logging a URL that embeds the
    password.
    """
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "assetdb")
    user = os.environ.get("POSTGRES_USER", "assetuser")
    password = os.environ.get("POSTGRES_PASSWORD", "")

    if not password:
        raise RuntimeError(
            "POSTGRES_PASSWORD environment variable is not set. "
            "The application refuses to start without a database password."
        )

    # Build URL via SQLAlchemy so special characters in credentials are escaped.
    return URL.create(
        drivername="postgresql+psycopg2",
        username=user,
        password=password,
        host=host,
        port=int(port),
        database=db,
    ).render_as_string(hide_password=False)


# ---------------------------------------------------------------------------
# Engine — module-level singleton
# ---------------------------------------------------------------------------

engine = create_engine(
    _build_database_url(),
    poolclass=QueuePool,
    pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
    pool_pre_ping=True,        # Validate connections on checkout
    pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", "300")),  # 5 min
    echo=False,                # NEVER echo SQL — queries may contain PII/sensitive data
    connect_args={
        "connect_timeout": 10,
        # Hard query timeout at the driver level (30 s).
        # This provides a safety net against slow queries exhausting the pool.
        "options": "-c statement_timeout=30000 -c lock_timeout=5000",
    },
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,  # Prevent lazy-load errors after commit
)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency — yields a DB session per request.

    Commits on successful completion, rolls back on any unhandled exception,
    and always closes the session regardless of outcome.
    """
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


def create_all_tables() -> None:
    """
    Create all tables defined in the ORM metadata if they do not already exist.
    Safe to call on every startup (CREATE TABLE IF NOT EXISTS semantics).
    """
    from models import Base  # local import prevents circular dependency at module load

    Base.metadata.create_all(bind=engine)
    logger.info("Database schema verified / tables created.")


def verify_connectivity() -> bool:
    """
    Lightweight connectivity check used by the health endpoint.
    Returns True if the database is reachable, False otherwise.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("Database connectivity check failed: %s", exc)
        return False
