"""
manage_api_keys.py — Administrative CLI for bootstrapping organizations and
API keys (Phase 1: Multi-Tenancy & API Key Authentication).

There is intentionally NO public HTTP endpoint for creating organizations or
API keys in this phase — that would let anyone self-provision tenants. This
script is meant to be run by an operator directly against the same database
(e.g. `docker compose exec app python manage_api_keys.py ...`).

Usage:
    python manage_api_keys.py create-org "Acme Corp"
    python manage_api_keys.py list-orgs
    python manage_api_keys.py create-key <organization_id> [--name "CI key"]
    python manage_api_keys.py list-keys <organization_id>
    python manage_api_keys.py revoke-key <api_key_id>

The raw API key is printed exactly once at creation time and is never stored
anywhere — only its hash is persisted in the database.
"""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv

load_dotenv()

from auth import generate_api_key
from database import SessionLocal, create_all_tables
from models import ApiKey, Organization


def create_org(name: str) -> None:
    db = SessionLocal()
    try:
        org = Organization(name=name)
        db.add(org)
        db.commit()
        db.refresh(org)
        print(f"Created organization: id={org.id} name={org.name}")
    finally:
        db.close()


def list_orgs() -> None:
    db = SessionLocal()
    try:
        for org in db.query(Organization).order_by(Organization.created_at).all():
            print(f"{org.id}  {org.name}  active={org.is_active}")
    finally:
        db.close()


def create_key(organization_id: str, name: str | None) -> None:
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == organization_id).first()
        if org is None:
            print(f"No organization found with id={organization_id}", file=sys.stderr)
            sys.exit(1)

        raw_key, key_hash, prefix = generate_api_key()
        api_key = ApiKey(
            organization_id=org.id,
            key_hash=key_hash,
            prefix=prefix,
            name=name,
        )
        db.add(api_key)
        db.commit()
        db.refresh(api_key)

        print(f"Created API key id={api_key.id} for organization={org.id} ({org.name})")
        print(f"Raw key (shown once, store it securely): {raw_key}")
    finally:
        db.close()


def list_keys(organization_id: str) -> None:
    db = SessionLocal()
    try:
        keys = (
            db.query(ApiKey)
            .filter(ApiKey.organization_id == organization_id)
            .order_by(ApiKey.created_at)
            .all()
        )
        for k in keys:
            print(
                f"{k.id}  prefix={k.prefix}...  name={k.name}  "
                f"active={k.is_active}  last_used_at={k.last_used_at}"
            )
    finally:
        db.close()


def revoke_key(api_key_id: str) -> None:
    db = SessionLocal()
    try:
        key = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()
        if key is None:
            print(f"No API key found with id={api_key_id}", file=sys.stderr)
            sys.exit(1)
        key.is_active = False
        db.commit()
        print(f"Revoked API key id={key.id}")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_create_org = sub.add_parser("create-org", help="Create a new organization")
    p_create_org.add_argument("name")

    sub.add_parser("list-orgs", help="List all organizations")

    p_create_key = sub.add_parser("create-key", help="Create a new API key for an organization")
    p_create_key.add_argument("organization_id")
    p_create_key.add_argument("--name", default=None)

    p_list_keys = sub.add_parser("list-keys", help="List API keys for an organization")
    p_list_keys.add_argument("organization_id")

    p_revoke = sub.add_parser("revoke-key", help="Revoke (deactivate) an API key")
    p_revoke.add_argument("api_key_id")

    args = parser.parse_args()

    # Ensure tables exist when running this script standalone (e.g. before
    # the API container has started once).
    create_all_tables()

    if args.command == "create-org":
        create_org(args.name)
    elif args.command == "list-orgs":
        list_orgs()
    elif args.command == "create-key":
        create_key(args.organization_id, args.name)
    elif args.command == "list-keys":
        list_keys(args.organization_id)
    elif args.command == "revoke-key":
        revoke_key(args.api_key_id)


if __name__ == "__main__":
    main()
