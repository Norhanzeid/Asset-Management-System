"""
admin_app.py — Streamlit administration console (Phase 2).

Pages:
- Dashboard        — platform-wide statistics.
- Organizations    — create organizations, view per-org stats.
- API Keys         — create / revoke API keys, view metadata (never plaintext
                      after creation).

Security:
- Gated behind a single admin password stored in `ADMIN_PASSWORD` (.env).
  Verified with a timing-safe comparison (see `admin_service.verify_admin_password`).
- This app talks directly to the database via SQLAlchemy — it does not call
  the FastAPI `/import`/`/assets`/`/analyze` customer endpoints and does not
  modify any customer-facing code.
- Raw API keys are shown exactly once, immediately after creation, and are
  never persisted or re-displayed.
"""

from __future__ import annotations

import os

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from database import SessionLocal, create_all_tables  # noqa: E402
import admin_service as svc  # noqa: E402

st.set_page_config(
    page_title="ASM Admin Console",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------


def _login_form() -> None:
    st.title("🛡️ ASM Admin Console")
    st.caption("Platform administration — organizations and API keys.")
    with st.form("login_form"):
        password = st.text_input("Admin password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        try:
            ok = svc.verify_admin_password(password)
        except RuntimeError as exc:
            st.error(str(exc))
            return
        if ok:
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password.")


if not st.session_state.get("authenticated"):
    _login_form()
    st.stop()


# ---------------------------------------------------------------------------
# Session / DB setup (only reached once authenticated)
# ---------------------------------------------------------------------------

create_all_tables()


def get_session():
    return SessionLocal()


# ---------------------------------------------------------------------------
# Sidebar navigation
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🛡️ ASM Admin")
    page = st.radio(
        "Navigate",
        ["Dashboard", "Organizations", "API Keys"],
        label_visibility="collapsed",
    )
    st.divider()
    if st.button("Log out", use_container_width=True):
        st.session_state["authenticated"] = False
        st.rerun()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

if page == "Dashboard":
    st.header("Dashboard")
    db = get_session()
    try:
        summary = svc.dashboard_summary(db)
    finally:
        db.close()

    col1, col2, col3 = st.columns(3)
    col1.metric("Organizations", summary["org_count"], f"{summary['active_org_count']} active")
    col2.metric("Total assets", summary["asset_count"])
    col3.metric(
        "API keys",
        summary["total_key_count"],
        f"{summary['active_key_count']} active",
    )

    col4, _, _ = st.columns(3)
    col4.metric("Import batches", summary["import_count"])

    st.divider()
    st.subheader("Organizations overview")
    db = get_session()
    try:
        orgs = svc.list_organizations_with_stats(db)
    finally:
        db.close()

    if not orgs:
        st.info("No organizations yet. Create one from the Organizations page.")
    else:
        st.dataframe(
            [
                {
                    "Name": o.name,
                    "Active": o.is_active,
                    "Assets": o.asset_count,
                    "API Keys (active/total)": f"{o.active_key_count}/{o.total_key_count}",
                    "Last Import": o.last_import_at,
                    "Created": o.created_at,
                }
                for o in orgs
            ],
            use_container_width=True,
            hide_index=True,
        )


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------

elif page == "Organizations":
    st.header("Organizations")

    with st.expander("➕ Create a new organization", expanded=False):
        with st.form("create_org_form", clear_on_submit=True):
            new_org_name = st.text_input("Organization name")
            create_submitted = st.form_submit_button("Create organization")
        if create_submitted:
            db = get_session()
            try:
                org = svc.create_organization(db, new_org_name)
                st.success(f"Created organization '{org.name}' (id={org.id}).")
            except ValueError as exc:
                st.error(str(exc))
            finally:
                db.close()

    db = get_session()
    try:
        orgs = svc.list_organizations_with_stats(db)
    finally:
        db.close()

    st.subheader(f"All organizations ({len(orgs)})")
    if not orgs:
        st.info("No organizations yet.")
    else:
        for o in orgs:
            with st.container(border=True):
                c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
                c1.markdown(f"**{o.name}**  \n`{o.id}`")
                c2.metric("Assets", o.asset_count)
                c3.metric("API keys", f"{o.active_key_count}/{o.total_key_count}")
                status_label = "Active" if o.is_active else "Disabled"
                c4.markdown(f"**Status:** {status_label}")
                toggle_label = "Disable" if o.is_active else "Re-enable"
                if c4.button(toggle_label, key=f"toggle_{o.id}"):
                    db = get_session()
                    try:
                        svc.set_organization_active(db, o.id, not o.is_active)
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
                    finally:
                        db.close()


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------

elif page == "API Keys":
    st.header("API Keys")

    db = get_session()
    try:
        orgs = svc.list_organizations_with_stats(db)
    finally:
        db.close()

    if not orgs:
        st.warning("Create an organization first before issuing API keys.")
    else:
        org_options = {f"{o.name} ({o.id})": o.id for o in orgs}

        with st.expander("➕ Create a new API key", expanded=False):
            with st.form("create_key_form", clear_on_submit=True):
                selected_org_label = st.selectbox("Organization", list(org_options.keys()))
                key_name = st.text_input("Key label (optional)", placeholder="e.g. CI pipeline")
                create_key_submitted = st.form_submit_button("Create API key")
            if create_key_submitted:
                db = get_session()
                try:
                    result = svc.create_api_key(db, org_options[selected_org_label], key_name)
                    st.success(
                        f"Created API key `{result['prefix']}...` for "
                        f"**{result['organization_name']}**."
                    )
                    st.warning(
                        "This is the only time the full key will be shown. "
                        "Copy it now — it cannot be retrieved again."
                    )
                    st.code(result["raw_key"], language=None)
                except ValueError as exc:
                    st.error(str(exc))
                finally:
                    db.close()

    st.divider()
    st.subheader("Existing API keys")

    filter_options = {"All organizations": None, **{f"{o.name}": o.id for o in orgs}}
    filter_label = st.selectbox("Filter by organization", list(filter_options.keys()))

    db = get_session()
    try:
        keys = svc.list_api_keys(db, filter_options[filter_label])
    finally:
        db.close()

    if not keys:
        st.info("No API keys found.")
    else:
        for k in keys:
            with st.container(border=True):
                c1, c2, c3, c4 = st.columns([3, 2, 2, 1])
                c1.markdown(
                    f"**{k['prefix']}...**  \n"
                    f"{k['name'] or '_(no label)_'} · {k['organization_name']}"
                )
                c2.markdown(f"Created: {k['created_at']}")
                c3.markdown(f"Last used: {k['last_used_at'] or 'never'}")
                if k["is_active"]:
                    if c4.button("Revoke", key=f"revoke_{k['id']}"):
                        db = get_session()
                        try:
                            svc.revoke_api_key(db, k["id"])
                            st.rerun()
                        except ValueError as exc:
                            st.error(str(exc))
                        finally:
                            db.close()
                else:
                    c4.markdown("🚫 Revoked")

