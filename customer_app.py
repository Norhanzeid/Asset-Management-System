"""
customer_app.py — Streamlit organization-facing portal (Phase 3).

Pages:
- Connect using API Key — enter and validate an API key; stored only in
  `st.session_state` for the lifetime of the browser session.
- Upload Assets        — bulk import assets via the authenticated /import call.
- Browse Assets        — paginated view of the org's own assets.
- AI Assistant         — natural-language analysis via the shared AssetService
                          (through /analyze), scoped to the caller's org.
- Risk Assessment      — a lightweight, client-side summary built from the
                          org's own /assets data (types, statuses, stale
                          assets, top tags).

NOTE: This module is presentation-only. No API contracts, endpoints,
request/response shapes, or auth logic were changed here — see
`customer_service.py` for the (unmodified) HTTP client.

Security:
- This app is a pure HTTP client of the FastAPI service (see
  `customer_service.py`) — it never touches the database directly and never
  learns or stores an organization_id; every request is scoped server-side
  by the X-API-Key header (see auth.py::get_organization_id).
- The raw API key lives ONLY in `st.session_state["api_key"]` for this
  browser session. It is never written to disk, never logged, and is
  deleted immediately on "Disconnect".
- No code path in this file ever calls `print`, `logging`, or `st.write`/
  `st.code` on the API key itself (only a masked preview is ever displayed).
"""

from __future__ import annotations

import json
import os
from collections import Counter

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

import customer_service as api  # noqa: E402
from customer_service import ApiError  # noqa: E402

st.set_page_config(
    page_title="ASM Organization Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

_DEFAULT_BASE_URL = os.environ.get("CUSTOMER_API_BASE_URL", "http://localhost:8083")


# ---------------------------------------------------------------------------
# Enterprise theme (presentation only — no functional changes)
# ---------------------------------------------------------------------------

_THEME_CSS = """
<style>
:root {
    --asm-navy: #0b1f3a;
    --asm-blue: #1a56db;
    --asm-slate-light: #64748b;
    --asm-bg: #f8fafc;
    --asm-border: #e2e8f0;
    --asm-success: #0e9f6e;
    --asm-success-bg: #ecfdf3;
    --asm-warning-bg: #fffbeb;
    --asm-warning-fg: #92400e;
}
.stApp { background-color: var(--asm-bg); }
@keyframes asmFadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
}
.asm-fade-in { animation: asmFadeIn 0.45s ease-out; }
.asm-hero-wrap { max-width: 460px; margin: 3.5rem auto 0 auto; }
.asm-hero-icon {
    width: 56px; height: 56px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 14px;
    background: linear-gradient(135deg, var(--asm-navy), var(--asm-blue));
    font-size: 28px; margin: 0 auto 1.1rem auto;
    box-shadow: 0 8px 20px rgba(26, 86, 219, 0.25);
}
.asm-hero-title {
    text-align: center; font-size: 1.55rem; font-weight: 700;
    color: var(--asm-navy); margin-bottom: 0.25rem; letter-spacing: -0.01em;
}
.asm-hero-subtitle {
    text-align: center; color: var(--asm-slate-light);
    font-size: 0.92rem; margin-bottom: 1.75rem;
}
.asm-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 0.78rem; font-weight: 600; padding: 4px 10px; border-radius: 999px;
    background: var(--asm-success-bg); color: var(--asm-success);
    border: 1px solid rgba(14, 159, 110, 0.25);
}
.asm-dot { width: 7px; height: 7px; border-radius: 999px; background: var(--asm-success); }
.asm-org-card {
    background: #ffffff; border: 1px solid var(--asm-border); border-radius: 12px;
    padding: 0.9rem 1rem; margin-bottom: 0.75rem;
}
.asm-org-label {
    font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
    color: var(--asm-slate-light); font-weight: 600; margin-bottom: 2px;
}
.asm-org-value {
    font-size: 0.92rem; color: var(--asm-navy); font-weight: 600;
    font-family: "SFMono-Regular", Consolas, monospace;
}
.asm-section-title { color: var(--asm-navy); font-weight: 700; letter-spacing: -0.01em; }
.asm-section-caption { color: var(--asm-slate-light); }
hr { border-color: var(--asm-border); }
</style>
"""

st.markdown(_THEME_CSS, unsafe_allow_html=True)


def _mask(key: str) -> str:
    """Never display the full key — only used to redact it from any debug output."""
    if len(key) <= 12:
        return "•" * len(key)
    return f"{key[:8]}...{key[-4:]}"


# ---------------------------------------------------------------------------
# Connect page
# ---------------------------------------------------------------------------


def _connect_page() -> None:
    st.markdown('<div class="asm-fade-in asm-hero-wrap">', unsafe_allow_html=True)
    st.markdown('<div class="asm-hero-icon">🛡️</div>', unsafe_allow_html=True)
    st.markdown('<div class="asm-hero-title">ASM Organization Portal</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="asm-hero-subtitle">Connect with your organization&#39;s API key '
        "to access your asset inventory.</div>",
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        with st.form("connect_form"):
            api_key = st.text_input(
                "Organization API key",
                type="password",
                placeholder="asm_...",
                help="Issued by your ASM administrator. Never shared or stored outside this session.",
            )
            with st.expander("Advanced connection settings"):
                base_url = st.text_input("API base URL", value=_DEFAULT_BASE_URL)

            submitted = st.form_submit_button("Connect →", use_container_width=True, type="primary")

    st.markdown("</div>", unsafe_allow_html=True)

    if submitted:
        if not api_key.strip():
            st.error("Please enter an API key.")
            return
        with st.spinner("Verifying credentials..."):
            try:
                ok = api.check_connection(base_url.strip(), api_key.strip())
            except ApiError as exc:
                st.error(f"Connection failed: {exc}")
                return

        if ok:
            # Stored ONLY in session_state — never persisted, never logged.
            st.session_state["api_key"] = api_key.strip()
            st.session_state["base_url"] = base_url.strip()
            st.success("Connected successfully.")
            st.rerun()
        else:
            st.error("Invalid or revoked API key.")


if not st.session_state.get("api_key"):
    _connect_page()
    st.stop()


# ---------------------------------------------------------------------------
# Sidebar — connection status + navigation
# ---------------------------------------------------------------------------

_NAV_ITEMS = ["Upload Assets", "Browse Assets", "AI Assistant", "Risk Assessment"]
_NAV_ICONS = {"Upload Assets": "⬆️", "Browse Assets": "🗂️", "AI Assistant": "✨", "Risk Assessment": "📊"}


@st.cache_data(ttl=60, show_spinner=False)
def _cached_get_organization(base_url: str, api_key: str) -> dict:
    return api.get_organization(base_url, api_key)


with st.sidebar:
    st.markdown(
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:0.75rem;">'
        '<span style="font-size:1.3rem;">🛡️</span>'
        '<span style="font-weight:700;font-size:1.05rem;color:#0b1f3a;">ASM Portal</span>'
        "</div>",
        unsafe_allow_html=True,
    )

    try:
        _org = _cached_get_organization(st.session_state["base_url"], st.session_state["api_key"])
    except ApiError:
        st.markdown(
            '<div class="asm-org-card">'
            '<div class="asm-badge"><span class="asm-dot"></span> Connected</div>'
            '<p style="margin-top:10px;font-size:0.82rem;color:var(--asm-slate-light);">'
            "Unable to load organization information.</p>"
            "</div>",
            unsafe_allow_html=True,
        )
    else:
        _created = str(_org.get("created_at", ""))[:10]
        st.markdown(
            f"""
            <div class="asm-org-card">
                <div class="asm-badge"><span class="asm-dot"></span> Connected</div>
                <div style="margin-top:10px;" class="asm-org-label">Organization</div>
                <div class="asm-org-value">{_org.get('name', 'Unknown')}</div>
                <div style="margin-top:8px;" class="asm-org-label">Status</div>
                <div class="asm-org-value">{str(_org.get('status', 'unknown')).capitalize()}</div>
                <div style="margin-top:8px;" class="asm-org-label">Created</div>
                <div class="asm-org-value">{_created or 'Unknown'}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    page = st.radio(
        "Navigate",
        _NAV_ITEMS,
        format_func=lambda label: f"{_NAV_ICONS[label]}  {label}",
        label_visibility="collapsed",
    )

    st.markdown("<div style='margin-top: 25vh;'></div>", unsafe_allow_html=True)
    st.divider()
    if st.button("⏻ Disconnect", use_container_width=True):
        # Clear the key immediately — nothing about it is retained anywhere.
        st.session_state.pop("api_key", None)
        st.session_state.pop("base_url", None)
        st.rerun()


def _api_key() -> str:
    return st.session_state["api_key"]


def _base_url() -> str:
    return st.session_state["base_url"]


@st.cache_data(ttl=30, show_spinner=False)
def _cached_list_assets(
    base_url: str,
    api_key: str,
    type: str | None,
    status: str | None,
    source: str | None,
    tag: str | None,
    page: int,
    page_size: int,
) -> dict:
    # Cached per unique combination of filters/page for a short TTL — avoids
    # re-hitting the API on every unrelated widget rerun (a major source of
    # perceived slowness), while still refreshing regularly.
    return api.list_assets(
        base_url,
        api_key,
        type=type,
        status=status,
        source=source,
        tag=tag,
        page=page,
        page_size=page_size,
    )


def _handle_api_error(exc: ApiError) -> None:
    if exc.status_code == 401:
        st.error("Your API key is no longer valid. Please reconnect.")
        st.session_state.pop("api_key", None)
        st.session_state.pop("base_url", None)
        st.rerun()
    else:
        st.error(f"Request failed: {exc}")


# ---------------------------------------------------------------------------
# Upload Assets
# ---------------------------------------------------------------------------

if page == "Upload Assets":
    st.markdown('<div class="asm-fade-in">', unsafe_allow_html=True)
    st.markdown('<h2 class="asm-section-title">⬆️ Upload Assets</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="asm-section-caption">Upload a JSON array of asset records, or paste one directly. '
        "Each record must include at least <code>id</code>, <code>type</code>, and <code>value</code>.</p>",
        unsafe_allow_html=True,
    )
    st.write("")

    with st.container(border=True):
        uploaded = st.file_uploader("Asset JSON file", type=["json"])
        st.caption("— or —")
        pasted = st.text_area(
            "Paste a JSON array",
            height=200,
            placeholder='[{"id": "example-1", "type": "domain", "value": "example.com"}]',
        )

        import_clicked = st.button("Import assets", type="primary", use_container_width=True)

    if import_clicked:
        raw_text = None
        if uploaded is not None:
            raw_text = uploaded.read().decode("utf-8", errors="replace")
        elif pasted.strip():
            raw_text = pasted

        if not raw_text:
            st.warning("Provide a file or paste JSON before importing.")
        else:
            try:
                payload = json.loads(raw_text)
                if not isinstance(payload, list):
                    raise ValueError("Top-level JSON must be an array of asset objects.")
            except (json.JSONDecodeError, ValueError) as exc:
                st.error(f"Invalid JSON: {exc}")
            else:
                with st.spinner("Importing assets..."):
                    try:
                        result = api.import_assets(_base_url(), _api_key(), payload)
                    except ApiError as exc:
                        _handle_api_error(exc)
                    else:
                        st.success(
                            f"Imported {result['imported']}, updated {result['updated']}, "
                            f"failed {result['failed']} (total {result['total']})."
                        )
                        if result.get("errors"):
                            st.warning("Some records failed:")
                            st.dataframe(result["errors"], use_container_width=True, hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Browse Assets
# ---------------------------------------------------------------------------

elif page == "Browse Assets":
    st.markdown('<div class="asm-fade-in">', unsafe_allow_html=True)
    st.markdown('<h2 class="asm-section-title">🗂️ Browse Assets</h2>', unsafe_allow_html=True)

    page_num = st.number_input("Page", min_value=1, value=1, step=1)

    try:
        result = _cached_list_assets(
            _base_url(),
            _api_key(),
            None,
            None,
            None,
            None,
            int(page_num),
            20,
        )
    except ApiError as exc:
        _handle_api_error(exc)
    else:
        st.markdown(
            f'<p class="asm-section-caption">{result["total"]} assets · '
            f'page {result["page"]} of {result["pages"]}</p>',
            unsafe_allow_html=True,
        )
        with st.container(border=True):
            if not result["assets"]:
                st.info("No assets found.")
            else:
                st.dataframe(result["assets"], use_container_width=True, hide_index=True)
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# AI Chat
# ---------------------------------------------------------------------------

elif page == "AI Assistant":
    st.markdown('<div class="asm-fade-in">', unsafe_allow_html=True)
    st.markdown('<h2 class="asm-section-title">✨ AI Assistant</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="asm-section-caption">Ask natural-language questions about your organization&#39;s '
        "attack surface. Answers are generated from your own asset data only.</p>",
        unsafe_allow_html=True,
    )

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    for role, content in st.session_state["chat_history"]:
        avatar = "🧑‍💻" if role == "user" else "🛡️"
        with st.chat_message(role, avatar=avatar):
            st.markdown(content)

    query = st.chat_input("Ask about your assets...")
    if query:
        st.session_state["chat_history"].append(("user", query))
        with st.chat_message("user", avatar="🧑‍💻"):
            st.markdown(query)

        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("Analyzing your asset inventory..."):
                try:
                    result = api.analyze(_base_url(), _api_key(), query)
                except ApiError as exc:
                    if exc.status_code == 401:
                        st.error("Your API key is no longer valid. Please reconnect.")
                        st.session_state.pop("api_key", None)
                        st.session_state.pop("base_url", None)
                        st.rerun()
                    else:
                        st.error(f"Request failed: {exc}")
                else:
                    st.markdown(result["result"])
                    st.session_state["chat_history"].append(("assistant", result["result"]))
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Risk Report
# ---------------------------------------------------------------------------

elif page == "Risk Assessment":
    st.markdown('<div class="asm-fade-in">', unsafe_allow_html=True)
    st.markdown('<h2 class="asm-section-title">📊 Risk Assessment</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="asm-section-caption">A quick summary derived entirely from your organization&#39;s '
        "own asset inventory.</p>",
        unsafe_allow_html=True,
    )

    try:
        # Pull a reasonably large page to summarize; server still caps at 100/page.
        result = _cached_list_assets(_base_url(), _api_key(), None, None, None, None, 1, 100)
    except ApiError as exc:
        _handle_api_error(exc)
    else:
        assets = result["assets"]
        total = result["total"]

        if total == 0:
            st.info("No assets to report on yet — upload some assets first.")
        else:
            if total > len(assets):
                st.markdown(
                    '<div class="asm-org-card" style="background:var(--asm-warning-bg);'
                    'border-color:#fde68a;color:var(--asm-warning-fg);font-size:0.85rem;">'
                    f"⚠️ Showing a report based on the first {len(assets)} of {total} assets "
                    "(pagination not yet aggregated).</div>",
                    unsafe_allow_html=True,
                )

            type_counts = Counter(a["type"] for a in assets)
            status_counts = Counter(a["status"] for a in assets)

            col1, col2, col3 = st.columns(3)
            with col1, st.container(border=True):
                st.metric("Total assets (sampled)", len(assets))
            with col2, st.container(border=True):
                st.metric("Active", status_counts.get("active", 0))
            with col3, st.container(border=True):
                st.metric("Inactive / archived", len(assets) - status_counts.get("active", 0))

            st.write("")
            col_a, col_b = st.columns(2)
            with col_a, st.container(border=True):
                st.markdown("**By type**")
                st.bar_chart(type_counts)
            with col_b, st.container(border=True):
                st.markdown("**By status**")
                st.bar_chart(status_counts)

            st.write("")
            with st.container(border=True):
                st.markdown("**Stalest assets (oldest last_seen)**")
                sorted_assets = sorted(assets, key=lambda a: a["last_seen"])[:10]
                st.dataframe(
                    [
                        {
                            "ID": a["id"],
                            "Type": a["type"],
                            "Value": a["value"],
                            "Status": a["status"],
                            "Last seen": a["last_seen"],
                        }
                        for a in sorted_assets
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

            tag_counts: Counter = Counter()
            for a in assets:
                tag_counts.update(a.get("tags") or [])
            if tag_counts:
                st.write("")
                with st.container(border=True):
                    st.markdown("**Top tags**")
                    st.bar_chart(dict(tag_counts.most_common(10)))
    st.markdown("</div>", unsafe_allow_html=True)
