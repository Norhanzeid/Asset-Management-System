"""
customer_service.py — Thin HTTP client wrapping the ASM FastAPI endpoints for
the Streamlit customer portal (Phase 3).

Design:
- The portal is a pure API consumer — it never touches the database directly
  and never knows (or needs to know) the caller's organization_id. Tenant
  scoping is enforced entirely server-side by `auth.get_organization_id`
  (see auth.py) based on the X-API-Key header.
- Every function here takes `api_key` explicitly and forwards it as the
  `X-API-Key` header on each request — nothing is cached or reused beyond
  the single call. The caller (customer_app.py) is responsible for storing
  the key only in `st.session_state`.
- SECURITY: no function in this module ever logs, prints, or persists the
  raw API key. Only generic, sanitized error messages are returned/raised.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

import httpx

DEFAULT_TIMEOUT = 15.0
ANALYZE_TIMEOUT = 130.0  # /analyze can run an LLM agent loop server-side

# A single, shared, keep-alive connection pool avoids paying the TCP/TLS
# handshake cost on every request (each `httpx.get`/`httpx.post` call used to
# open and tear down its own connection). This is the single biggest lever
# for cutting per-request latency in the portal.
_CLIENT_LOCK = threading.Lock()
_clients: Dict[str, httpx.Client] = {}


def _get_client(base_url: str) -> httpx.Client:
    base_url = base_url.rstrip("/")
    client = _clients.get(base_url)
    if client is None or client.is_closed:
        with _CLIENT_LOCK:
            client = _clients.get(base_url)
            if client is None or client.is_closed:
                client = httpx.Client(
                    base_url=base_url,
                    limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
                    timeout=DEFAULT_TIMEOUT,
                )
                _clients[base_url] = client
    return client


class ApiError(Exception):
    """Raised for any non-2xx response. Carries a sanitized message only."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


def _headers(api_key: str) -> Dict[str, str]:
    return {"X-API-Key": api_key}


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        raise ApiError(401, "Invalid or revoked API key.")
    if resp.status_code == 429:
        raise ApiError(429, "Rate limit exceeded. Please wait and try again.")
    if resp.status_code >= 400:
        # Never echo raw server internals back verbatim beyond the status text;
        # FastAPI's `detail` is safe (validation errors, not stack traces).
        detail: Any = None
        try:
            detail = resp.json().get("detail")
        except Exception:
            pass
        raise ApiError(resp.status_code, str(detail) if detail else "Request failed.")


def check_connection(base_url: str, api_key: str) -> bool:
    """
    Validates an API key by making a minimal authenticated call.
    Returns True if the key is valid, False if the server responds 401.
    Any other error is raised as ApiError.
    """
    client = _get_client(base_url)
    try:
        resp = client.get(
            "/assets",
            headers=_headers(api_key),
            params={"page": 1, "page_size": 1},
            timeout=DEFAULT_TIMEOUT,
        )
    except httpx.RequestError as exc:
        raise ApiError(0, f"Could not reach the API server: {exc.__class__.__name__}")

    if resp.status_code == 401:
        return False
    _raise_for_status(resp)
    return True


def import_assets(base_url: str, api_key: str, payload: List[Dict[str, Any]]) -> Dict[str, Any]:
    client = _get_client(base_url)
    try:
        resp = client.post(
            "/import",
            headers=_headers(api_key),
            json=payload,
            timeout=DEFAULT_TIMEOUT,
        )
    except httpx.RequestError as exc:
        raise ApiError(0, f"Could not reach the API server: {exc.__class__.__name__}")
    _raise_for_status(resp)
    return resp.json()


def list_assets(
    base_url: str,
    api_key: str,
    *,
    type: Optional[str] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    tag: Optional[str] = None,
    id: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"page": page, "page_size": page_size}
    if type:
        params["type"] = type
    if status:
        params["asset_status"] = status
    if source:
        params["source"] = source
    if tag:
        params["tag"] = tag
    if id:
        params["id"] = id

    client = _get_client(base_url)
    try:
        resp = client.get("/assets", headers=_headers(api_key), params=params, timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise ApiError(0, f"Could not reach the API server: {exc.__class__.__name__}")
    _raise_for_status(resp)
    return resp.json()


def analyze(base_url: str, api_key: str, query: str) -> Dict[str, Any]:
    client = _get_client(base_url)
    try:
        resp = client.post(
            "/analyze",
            headers=_headers(api_key),
            json={"query": query},
            timeout=ANALYZE_TIMEOUT,
        )
    except httpx.RequestError as exc:
        raise ApiError(0, f"Could not reach the API server: {exc.__class__.__name__}")
    _raise_for_status(resp)
    return resp.json()


def get_organization(base_url: str, api_key: str) -> Dict[str, Any]:
    """Fetch safe profile info (name/status/created_at) for the authenticated org."""
    client = _get_client(base_url)
    try:
        resp = client.get("/organizations/me", headers=_headers(api_key), timeout=DEFAULT_TIMEOUT)
    except httpx.RequestError as exc:
        raise ApiError(0, f"Could not reach the API server: {exc.__class__.__name__}")
    _raise_for_status(resp)
    return resp.json()
