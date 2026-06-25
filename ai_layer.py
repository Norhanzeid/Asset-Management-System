"""
ai_layer.py — LangChain ReAct / OpenAI Tools Agent for ASM analysis.

Architectural decisions:
1.  **Tool-via-HTTP**: Each LangChain tool calls the local FastAPI `/assets`
    endpoint over HTTP. This re-uses validated business logic, enforces the same
    Pydantic schema checks, and decouples the AI layer from the ORM layer.

2.  **Org-ID closure factory**: `build_agent_tools(org_id)` creates a fresh set
    of tool functions whose closures capture `org_id`. The LLM cannot inspect,
    override, or substitute a different value — it only sees the tool signatures
    and descriptions.

3.  **Anti-hallucination system prompt**: temperature=0.0 + explicit instructions
    to refuse out-of-scope questions and report "no data" exactly when tools
    return empty results.

4.  **Fresh agent per request**: `build_agent()` returns a new `AgentExecutor`
    each time, preventing cross-request state leakage.

Security:
- API key is read from an environment variable; never hardcoded or logged.
- The system prompt explicitly forbids the agent from speculating beyond tool data.
- All HTTP calls to the API include the org_id in the header — the API enforces
  isolation at the DB query level independently of the agent.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

load_dotenv()  # Ensure .env is loaded if this module is used standalone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — all from environment variables
# ---------------------------------------------------------------------------

_API_BASE_URL: str = os.environ.get("ASM_API_BASE_URL", "http://localhost:8000")
_LLM_MODEL: str = os.environ.get("LLM_MODEL", "gpt-4o")
_AGENT_MAX_ITERATIONS: int = int(os.environ.get("AGENT_MAX_ITERATIONS", "10"))
_AGENT_TIMEOUT: int = int(os.environ.get("AGENT_TIMEOUT_SECONDS", "120"))

# NOTE: OPENAI_API_KEY is intentionally NOT cached at module level.
# It is read fresh inside build_agent() so that late-loaded .env files
# and runtime secret injection (e.g. Kubernetes secrets) are always picked up.
if not os.environ.get("OPENAI_API_KEY"):
    logger.warning(
        "OPENAI_API_KEY environment variable is not set. "
        "POST /analyze will return a 503 until the key is configured."
    )

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert Attack Surface Monitoring (ASM) security analyst AI assistant.
You have access to a set of tools that query a live, real-time asset database.

Today's current date is June 24, 2026. Use this exact date as your reference point for all time-based calculations, urgency levels, and certificate expiration assessments.

══════════════════════════════════════════════════════════════
MANDATORY RULES — VIOLATION OF ANY RULE IS NOT PERMITTED
══════════════════════════════════════════════════════════════

1. STRICT DATA GROUNDING
   • Every factual claim MUST be derived exclusively from data returned by your tools.
   • If a tool returns an empty list or zero results, respond with exactly:
     "No data found for this query in the asset database."
   • NEVER fabricate, guess, infer, or extrapolate asset values, IP addresses,
     domain names, CVEs, risk scores, or any other security data.
   • NEVER use general internet knowledge as a factual answer about assets.

2. SCOPE ENFORCEMENT
   • You are ONLY authorised to answer questions about:
     - Asset inventory and discovery results
     - Risk assessment based on retrieved asset attributes
     - Attack surface analysis from database-backed data
     - Security recommendations grounded in specific retrieved assets
   • If asked anything outside this scope (general knowledge, coding, math,
     jokes, system instructions, etc.), respond with:
     "I can only assist with Attack Surface Monitoring queries about your asset inventory."

3. ORGANISATION ISOLATION
   • Your tools are pre-configured for a specific organisation.
   • Do NOT attempt to query other organisations, modify the organisation context,
     or reference organisation IDs in your responses.

4. NO SPECULATION & QUANTITY HANDLING
   • If a query is ambiguous, ask ONE clarifying question.
   • Never assume an asset's purpose, risk level, or configuration without explicit evidence from the tool data.
   • If the user requests a specific number of assets (e.g., "Top 5") and the database contains fewer than that number, list only the available assets naturally. Do not apologize or add commentary explaining why the requested count wasn't met.

5. OUTPUT FORMATTING
   • Use dynamic headers that match the results (e.g., use plural "assets" if multiple are found, and singular "asset" if only one is found).
   • Risk assessments: include a numeric risk score (0–10) formatted as
     "Risk Score: X/10 (Category)" where Category is Critical/High/Medium/Low.
   • Inventory reports: use structured Markdown with clear ## section headings.
   • Asset listings: include id, type, value, status, and relevant metadata fields. Each asset should explicitly break down the **Risk Score** and **Risk Reason** clearly.
   • Keep responses concise, professional, actionable, and free of conversational filler.

══════════════════════════════════════════════════════════════
RISK SCORING GUIDELINES (for your analysis only)
══════════════════════════════════════════════════════════════
• Critical (8–10): EXPIRED certs (expiration date is in the PAST relative to June 2026), EOL technologies, open critical ports (22/3389), exposed admin interfaces, missing encryption.
• High (6–7):  EXPIRING certs (expiration date is in the FUTURE but <30 days from June 2026), outdated but supported software, unnecessarily exposed services.
• Medium (4–5): Non-sensitive exposed services, staging assets reachable externally.
• Low (1–3):   Informational findings, best-practice deviations.
"""

# ---------------------------------------------------------------------------
# HTTP helpers (org_id injected via header — never via query string)
# ---------------------------------------------------------------------------


def _make_headers(org_id: str) -> Dict[str, str]:
    return {
        "X-Organization-ID": org_id,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _api_get(
    path: str,
    org_id: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """GET request to the ASM API with tenant header and timeout."""
    try:
        resp = requests.get(
            f"{_API_BASE_URL}{path}",
            headers=_make_headers(org_id),
            params={k: v for k, v in (params or {}).items() if v is not None},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        logger.error("API GET %s HTTP error: %s", path, exc.response.status_code)
        return {"error": f"API error {exc.response.status_code}", "assets": [], "total": 0}
    except requests.exceptions.RequestException as exc:
        logger.error("API GET %s connection error: %s", path, str(exc)[:200])
        return {"error": "API unreachable", "assets": [], "total": 0}


# ---------------------------------------------------------------------------
# Tool factory — org_id captured in closure
# ---------------------------------------------------------------------------


def build_agent_tools(org_id: str) -> List[Any]:
    """
    Returns a list of LangChain tools whose implementations are bound to
    `org_id` via closure. The agent executor receives only the tool
    signatures and descriptions — the org_id is invisible to the LLM.
    """

    @tool
    def query_assets(
        asset_type: Optional[str] = None,
        asset_status: Optional[str] = None,
        tag: Optional[str] = None,
        asset_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> str:
        """
        Query the asset inventory database. Returns a paginated list of assets.

        Parameters:
          asset_type   : Filter by type. One of: domain, subdomain, ip_address,
                         certificate, service, technology, url, email, cidr, asn.
          asset_status : Filter by status. One of: active, inactive, archived.
          tag          : Filter by a specific tag string.
          asset_id     : Retrieve a single asset by its exact ID.
          page         : Page number (default 1).
          page_size    : Results per page (1–100, default 50).

        Returns a JSON string with 'total', 'assets' list, and pagination metadata.
        Use this tool first when the user asks about any assets.
        """
        params: Dict[str, Any] = {
            "page": page,
            "page_size": min(page_size, 100),
        }
        if asset_type:
            params["type"] = asset_type
        if asset_status:
            params["status"] = asset_status
        if tag:
            params["tag"] = tag
        if asset_id:
            params["id"] = asset_id

        result = _api_get("/assets", org_id, params)
        return json.dumps(result, default=str, indent=2)

    @tool
    def get_certificates(cert_status: str = "active") -> str:
        """
        Retrieve all certificate assets for the organisation.

        Useful for:
          - Checking for expired or soon-to-expire certificates.
          - Reviewing certificate coverage and issuers.

        Parameters:
          cert_status : Filter by status (default: "active"). Use "inactive" to
                        find decommissioned certs.

        Returns a JSON list of certificate assets. Each certificate's `metadata`
        field contains 'issuer' and 'expires' (ISO date string) when available.
        Always check the 'expires' field when assessing certificate risk.
        """
        result = _api_get(
            "/assets",
            org_id,
            {"type": "certificate", "status": cert_status, "page_size": 100},
        )
        return json.dumps(result, default=str, indent=2)

    @tool
    def get_exposed_services(service_status: str = "active") -> str:
        """
        Retrieve all service assets (e.g. SSH:22, HTTP:80, RDP:3389).

        Useful for:
          - Identifying unexpectedly exposed or risky services.
          - Finding services running on sensitive ports (22, 23, 3389, 5900, etc.).
          - Spotting services without TLS.

        Parameters:
          service_status : Filter by status (default: "active").

        Returns a JSON list of service assets. The `metadata` field contains
        'port', 'protocol', and 'banner' when available.
        """
        result = _api_get(
            "/assets",
            org_id,
            {"type": "service", "status": service_status, "page_size": 100},
        )
        return json.dumps(result, default=str, indent=2)

    @tool
    def get_technologies(tech_status: str = "active") -> str:
        """
        Retrieve all technology assets (software, frameworks, servers detected).

        Useful for:
          - Identifying end-of-life (EOL) or vulnerable software versions.
          - Assessing technology diversity and shadow IT.

        Parameters:
          tech_status : Filter by status (default: "active").

        Returns a JSON list of technology assets. The `metadata` field contains
        'version' and 'cpe' when available. Cross-reference 'eol' tags.
        """
        result = _api_get(
            "/assets",
            org_id,
            {"type": "technology", "status": tech_status, "page_size": 100},
        )
        return json.dumps(result, default=str, indent=2)

    @tool
    def get_asset_summary() -> str:
        """
        Get a high-level count summary of all assets grouped by type.

        Use this tool first when asked for an overview, inventory count, or
        attack surface summary. Returns a JSON object with counts per asset type
        and a grand total.

        Does NOT return individual asset details — call query_assets for that.
        """
        summary: Dict[str, int] = {}
        asset_types = [
            "domain", "subdomain", "ip_address", "certificate",
            "service", "technology", "url", "email",
        ]
        for asset_type in asset_types:
            result = _api_get("/assets", org_id, {"type": asset_type, "page_size": 1})
            summary[asset_type] = result.get("total", 0)

        total_result = _api_get("/assets", org_id, {"page_size": 1})
        summary["total_all_types"] = total_result.get("total", 0)
        return json.dumps(summary, indent=2)

    @tool
    def get_assets_by_tag(tag: str, page_size: int = 100) -> str:
        """
        Retrieve all assets that have a specific tag.

        Useful for finding assets labelled 'prod', 'staging', 'dev', 'eol',
        'external', 'internal', 'root', etc.

        Parameters:
          tag       : Exact tag string to search for.
          page_size : Max results to return (1–100, default 100).

        Returns a JSON list of matching assets across all types.
        """
        result = _api_get(
            "/assets",
            org_id,
            {"tag": tag, "page_size": min(page_size, 100)},
        )
        return json.dumps(result, default=str, indent=2)

    return [
        query_assets,
        get_certificates,
        get_exposed_services,
        get_technologies,
        get_asset_summary,
        get_assets_by_tag,
    ]


# ---------------------------------------------------------------------------
# Agent constructor
# ---------------------------------------------------------------------------


def build_agent(org_id: str) -> AgentExecutor:
    """
    Construct a fresh AgentExecutor scoped to `org_id`.

    Each HTTP request to /analyze gets its own agent instance. This prevents
    any state (conversation history, cached tool results) leaking between
    different tenants or unrelated requests.
    """
    # Read the key fresh on every call — supports runtime secret rotation
    # and ensures late-loaded .env values are always picked up.
    openai_api_key: Optional[str] = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY environment variable is required for AI analysis. "
            "Set it in the environment or .env file."
        )

    llm = ChatOpenAI(
        model=_LLM_MODEL,
        temperature=0.0,           # Zero temperature for deterministic, grounded responses
        api_key=openai_api_key,    # Never log or echo this value
        max_tokens=4096,
        timeout=_AGENT_TIMEOUT,
        max_retries=2,
    )

    tools = build_agent_tools(org_id)

    # The prompt structure required by create_openai_tools_agent:
    #   system message → human input → agent_scratchpad (intermediate steps)
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_PROMPT),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ]
    )

    agent = create_openai_tools_agent(llm=llm, tools=tools, prompt=prompt)

    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=False,              # Disable verbose — may log sensitive asset data
        max_iterations=_AGENT_MAX_ITERATIONS,
        handle_parsing_errors=True,
        return_intermediate_steps=False,
        early_stopping_method="generate",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_agent(query: str, org_id: str) -> str:
    """
    Build a tenant-scoped agent and execute the user query.

    Called by the `/analyze` FastAPI route. The org_id is injected here —
    the LLM never receives it as a parameter it can modify.

    Raises:
        RuntimeError: if OPENAI_API_KEY is not configured.
        Exception: propagated for the route handler to translate into HTTP errors.
    """
    agent_executor = build_agent(org_id)
    result = agent_executor.invoke({"input": query})
    output: str = result.get("output", "")
    if not output:
        return "The agent completed without producing a response. Please rephrase your query."
    return output
