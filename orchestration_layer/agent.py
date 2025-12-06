"""Agent orchestration with client-based tool access control."""

import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("terrabridge.agent")

# config
LLM_URL = os.getenv("OPENAI_API_BASE")
LLM_KEY = os.getenv("OPENAI_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL")
MCP_URL = os.getenv("MCP_SERVER_HOST_PORT")
DMS_ID = os.getenv("DMS_CLIENT_ID")
DMS_SECRET = os.getenv("DMS_CLIENT_SECRET")
DMS_USERNAME = os.getenv("DMS_USERNAME")
DMS_PASSWORD = os.getenv("DMS_PASSWORD")

def _require_env(var_name: str, value: str | None) -> str:
    """Ensure required environment variables are present."""
    if value and value.strip():
        return value
    raise RuntimeError(
        f"Missing required environment variable {var_name}."
    )


@dataclass(frozen=True)
class AgentConfig:
    mcp_url: str
    llm_url: str
    llm_key: str
    llm_model: str


@lru_cache(maxsize=1)
def _get_config() -> AgentConfig:
    """Load and cache required configuration."""
    return AgentConfig(
        mcp_url=_require_env("MCP_SERVER_HOST_PORT", MCP_URL),
        llm_url=_require_env("OPENAI_API_BASE", LLM_URL),
        llm_key=_require_env("OPENAI_API_KEY", LLM_KEY),
        llm_model=_require_env("LLM_MODEL", LLM_MODEL),
    )


# shared httpx clients for connection pooling across agent requests
_MCP_HTTP_CLIENT: httpx.AsyncClient | None = None
_LLM_HTTP_CLIENT: httpx.AsyncClient | None = None


def _mcp_http_client() -> httpx.AsyncClient:
    """Lazily build/reuse HTTP client for MCP calls."""
    global _MCP_HTTP_CLIENT
    if _MCP_HTTP_CLIENT is None:
        _MCP_HTTP_CLIENT = httpx.AsyncClient(
            timeout=60.0,
            follow_redirects=True,
            http2=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
    return _MCP_HTTP_CLIENT


def _llm_http_client() -> httpx.AsyncClient:
    """Lazily build/reuse HTTP client for LLM calls."""
    global _LLM_HTTP_CLIENT
    if _LLM_HTTP_CLIENT is None:
        _LLM_HTTP_CLIENT = httpx.AsyncClient(
            timeout=120.0,
            http2=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _LLM_HTTP_CLIENT


# client access control

# tool subscriptions per client id. empty set means no tools, "*" means all tools.
# in production, this would be loaded from a database or config service.
CLIENT_TOOL_SUBSCRIPTIONS: dict[str, set[str]] = {
    # admin client - full access
    "admin": {"*"},
    # dms-only client
    "dms-client": {
        "login_service_account",
        "search_documents",
        "get_user_profile",
        "get_document",
        "list_folders",
    },
    # compliance-only client
    "compliance-client": {
        "ingest_compliance_scan",
        "ingest_security_events",
        "ingest_critical_alert",
        "get_compliance_status",
        "get_fleet_status",
        "get_security_events",
        "get_unacknowledged_alerts",
        "acknowledge_alert",
        "get_compliance_history",
        "generate_compliance_report",
        "analyze_compliance_ai",
        "get_iso_control_info",
        "get_failing_controls_detail",
    },
    # database-only client
    "db-client": {
        "db_schema_overview",
        "db_schema_relations",
        "db_execute_cql",
    },
    # default client - limited tools
    "default": {
        "get_compliance_status",
        "get_fleet_status",
        "search_documents",
    },
}


def get_allowed_tools(client_id: str) -> set[str]:
    """Get allowed tools for a client ID."""
    return CLIENT_TOOL_SUBSCRIPTIONS.get(
        client_id, CLIENT_TOOL_SUBSCRIPTIONS.get("default", set())
    )


def filter_tools_for_client(tools: list[dict], client_id: str) -> list[dict]:
    """Filter tools based on client subscription."""
    allowed = get_allowed_tools(client_id)
    if "*" in allowed:
        return tools
    return [t for t in tools if t.get("name") in allowed]


def is_tool_allowed(tool_name: str, client_id: str) -> bool:
    """Check if a specific tool is allowed for a client."""
    allowed = get_allowed_tools(client_id)
    return "*" in allowed or tool_name in allowed


# prompts

SYSTEM_PROMPT = """You are an enterprise agent with access to:
- DMS API (via tools login_service_account, search_documents, get_user_profile, etc.).
- Cassandra database (via db_schema_overview, db_schema_relations, db_execute_cql).
- Compliance monitoring (via compliance tools).

GENERAL RULES:
1. Never invent SQL or CQL in natural language; always use tools.
2. Before using db_execute_cql, you MUST:
   - Call db_schema_overview (and db_schema_relations if needed) at least once
     for the target keyspace to learn the exact table and column names.
3. When constructing CQL for db_execute_cql:
   - Use exactly the table and column names returned by db_schema_overview.
   - Do NOT change case or add underscores. For example, if schema shows 'clientid',
     you must use 'clientid', not 'CLIENT_ID' or 'client_id'.
   - Use %s placeholders for parameters and pass values via params_json as a JSON array.
4. If db_execute_cql returns an error containing 'Undefined column name':
   - Inspect the last db_schema_overview result in the conversation.
   - Correct the column name and try ONCE more. Do not repeat the same invalid query.
5. Prefer semantic, safe queries instead of 'SELECT *' over large tables.
"""

STATE_PROMPT = """Workflow State:
- is_authenticated: {authenticated}
- Call login_service_account exactly once when unauthenticated before invoking any DMS data tool.
- When calling login_service_account, pass an empty object ({{}}); credentials are injected automatically.
- After successful login, rely on search_documents and other DMS tools to answer the user's question.
"""

# state/clients


@dataclass(slots=True)
class State:
    conversation: list[dict[str, Any]] = field(default_factory=list)
    authenticated: bool = False
    max_iter: int = 10
    client_id: str = "default"

    def context_message(self) -> dict[str, str]:
        return {
            "role": "system",
            "content": STATE_PROMPT.format(
                authenticated=str(self.authenticated).lower()
            ),
        }


class MCP:
    """Async MCP client for tool discovery and execution."""

    __slots__ = ("url", "http", "tools", "_req_id", "_session_id", "_owns_client")

    def __init__(self, url: str, http_client: httpx.AsyncClient | None = None) -> None:
        if not url:
            raise ValueError("MCP URL must be provided")
        self.url = url.rstrip("/")
        self.http = http_client or httpx.AsyncClient(
            timeout=60.0,
            follow_redirects=True,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        self.tools: dict[str, dict] = {}
        self._req_id = 0
        self._session_id: str | None = None
        self._owns_client = http_client is None

    def _payload(self, method: str, params: dict) -> dict:
        self._req_id += 1
        return {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params,
        }

    async def _post(self, payload: dict) -> dict:
        """Make a POST request, including session header if available."""
        headers = {"Mcp-Session-Id": self._session_id} if self._session_id else {}
        try:
            r = await self.http.post(f"{self.url}/mcp", json=payload, headers=headers)
            r.raise_for_status()
        except httpx.RequestError as exc:
            raise RuntimeError(f"MCP request failed: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"MCP returned HTTP {exc.response.status_code}: "
                f"{exc.response.text[:200]}"
            ) from exc

        if "mcp-session-id" in r.headers:
            self._session_id = r.headers["mcp-session-id"]

        content_type = r.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            return self._parse_sse(r.text)
        return r.json()

    def _parse_sse(self, text: str) -> dict:
        """Parse Server-Sent Events format and extract JSON-RPC response."""
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data_str = line[5:].strip()
                if data_str:
                    try:
                        return json.loads(data_str)
                    except json.JSONDecodeError:
                        pass
        return {}

    async def initialize(self) -> dict:
        """Initialize MCP session."""
        return await self._post(
            self._payload(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "terrabridge-agent", "version": "1.0.0"},
                },
            )
        )

    async def discover(self, client_id: str = "default") -> list[dict]:
        """Fetch tools from MCP server, filtered by client subscription."""
        if not self._session_id:
            await self.initialize()

        data = await self._post(self._payload("tools/list", {}))
        all_tools = data.get("result", {}).get("tools", [])

        # filter tools based on client subscription
        filtered_tools = filter_tools_for_client(all_tools, client_id)
        self.tools = {t["name"]: t for t in filtered_tools}
        return filtered_tools

    async def call(self, name: str, args: dict, client_id: str = "default") -> Any:
        """Execute tool on MCP server with access control."""
        # check access before calling
        if not is_tool_allowed(name, client_id):
            return {
                "status": "error",
                "message": f"Tool '{name}' not authorized for client '{client_id}'",
            }

        data = await self._post(
            self._payload("tools/call", {"name": name, "arguments": args})
        )

        if error := data.get("error"):
            return {
                "status": "error",
                "message": error.get("message"),
                "code": error.get("code"),
            }

        result = data.get("result", {})
        content = result.get("content", [])
        if content:
            block = content[0]
            if text := block.get("text"):
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return text
            if payload := block.get("json"):
                return payload
        return result

    def schema(self) -> list[dict]:
        """Convert MCP tools to OpenAI format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get(
                        "inputSchema", {"type": "object", "properties": {}}
                    ),
                },
            }
            for t in self.tools.values()
        ]

    async def close(self) -> None:
        if self._owns_client:
            await self.http.aclose()


class LLM:
    """Async OpenAI-compatible LLM client."""

    __slots__ = ("url", "key", "model", "http", "_owns_client")

    def __init__(
        self,
        url: str,
        key: str,
        model: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not url:
            raise ValueError("LLM URL must be provided")
        if not key:
            raise ValueError("LLM key must be provided")
        if not model:
            raise ValueError("LLM model must be provided")
        self.url = url.rstrip("/")
        self.key = key
        self.model = model
        self.http = http_client or httpx.AsyncClient(timeout=120.0)
        self._owns_client = http_client is None

    async def chat(self, messages: list[dict], tools: list[dict] | None = None) -> dict:
        """Send chat completion request."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            r = await self.http.post(
                f"{self.url}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.key}"},
            )
            r.raise_for_status()
        except httpx.RequestError as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"LLM returned HTTP {exc.response.status_code}: "
                f"{exc.response.text[:200]}"
            ) from exc
        return r.json()

    async def close(self) -> None:
        if self._owns_client:
            await self.http.aclose()


# agent runtime
def _safe_json(data: str | None) -> dict[str, Any]:
    if not data:
        return {}
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return {}


def _prepare_tool_args(name: str, args: dict) -> dict:
    if name != "login_service_account":
        return args

    creds = args.get("creds", {})
    merged = {
        "client_id": DMS_ID or creds.get("client_id"),
        "client_secret": DMS_SECRET or creds.get("client_secret"),
        "username": DMS_USERNAME or creds.get("username"),
        "password": DMS_PASSWORD or creds.get("password"),
    }
    args["creds"] = {k: v for k, v in merged.items() if v}
    return args


async def chat_completion(messages: list[dict], client_id: str = "default") -> dict:
    """Execute one chat completion with tool orchestration."""
    allowed = get_allowed_tools(client_id)
    if not allowed:
        return {
            "message": {
                "role": "assistant",
                "content": "No tools available for this client.",
            },
            "finish_reason": "stop",
        }

    state = State(conversation=messages, client_id=client_id)
    config = _get_config()

    mcp = MCP(config.mcp_url, _mcp_http_client())
    llm = LLM(config.llm_url, config.llm_key, config.llm_model, _llm_http_client())

    try:
        await mcp.discover(client_id)
        tools = mcp.schema()
        log.debug("client=%s tools=%s", client_id, list(mcp.tools.keys()))

        for i in range(state.max_iter):
            llm_messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                state.context_message(),
                *state.conversation,
            ]
            resp = await llm.chat(llm_messages, tools)
            choice = resp["choices"][0]
            msg = choice["message"]
            finish_reason = choice.get("finish_reason", "stop")
            state.conversation.append(msg)

            calls = msg.get("tool_calls", [])
            if not calls:
                return {"message": msg, "finish_reason": finish_reason}

            for tc in calls:
                fn, tid = tc["function"], tc["id"]
                args = _safe_json(fn.get("arguments"))
                prepared_args = _prepare_tool_args(fn["name"], args)

                result = await mcp.call(fn["name"], prepared_args, client_id)
                log.debug(
                    "tool %s result=%s",
                    fn["name"],
                    json.dumps(result, default=str)[:200],
                )

                if fn["name"] == "login_service_account":
                    state.authenticated = (
                        isinstance(result, dict) and result.get("status") == "success"
                    )

                state.conversation.append(
                    {
                        "role": "tool",
                        "tool_call_id": tid,
                        "content": json.dumps(result, default=str),
                    }
                )

        return {
            "message": {
                "role": "assistant",
                "content": "max iterations reached",
            },
            "finish_reason": "length",
        }
    finally:
        await mcp.close()
        await llm.close()


async def run(prompt: str, client_id: str = "default") -> str:
    """CLI helper to run the agent on a single prompt."""
    result = await chat_completion([{"role": "user", "content": prompt}], client_id)
    message = result.get("message", {})
    return message.get("content", "")


def main() -> None:
    client_id = os.getenv("CLIENT_ID", "default")
    query = os.getenv(
        "AGENT_QUERY",
        "list all documents for client fae8f1d2-23f7-4222-bd1d-4a5dd659657e",
    )

    log.info("client_id=%s", client_id)
    log.info("query=%s", query)
    try:
        _get_config()
        log.info("response=%s", asyncio.run(run(query, client_id)))
    except (RuntimeError, ValueError) as exc:
        log.error("error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
