import os
import json
import logging
from typing import Any
from functools import lru_cache

from dotenv import load_dotenv
from fastmcp import FastMCP
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.query import SimpleStatement
from cassandra import ConsistencyLevel

load_dotenv()
log = logging.getLogger(__name__)

# config
HOSTS = os.getenv("CASSANDRA_CONTACT_POINTS", "localhost:9042").split(",")
KEYSPACE = os.getenv("CASSANDRA_KEYSPACE", "claims_app")
USER = os.getenv("CASSANDRA_USERNAME", "cassandra")
PASS = os.getenv("CASSANDRA_PASSWORD", "cassandra")

# connection pool
_cluster: Cluster | None = None
_sessions: dict[str, Any] = {}

FORBIDDEN = frozenset(
    [
        "DROP ",
        "TRUNCATE ",
        "ALTER ",
        "GRANT ",
        "REVOKE ",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
    ]
)


def _cluster_instance() -> Cluster:
    """lazily create cluster connection."""
    global _cluster
    if not _cluster:
        hosts = [h.split(":")[0] for h in HOSTS]
        port = int(HOSTS[0].split(":")[1]) if ":" in HOSTS[0] else 9042
        _cluster = Cluster(
            hosts, port=port, auth_provider=PlainTextAuthProvider(USER, PASS)
        )
    return _cluster


def _session(keyspace: str = KEYSPACE):
    """get or create session for keyspace."""
    if keyspace not in _sessions:
        try:
            _sessions[keyspace] = _cluster_instance().connect(keyspace)
        except Exception as exc:  # pragma: no cover - defensive connection guard
            log.exception("cassandra connect failed")
            raise RuntimeError(
                f"failed to connect to keyspace '{keyspace}': {exc}"
            ) from exc
    return _sessions[keyspace]


def _col_type(col) -> str:
    """extract column type string."""
    return str(getattr(col, "cql_type", None) or getattr(col, "type", "unknown"))


def register_cassandra_tools(mcp: FastMCP) -> None:
    """register cassandra tools to mcp server."""

    @mcp.tool()
    async def db_schema_overview(keyspace: str = KEYSPACE) -> dict[str, Any]:
        """get schema overview: tables, columns, primary keys. call before writing cql."""
        meta = _cluster_instance().metadata
        if keyspace not in meta.keyspaces:
            return {
                "keyspace": keyspace,
                "tables": [],
                "error": f"keyspace '{keyspace}' not found",
            }

        ks = meta.keyspaces[keyspace]
        tables = [
            {
                "name": name,
                "partition_keys": [c.name for c in t.partition_key],
                "clustering_keys": [c.name for c in t.clustering_key],
                "columns": [
                    {"name": c.name, "type": _col_type(c)} for c in t.columns.values()
                ],
            }
            for name, t in ks.tables.items()
        ]
        return {"keyspace": keyspace, "tables": tables}

    @mcp.tool()
    async def db_schema_relations(keyspace: str = KEYSPACE) -> dict[str, Any]:
        """infer table relationships by matching column names/types."""
        meta = _cluster_instance().metadata
        if keyspace not in meta.keyspaces:
            return {
                "keyspace": keyspace,
                "relations": [],
                "error": f"keyspace '{keyspace}' not found",
            }

        ks = meta.keyspaces[keyspace]
        info = {
            name: {
                "pk": frozenset(c.name for c in t.partition_key),
                "cols": {c.name: _col_type(c) for c in t.columns.values()},
            }
            for name, t in ks.tables.items()
        }

        tables = list(info.keys())
        relations = [
            {
                "tables": [t1, t2],
                "column": col,
                "confidence": (
                    "high"
                    if col in info[t1]["pk"] and col in info[t2]["pk"]
                    else (
                        "medium"
                        if col in info[t1]["pk"] or col in info[t2]["pk"]
                        else "low"
                    )
                ),
            }
            for i, t1 in enumerate(tables)
            for t2 in tables[i + 1 :]
            for col in set(info[t1]["cols"]) & set(info[t2]["cols"])
            if info[t1]["cols"][col] == info[t2]["cols"][col]
        ]
        return {"keyspace": keyspace, "relations": relations}

    @mcp.tool()
    async def db_execute_cql(
        cql: str, params_json: str | None = None, limit: int = 500
    ) -> dict[str, Any]:
        """execute read-only cql. use %s placeholders, params_json as json array."""
        cql = cql.strip()
        upper = cql.upper()

        # security
        if not upper.startswith("SELECT"):
            return {"status": "error", "rows": [], "message": "only SELECT allowed"}
        if any(kw in upper for kw in FORBIDDEN):
            return {"status": "error", "rows": [], "message": "forbidden operation"}

        # params
        params: tuple = ()
        if params_json:
            try:
                p = json.loads(params_json)
                if not isinstance(p, list):
                    return {
                        "status": "error",
                        "rows": [],
                        "message": "params_json must be json array",
                    }
                params = tuple(p)
            except json.JSONDecodeError as e:
                return {"status": "error", "rows": [], "message": f"invalid json: {e}"}

        if (expected := cql.count("%s")) != len(params):
            return {
                "status": "error",
                "rows": [],
                "message": f"expected {expected} params, got {len(params)}",
            }

        try:
            session = _session()
            if "LIMIT" not in upper:
                cql = f"{cql.rstrip(';')} LIMIT {limit}"
            stmt = SimpleStatement(
                cql,
                consistency_level=ConsistencyLevel.LOCAL_QUORUM,
                fetch_size=min(limit, 1000),
            )
            rows = [dict(r._asdict()) for r in session.execute(stmt, params)]
            return {"status": "success", "row_count": len(rows), "rows": rows}
        except Exception as e:
            log.exception("cql failed")
            return {"status": "error", "rows": [], "message": str(e)}
