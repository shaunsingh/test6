"""mcp server, exposes dms/cassandra/compliance tools via fastmcp"""

import os

from fastmcp import FastMCP
from .tools.dms import register_dms_tools
from .tools.cassandra import register_cassandra_tools
from .tools.compliance import register_compliance_tools

mcp = FastMCP("Terrabridge MCP")


def main() -> None:
    """start mcp server with all registered tools."""
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8001"))
    register_dms_tools(mcp)
    register_cassandra_tools(mcp)
    register_compliance_tools(mcp)

    tools = list(mcp._tool_manager._tools.keys())
    print(f"\nregistered tools: {tools}\n")

    mcp.run(transport="streamable-http", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
