from orchestration_layer import agent


def test_filter_tools_by_client() -> None:
    tools = [
        {"name": "login_service_account"},
        {"name": "search_documents"},
        {"name": "ingest_compliance_scan"},
    ]

    filtered = agent.filter_tools_for_client(tools, "dms-client")
    filtered_names = {t["name"] for t in filtered}

    assert "login_service_account" in filtered_names
    assert "search_documents" in filtered_names
    assert "ingest_compliance_scan" not in filtered_names


def test_tool_authorization_checks() -> None:
    assert agent.is_tool_allowed("ingest_compliance_scan", "compliance-client")
    assert not agent.is_tool_allowed("ingest_compliance_scan", "dms-client")
    assert agent.is_tool_allowed("search_documents", "admin")  # wildcard client
