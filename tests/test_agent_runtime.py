from serving_layer.server import AgentRuntime


async def _add(a: int, b: int) -> int:
    return a + b


def test_agent_runtime_runs_coroutines() -> None:
    runtime = AgentRuntime()
    try:
        assert runtime.run(_add(2, 3)) == 5
    finally:
        runtime.close()
