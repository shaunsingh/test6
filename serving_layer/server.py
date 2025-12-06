"""Unified Terrabridge server: LLM backend + MCP + agent HTTP front-end."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Coroutine

log = logging.getLogger("terrabridge")

# model catalog (MLX variants are resolved per-platform and hidden on Linux)
MODEL_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "id": "ibm-granite/granite-4.0-h-micro",
        "mlx_id": "mlx-community/granite-4.0-h-micro-8bit",
        "name": "Granite 4.0 Micro (recommended)",
        "default": True,
    },
    {
        "id": "ibm-granite/granite-4.0-h-tiny",
        "mlx_id": "mlx-community/granite-4.0-h-small-8bit",
        "name": "Granite 4.0 Tiny",
    },
    {
        "id": "ibm-granite/granite-4.0-8b-instruct",
        "mlx_id": "mlx-community/granite-4.0-8b-instruct-8bit",
        "name": "Granite 4.0 8B",
    },
    {
        "id": "meta-llama/Llama-3.1-8B-Instruct",
        "mlx_id": "mlx-community/Llama-3.1-8B-Instruct-4bit",
        "name": "Llama 3.1 8B",
    },
    {
        "id": "meta-llama/Llama-3.1-70B-Instruct",
        "mlx_id": "mlx-community/Llama-3.1-70B-Instruct-4bit",
        "name": "Llama 3.1 70B",
    },
    {
        "id": "gpt-oss/gpt-oss-20b",
        "mlx_id": "mlx-community/gpt-oss-20b-4bit",
        "name": "GPT OSS 20B",
    },
    {
        "id": "gpt-oss/gpt-oss-120b",
        "mlx_id": "mlx-community/gpt-oss-120b-4bit",
        "name": "GPT OSS 120B",
    },
)


class JsonHandler(BaseHTTPRequestHandler):
    """Base HTTP handler with JSON helpers."""

    def _json_body(self) -> tuple[dict, str | None]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}, "empty body"
        try:
            return json.loads(self.rfile.read(length)), None
        except json.JSONDecodeError:
            return {}, "invalid json"

    def _write_json(self, status: int, payload: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, *_) -> None:  # pragma: no cover - quiet default HTTP logs
        pass


def _platform_models() -> tuple[dict[str, Any], ...]:
    """Return platform-specific catalog (MLX ids on macOS, hidden on Linux)."""
    use_mlx = platform.system() == "Darwin"
    models: list[dict[str, Any]] = []
    for m in MODEL_CATALOG:
        entry = {k: v for k, v in m.items() if k != "mlx_id"}
        entry["id"] = m["mlx_id"] if use_mlx and m.get("mlx_id") else m["id"]
        models.append(entry)
    return tuple(models)


def default_model() -> str:
    models = _platform_models()
    for m in models:
        if m.get("default"):
            return m["id"]
    return models[0]["id"]


def pick_model_interactive() -> str:
    """CLI model picker - returns selected model ID."""
    models = _platform_models()
    default_idx = next((i for i, m in enumerate(models) if m.get("default")), 0)
    default_choice = models[default_idx]["id"]

    print("\n┌─────────────────────────────────────────┐")
    print("│         Select LLM Model                │")
    print("└─────────────────────────────────────────┘\n")
    for i, m in enumerate(models, 1):
        marker = " ★" if m.get("default") else ""
        print(f"  [{i}] {m['name']}{marker}")
    print()

    while True:
        try:
            choice = input(f"Enter number (default={default_idx+1}): ").strip()
            if not choice:
                return default_choice
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                selected = models[idx]
                print(f"\n  → Selected: {selected['name']}\n")
                return selected["id"]
        except (ValueError, IndexError):
            pass
        print("  Invalid choice, try again.")


# gpu/backend detection
def run_cmd(
    cmd: list[str], timeout: float = 5.0
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


@dataclass(frozen=True, slots=True)
class GPUInfo:
    has_cuda: bool
    has_rocm: bool
    compute_capability: float | None


_GPU_INFO: GPUInfo | None = None


def _detect_gpu() -> GPUInfo:
    global _GPU_INFO
    if _GPU_INFO is not None:
        return _GPU_INFO

    has_cuda = False
    has_rocm = False
    compute_cap: float | None = None

    def _probe(
        cmd: list[str], timeout: float = 5.0
    ) -> subprocess.CompletedProcess[str] | None:
        return run_cmd(cmd, timeout=timeout)

    cap_proc = run_cmd(
        ["nvidia-smi", "--query-gpu=compute_cap", "--format=csv,noheader,nounits"]
    )
    if cap_proc and cap_proc.returncode == 0 and cap_proc.stdout.strip():
        has_cuda = True
        try:
            compute_cap = float(cap_proc.stdout.strip().split("\n")[0])
        except ValueError:
            compute_cap = None
    else:
        # fallback probe to distinguish missing binary vs. other errors
        probe = _probe(["nvidia-smi"])
        has_cuda = probe is not None and probe.returncode == 0

    if platform.system() == "Linux":
        for cmd in (["rocminfo"], ["rocm-smi", "-i"]):
            proc = _probe(cmd, timeout=8.0)
            if proc and proc.returncode == 0:
                has_rocm = True
                break

    _GPU_INFO = GPUInfo(
        has_cuda=has_cuda, has_rocm=has_rocm, compute_capability=compute_cap
    )
    return _GPU_INFO


def has_rocm() -> bool:
    """Return True when ROCm tooling reports at least one AMD GPU."""
    return _detect_gpu().has_rocm


def has_cuda() -> bool:
    return _detect_gpu().has_cuda


def compute_capability() -> float | None:
    return _detect_gpu().compute_capability


def has_tensorrt() -> bool:
    try:
        import importlib.util

        if importlib.util.find_spec("tensorrt_llm") is None:
            return False
    except Exception:
        return False
    return shutil.which("trtllm-serve") is not None


def has_vllm() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("vllm") is not None
    except Exception:
        return False


def select_backend() -> tuple[str, str | None]:
    """Choose backend and device.

    - macOS: MLX only.
    - Linux: TensorRT when WITH_TENSORRT=1 is set and dependencies are available;
      otherwise vLLM (GPU if present, else CPU).
    - WITH_TENSORRT=0 is the default and expects vLLM installed; installs are mutually exclusive.
    """

    if platform.system() == "Darwin":
        return "mlx", None

    with_tensorrt = os.getenv("WITH_TENSORRT") == "1"
    cc = compute_capability()
    if cc:
        log.info("GPU compute capability: %.1f", cc)
    elif has_cuda():
        log.info("GPU detected without reported compute capability")

    if with_tensorrt:
        if not has_tensorrt():
            raise RuntimeError(
                "WITH_TENSORRT=1 but tensorrt-llm/trtllm-serve not found. "
                "Install tensorrt-llm & ensure tooling is present."
            )
        if not cc or cc < 8.0:
            raise RuntimeError("WITH_TENSORRT=1 requires compute capability >= 8.0.")
        return "tensorrt", None

    if not has_vllm():
        raise RuntimeError("vLLM is not installed. Install vLLM & ensure tooling is present")

    if has_cuda():
        return "vllm", "cuda"
    if has_rocm():
        log.info("ROCm-capable GPU detected")
        return "vllm", "rocm"

    log.info("Using vLLM on CPU")
    return "vllm", "cpu"


# mlx backend (macos)
mlx_mod: Any = None
mlx_model: Any = None
mlx_tokenizer: Any = None
mlx_model_id: str | None = None
mlx_lock = threading.Lock()


def load_mlx():
    global mlx_mod
    if mlx_mod:
        return
    from mlx_lm import load, generate
    from mlx_lm.sample_utils import make_sampler

    mlx_mod = type(
        "MLX", (), {"load": load, "generate": generate, "make_sampler": make_sampler}
    )


def get_mlx_model(model_id: str):
    global mlx_model, mlx_tokenizer, mlx_model_id
    load_mlx()
    if mlx_model is None or mlx_model_id != model_id:
        log.info("loading MLX model: %s", model_id)
        mlx_model, mlx_tokenizer = mlx_mod.load(model_id)
        mlx_model_id = model_id
        log.info("MLX model ready")
    return mlx_model, mlx_tokenizer


def parse_tool_calls(text: str) -> list[dict] | None:
    matches = re.findall(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", text, re.DOTALL)
    if not matches:
        return None
    calls = []
    for raw in matches:
        try:
            data = json.loads(raw)
            calls.append(
                {
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": data.get("name", ""),
                        "arguments": json.dumps(data.get("arguments", {})),
                    },
                }
            )
        except json.JSONDecodeError:
            continue
    return calls or None


def mlx_generate(
    model_id: str,
    messages: list[dict],
    max_tokens: int = 2048,
    temperature: float = 0.0,
) -> dict:
    with mlx_lock:  # mlx is not thread-safe; serialize Metal command buffers
        model, tok = get_mlx_model(model_id)
        prompt = tok.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        sampler = mlx_mod.make_sampler(temp=temperature)
        text = mlx_mod.generate(
            model, tok, prompt=prompt, max_tokens=max_tokens, sampler=sampler
        )
    tools = parse_tool_calls(text)
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model_id,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None if tools else text,
                    "tool_calls": tools,
                },
                "finish_reason": "tool_calls" if tools else "stop",
            }
        ],
        "usage": {},
    }


# process management
@dataclass(slots=True)
class Handle:
    name: str
    proc: subprocess.Popen | None = None
    shutdown: Callable[[], None] | None = None


def venv_bin() -> str:
    return os.path.dirname(sys.executable)


def start_process(
    name: str, cmd: list[str], env: dict[str, str] | None = None
) -> Handle:
    merged = {**os.environ, **(env or {})}
    path = merged.get("PATH", "")
    vbin = venv_bin()
    if vbin not in path:
        merged["PATH"] = f"{vbin}:{path}"
    proc = subprocess.Popen(cmd, env=merged)
    log.info("%s started (pid=%s)", name, proc.pid)
    return Handle(name=name, proc=proc)


def stop(h: Handle) -> None:
    if h.proc and h.proc.poll() is None:
        h.proc.terminate()
        try:
            h.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            h.proc.kill()
    if h.shutdown:
        try:
            h.shutdown()
        except Exception:
            log.exception("error stopping %s", h.name)


# backend servers
def start_mlx_server(host: str, port: int, model_id: str) -> Handle:
    class H(JsonHandler):
        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            body, err = self._json_body()
            if err:
                self.send_error(400, err)
                return
            try:
                resp = mlx_generate(
                    model_id,
                    body.get("messages", []),
                    int(body.get("max_tokens", 2048)),
                    float(body.get("temperature", 0.0)),
                )
                self._write_json(200, resp)
            except Exception:
                log.exception("MLX error")
                self.send_error(500)

        def do_GET(self):
            if self.path == "/v1/models":
                self._write_json(
                    200,
                    {
                        "object": "list",
                        "data": [{"id": model_id, "object": "model"}],
                    },
                )
            elif self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_error(404)

    httpd = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=httpd.serve_forever, daemon=True, name="mlx").start()
    log.info("mlx: http://%s:%s/v1", host, port)
    return Handle(name="mlx", shutdown=httpd.shutdown)


def start_tensorrt(host: str, port: int, model_id: str) -> Handle:
    cc = compute_capability()
    if not cc or cc < 8.0:
        raise RuntimeError("TensorRT requires CC >= 8.0")
    if not shutil.which("trtllm-serve"):
        raise RuntimeError("trtllm-serve not found")
    cmd = [
        "trtllm-serve",
        "--model",
        model_id,
        "--host",
        host,
        "--port",
        str(port),
        "--max_seq_len",
        os.getenv("MAX_MODEL_LEN", "8192"),
        "--tp_size",
        os.getenv("TENSOR_PARALLEL_SIZE", "1"),
        "--backend",
        os.getenv("TENSORRT_BACKEND", "pytorch"),
    ]
    return start_process("tensorrt", cmd)


def start_vllm(
    host: str, port: int, model_id: str, device: str | None = None
) -> Handle:
    selected_device = device or "auto"
    if selected_device == "cuda" and not has_cuda():
        log.warning("CUDA device requested but not available; switching to CPU")
        selected_device = "cpu"
    if selected_device == "rocm" and not has_rocm():
        log.warning("ROCm device requested but not available; switching to CPU")
        selected_device = "cpu"

    env: dict[str, str] = {}
    if selected_device == "rocm":
        env["VLLM_USE_ROCM"] = "1"

    cmd = [
        sys.executable,
        "-m",
        "vllm.entrypoints.openai.api_server",
        "--model",
        model_id,
        "--host",
        host,
        "--port",
        str(port),
        "--max-model-len",
        os.getenv("MAX_MODEL_LEN", "8192"),
        "--gpu-memory-utilization",
        os.getenv("GPU_MEMORY_UTIL", "0.90"),
        "--enable-auto-tool-choice",
        "--tool-call-parser",
        "hermes",
        "--trust-remote-code",
    ]
    cmd.extend(["--device", selected_device])
    return start_process("vllm", cmd, env=env)


def start_backend(
    kind: str, host: str, port: int, model_id: str, device: str | None = None
) -> Handle:
    if kind == "mlx":
        return start_mlx_server(host, port, model_id)
    if kind == "tensorrt":
        return start_tensorrt(host, port, model_id)
    if kind == "vllm":
        return start_vllm(host, port, model_id, device=device)
    raise RuntimeError(f"Unknown backend: {kind}")


# agent http server
class AgentRuntime:
    """runs agent coroutines on a dedicated event loop thread."""

    __slots__ = ("loop", "_thread")

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self.loop.run_forever, name="agent-loop", daemon=True
        )
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, Any]) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result()

    def close(self) -> None:
        if not self.loop.is_running():
            return

        def _cancel_pending() -> None:
            for task in asyncio.all_tasks(loop=self.loop):
                task.cancel()

        self.loop.call_soon_threadsafe(_cancel_pending)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5)


def create_agent_handler(client_id: str, runtime: AgentRuntime):
    from orchestration_layer import agent as agent_mod

    cid = client_id

    class H(JsonHandler):
        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            body, err = self._json_body()
            if err:
                self.send_error(400, err)
                return
            try:
                messages = body.get("messages", [])
                c = self.headers.get("X-Client-Id") or body.get("client_id") or cid
                result = runtime.run(agent_mod.chat_completion(messages, c))
                msg = result.get("message", {})
                resp = {
                    "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": agent_mod.LLM_MODEL,
                    "choices": [
                        {
                            "index": 0,
                            "message": msg,
                            "finish_reason": result.get("finish_reason", "stop"),
                        }
                    ],
                    "usage": {},
                }
                self._write_json(200, resp)
            except Exception as e:
                log.exception("agent error")
                self.send_error(500, str(e))

        def do_GET(self):
            if self.path == "/v1/models":
                data = [{"id": m["id"], "object": "model"} for m in _platform_models()]
                self._write_json(200, {"object": "list", "data": data})
            elif self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_error(404)

    return H


def start_agent_server(host: str, port: int, client_id: str) -> Handle:
    runtime = AgentRuntime()
    httpd = ThreadingHTTPServer((host, port), create_agent_handler(client_id, runtime))
    threading.Thread(target=httpd.serve_forever, daemon=True, name="agent").start()
    log.info("agent: http://%s:%s/v1", host, port)

    def shutdown() -> None:
        httpd.shutdown()
        runtime.close()

    return Handle(name="agent", shutdown=shutdown)


# main
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Terrabridge server")
    p.add_argument("--agent-host", default=os.getenv("AGENT_HOST", "0.0.0.0"))
    p.add_argument(
        "--agent-port", type=int, default=int(os.getenv("AGENT_PORT", "8000"))
    )
    p.add_argument("--llm-host", default=os.getenv("LLM_HOST", "0.0.0.0"))
    p.add_argument("--llm-port", type=int, default=int(os.getenv("LLM_PORT", "8002")))
    p.add_argument("--mcp-port", type=int, default=int(os.getenv("MCP_PORT", "8001")))
    p.add_argument("--model", default=os.getenv("LLM_MODEL"))
    p.add_argument("--client-id", default=os.getenv("CLIENT_ID", "default"))
    p.add_argument(
        "--interactive", "-i", action="store_true", help="Interactive model picker"
    )
    p.add_argument(
        "--log-level",
        default=os.getenv("LOG_LEVEL", "WARNING"),
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help="Logging verbosity (default WARNING).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    log_level = getattr(logging, args.log_level.upper(), logging.WARNING)
    logging.basicConfig(level=log_level, format="[%(name)s] %(message)s")

    try:
        backend, device = select_backend()
    except RuntimeError as e:
        log.error("failed to select backend: %s", e)
        return 1

    model = args.model or (
        pick_model_interactive() if args.interactive else default_model()
    )

    os.environ.setdefault("LLM_MODEL", model)
    os.environ.setdefault("OPENAI_API_KEY", "sk-local")
    os.environ.setdefault("OPENAI_API_BASE", f"http://127.0.0.1:{args.llm_port}/v1")
    os.environ.setdefault("MCP_SERVER_HOST_PORT", f"http://127.0.0.1:{args.mcp_port}")

    if device:
        log.info("backend=%s device=%s model=%s", backend, device, model)
    else:
        log.info("backend=%s model=%s", backend, model)
    log.info(
        "endpoints:\n"
        "  llm=http://%s:%s/v1\n"
        "  agent=http://%s:%s/v1\n"
        "  mcp=http://127.0.0.1:%s/mcp",
        args.llm_host,
        args.llm_port,
        args.agent_host,
        args.agent_port,
        args.mcp_port,
    )

    handles: list[Handle] = []
    stop_event = threading.Event()

    def on_signal(sig, _):
        log.info("signal %s, stopping...", sig)
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        handles.append(
            start_backend(backend, args.llm_host, args.llm_port, model, device=device)
        )
        handles.append(
            start_process(
                "mcp",
                ["mcp-server"],
                {"MCP_PORT": str(args.mcp_port), "MCP_HOST": "0.0.0.0"},
            )
        )
        handles.append(
            start_agent_server(args.agent_host, args.agent_port, args.client_id)
        )

        while not stop_event.wait(0.5):
            pass
    finally:
        for h in reversed(handles):
            stop(h)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
