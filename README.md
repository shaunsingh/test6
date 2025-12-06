# Terrabridge MCP Server

On-premise Agentic AI System using Model Context Protocol (MCP) for DMS, Cassandra integration, & ISO 27001 Compliance Monitoring

## Quick Start

Ports:
- Agent API: `http://localhost:8000/v1`
- MCP: `http://localhost:8001/mcp`
- LLM backend: `http://localhost:8002/v1`
- Open WebUI: `http://localhost:3000` (state in `.open-webui-data`, override with `DATA_DIR`)

### Option 1: Nix (Recommended)

Install Nix using [Determinate Nix](https://docs.determinate.systems)

```bash
# with WebUI
nix run

# without WebUI
nix run .#headless       # macOS: MLX headless, Linux: vLLM headless
nix run .#mcp-server     # MCP-only (defaults: MLX on macOS, vLLM on Linux)
nix run .#agent          # Agent-only (defaults: MLX on macOS, vLLM on Linux)

# Linux TensorRT variants (Ampere+)
nix run .#tensorrt
nix run .#tensorrt-headless

# Service-only launchers, aliases
nix run .#vllm-headless
nix run .#vllm-mcp-server
nix run .#vllm-agent
```

To launch development shell

```bash
nix develop          # Enter dev shell with all dependencies
uv sync              # Sync Python deps (already done by Nix)
```

### Option 2: UV Only

Install [UV](https://docs.astral.sh/uv/getting-started/installation/)

```bash
# Install dependencies (choose one)
# macOS (MLX base, no extras needed)
uv sync

# Linux vLLM (default)
WITH_TENSORRT=0 uv sync --extra vllm

# Linux TensorRT (Ampere+)
WITH_TENSORRT=1 UV_EXTRA_INDEX_URL=https://pypi.nvidia.com uv sync --extra tensorrt

# Run (uses whichever backend was installed)
uv run server

# Or run individual services:
uv run mcp-server           # MCP protocol layer only
uv run agent                # Orchestration agent only
```

### Option 3: Docker (Linux)

GPU build (TensorRT or vLLM) — requires NVIDIA runtime and driver:

Note: Uses Python 3.12 for TensorRT availability rather than 3.13, Nix users 3.13 to reduce duplication w/ openwebui deps

```bash
# vLLM (default, WITH_TENSORRT=0)
docker build --platform=linux/amd64 -t terrabridge-mcp:gpu-amd64 .

# TensorRT-LLM (Ampere+, WITH_TENSORRT=1)
docker build --platform=linux/amd64 --build-arg WITH_TENSORRT=1 -t terrabridge-mcp:gpu-amd64 .

docker run --platform=linux/amd64 --name terrabridge-mcp -d \
  -p 8000:8000 -p 8001:8001 -p 8002:8002 -p 3000:3000 \
  --gpus all \
  terrabridge-mcp:gpu-amd64
```

testing dont use

```bash
docker build -f Dockerfile.nix --platform=linux/amd64 -t terrabridge-mcp:nix .
docker build -f Dockerfile.nix --build-arg WITH_TENSORRT=1 --platform=linux/amd64 -t terrabridge-mcp:nix-trt .
docker run --rm -p 8000-8002:8000-8002 terrabridge-mcp:nix
```

## Architecture

```
                              ┌──────────────────────────────────────┐
                              │        Linux Machines (Sensors)      │
                              │  ┌────────────────────────────────┐  │
                              │  │   compliance-sensor (systemd)  │  │
                              │  │   - System Config Scanner      │  │
                              │  │   - Audit Log Tailer           │  │
                              │  │   - Vulnerability Checks       │  │
                              │  └────────────────┬───────────────┘  │
                              └───────────────────┼──────────────────┘
                                                  │ HTTP POST (JSON)
┌─────────────────────────────────────────────────┼─────────────────────────────┐
│                    Orchestration Layer          │                             │
│              (Pure async Python agent)          │                             │
└─────────────────────┬───────────────────────────┼─────────────────────────────┘
                      │ HTTP/JSON-RPC             │
┌─────────────────────▼───────────────────────────▼─────────────────────────────┐
│                           Protocol Layer                                      │
│                    (FastMCP Server @ :8001)                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────────────┐   │
│  │  DMS Tools   │  │   DB Tools   │  │   Compliance (Rulebook + DB + AI)  │   │
│  └──────────────┘  └──────────────┘  └────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────────────────────┐
│                            Serving Layer                                        │
│                  (OpenAI-compatible API @ :8000)                                │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐  ┌───────────┐  │
│  │   TensorRT-LLM           │  │         vLLM                 │  │    MLX    │  │
│  │   (Ampere+ GPUs, CC≥8.0) │  │   (older GPUs, fallback)     │  │  (macOS)  │  │
│  └──────────────────────────┘  └──────────────────────────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Model:** IBM Granite 4.0 Micro 3b

## Stack

- **Package Management:** Nix Flakes + UV
- **MCP Server:** FastMCP
- **Database:** Apache Cassandra
- **Validation:** Pydantic
- **LLM Serving (Linux):** TensorRT-LLM (Ampere+ opt-in) / vLLM 0.12.0 (default)
- **LLM Serving (macOS):** MLX (local dev)

## Operational Targets

- **System latency:** < 3 seconds end-to-end for standard prompts (e.g., “Get profile” or “get me docs”), measured from orchestrator receive → final answer
- **Detection latency:** Compliance sensors push critical findings to the MCP server in < 5 minutes
- **ISO coverage:** ≥ 15 ISO 27001 Annex A technical controls continuously mapped to machine telemetry
- **Reporting automation:** Daily fleet and machine reports are generated without manual steps

Uses `.env` for configuration, maps `8000/8001/8002` from the container, and expects NVIDIA GPUs when available (see `deploy.resources` in `compose.yaml`).

## Config

Create `.env` in project root:

```ini
# LLM Configuration
OPENAI_API_BASE=http://localhost:8000/v1
OPENAI_API_KEY=EMPTY
LLM_MODEL=ibm-granite/granite-4.0-h-micro

# MCP Server
MCP_SERVER_HOST_PORT=http://localhost:8001

# DMS API
DMS_API_BASE_URL=http://YOUR_DMS_IP:PORT

# Keycloak Auth
KEYCLOAK_URL=http://YOUR_KEYCLOAK_IP:PORT
KEYCLOAK_REALM=your_realm
DMS_CLIENT_ID=your-service-account-client-id
DMS_CLIENT_SECRET=your-service-account-client-secret

# Cassandra
CASSANDRA_CONTACT_POINTS=localhost:9042
CASSANDRA_KEYSPACE=claims_app
CASSANDRA_USERNAME=cassandra
CASSANDRA_PASSWORD=cassandra
```

### Serving Layer Options

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_MODEL` | platform default (`mlx` model on macOS, Granite on Linux) | Model ID |
| `LLM_HOST` | `0.0.0.0` | LLM backend bind address |
| `LLM_PORT` | `8002` | LLM backend port |
| `AGENT_HOST` | `0.0.0.0` | Agent HTTP bind address |
| `AGENT_PORT` | `8000` | Agent HTTP port |
| `MCP_PORT` | `8001` | MCP server port |
| `MAX_MODEL_LEN` | `8192` | Max sequence length |
| `GPU_MEMORY_UTIL` | `0.90` | GPU memory utilization (vLLM) |
| `TENSOR_PARALLEL_SIZE` | `1` | Tensor parallelism (TensorRT) |

## GPU Support

| GPU Generation | Compute Capability | Inference Engine |
|----------------|-------------------|------------------|
| Ampere (A100, RTX 30xx) | 8.0+ | TensorRT-LLM |
| Ada (RTX 40xx) | 8.9 | TensorRT-LLM |
| Hopper (H100) | 9.0 | TensorRT-LLM |
| Turing (RTX 20xx) | 7.5 | vLLM |
| Volta (V100) | 7.0 | vLLM |
| Pascal (P100) | 6.0 | vLLM |
| Any Apple Silicon Mac | N/A | MLX |

> **Note:** TensorRT-LLM is an **optional dependency**. Choose exactly one:
> ```bash
> WITH_TENSORRT=0 uv sync --extra vllm                                  # default, installs vLLM 0.12.0
> WITH_TENSORRT=1 UV_EXTRA_INDEX_URL=https://pypi.nvidia.com uv sync --extra tensorrt  # Ampere+ TensorRT-LLM
> ```
> On Linux, the serving layer uses TensorRT when `WITH_TENSORRT=1` **and** both `tensorrt_llm`
> and `trtllm-serve` are available with GPU compute capability ≥ 8.0; otherwise it falls back to vLLM.

## MCP Tools

### DMS Tools
- `login_service_account` - Keycloak client credentials auth
- `search_documents` - Search documents with filters

### Cassandra Tools
- `db_schema_overview` - Get keyspace schema (tables, columns, keys)
- `db_schema_relations` - Infer table relationships
- `db_execute_cql` - Execute read-only CQL queries

### Compliance Tools (ISO 27001)
- `ingest_compliance_scan` - Receive scan results from sensors
- `ingest_security_events` - Receive audit log events
- `ingest_critical_alert` - Receive critical security alerts
- `get_compliance_status` - Get compliance status for a machine
- `get_fleet_status` - Get compliance across all machines
- `get_security_events` - Query security events
- `get_unacknowledged_alerts` - Get pending alerts
- `acknowledge_alert` - Acknowledge a critical alert
- `get_compliance_history` - Get compliance trends
- `generate_compliance_report` - Generate JSON/HTML reports
- `analyze_compliance_ai` - AI-powered compliance analysis
- `get_iso_control_info` - Query ISO 27001 control reference
- `get_failing_controls_detail` - Get detailed failure information

## Client Subscription Controls

`orchestration_layer/agent.py` enforces which MCP tools each customer can see. Set `CLIENT_ID` before launching the agent:

```bash
CLIENT_ID=compliance-client uv run agent
```

Built-in subscriptions:

| Client ID | Tools |
|-----------|-------|
| `admin` | All tools (`*`) |
| `dms-client` | `login_service_account`, `search_documents`, `get_user_profile`, etc. |
| `compliance-client` | All compliance ingestion/reporting tools only |
| `db-client` | Cassandra schema + read-only query tools |
| `default` | Minimal read-only set (`get_compliance_status`, `get_fleet_status`, `search_documents`) |

Update `CLIENT_TOOL_SUBSCRIPTIONS` in the agent to add or remove entries. The protocol layer still hosts the full catalog, but orchestration filters discovery responses and blocks unauthorized `tools/call` requests, so each tenant only sees what they subscribe to.

## Project Structure

```
├── orchestration_layer/
│   └── agent.py              # Async agent with tool calling
├── protocol_layer/
│   ├── server.py             # FastMCP server entry
│   └── tools/
│       ├── dms.py            # DMS API tools
│       ├── cassandra.py      # Cassandra tools
│       └── compliance/       # ISO 27001 DB + rulebook + tooling
│           ├── __init__.py
│           ├── database.py
│           ├── evaluator.py
│           ├── iso_rules.py
│           └── reports.py
├── sensor_layer/
│   ├── scanner.py            # System compliance scanner (16 controls)
│   ├── log_tailer.py         # Audit log monitoring
│   ├── broadcaster.py        # MCP server data transmission
│   ├── install.sh            # Linux sensor installation script
│   └── compliance-sensor.service  # systemd unit file
├── serving_layer/
│   └── server.py             # Unified backend + MCP + agent HTTP front-end
├── pyproject.toml            # Python dependencies
├── flake.nix                 # Nix flake (reproducible builds)
└── compose.yaml              # Docker Compose (alternative)
```

## Commands Reference

### Nix

```bash
nix run                  # Default: macOS MLX or Linux vLLM + Open WebUI
nix run .#headless       # Headless (macOS MLX default, Linux vLLM headless)
nix run .#mcp-server     # MCP-only (macOS MLX default, Linux vLLM)
nix run .#agent          # Agent-only (macOS MLX default, Linux vLLM)
nix run .#tensorrt       # Linux TensorRT + Open WebUI (Ampere+)
nix run .#tensorrt-headless # Linux TensorRT headless
nix develop              # Dev shell
nix flake check          # Run tests
```

### UV

```bash
uv sync                  # Install dependencies
uv run server            # Full stack (backend auto-select)
uv run mcp-server        # MCP protocol layer only
uv run agent             # Agent CLI only
uv add <package>         # Add dependency

# Compliance monitoring
uv run compliance-scan   # Run single compliance scan (outputs JSON)
uv run compliance-sensor # Run continuous sensor (for target machines)
```

## Testing

```bash
# via nix
nix flake check

# via UV
uv run --group test pytest -q
```

## ISO 27001 Compliance Monitoring

The compliance monitoring system provides automated security compliance checking against ISO 27001:2022 Annex A controls.

### Monitored Controls (16 Technical Controls)

| Control | ISO Clause | Description |
|---------|------------|-------------|
| SSH Root Login | A.9.2.3 | Checks if root login via SSH is disabled |
| Password Complexity | A.9.4.3 | Validates password policy (minlen, complexity) |
| Sudo Configuration | A.9.2.3 | Checks sudo security (NOPASSWD, etc.) |
| Empty Passwords | A.9.4.3 | Detects accounts without passwords |
| Password Aging | A.9.4.3 | Validates password expiration policy |
| Audit Daemon | A.12.4.1 | Checks if auditd is running/enabled |
| Syslog Config | A.12.4.1 | Validates logging configuration |
| Log Permissions | A.12.4.3 | Checks log file access controls |
| Audit Rules | A.12.4.1 | Validates audit monitoring rules |
| Firewall Status | A.13.1.1 | Checks if firewall is active |
| Open Ports | A.13.1.1 | Identifies dangerous open ports |
| SSH Protocol | A.13.1.1 | Validates SSH cipher configuration |
| Kernel Parameters | A.14.2.5 | Checks security sysctl settings |
| File Permissions | A.14.2.5 | Validates critical file permissions |
| SELinux/AppArmor | A.14.2.5 | Checks mandatory access control |
| Auto Updates | A.12.6.1 | Validates automatic security updates |

### Sensor Deployment

Deploy the compliance sensor on Linux machines to monitor:

```bash
# On target Linux machine (Ubuntu/RHEL/CentOS)
sudo ./sensor_layer/install.sh

# Configure MCP server URL
sudo nano /etc/terrabridge/sensor.env

# Start the sensor
sudo systemctl start compliance-sensor
sudo systemctl enable compliance-sensor

# View logs
sudo journalctl -u compliance-sensor -f
```

### Configuration (Sensor)

Create `/etc/terrabridge/sensor.env`:

```ini
# MCP Server URL (required)
MCP_SERVER_URL=http://your-mcp-server:8001

# Scan intervals (seconds)
SENSOR_SCAN_INTERVAL=900      # Full compliance scan every 15 min
SENSOR_CRITICAL_INTERVAL=300   # Critical event check every 5 min

# Optional authentication
SENSOR_API_KEY=your-api-key
```

### Report Generation

```bash
# Generate daily fleet report (via agent or API)
curl -X POST http://localhost:8001/mcp -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "generate_compliance_report",
    "arguments": {"report_type": "daily", "format": "json"}
  }
}'

# Generate HTML report for specific machine
curl -X POST http://localhost:8001/mcp -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "generate_compliance_report",
    "arguments": {"hostname": "server1", "report_type": "machine", "format": "html"}
  }
}'
```

### Compliance Flow

```
┌─────────────────┐    Every 15min    ┌──────────────────┐
│  Linux Server   │ ───────────────▶  │   MCP Server     │
│  (Sensor)       │   JSON scan data  │                  │
│                 │                   │  ┌────────────┐  │
│  - auditd       │                   │  │ Compliance │  │
│  - sshd_config  │                   │  │    DB      │  │
│  - /etc/passwd  │                   │  └────────────┘  │
│  - firewall     │                   │        │         │
│  - sysctl       │   Critical alert  │        ▼         │
│                 │ ◀─────────────────│  ┌────────────┐  │
│                 │   (< 5 min SLA)   │  │ ISO 27001  │  │
└─────────────────┘                   │  │ Rule Book  │  │
                                      │  └────────────┘  │
                                      │        │         │
        ┌─────────────────────────────┼────────┘         │
        │                             │                  │
        ▼                             │                  │
┌─────────────────┐                   │  ┌────────────┐  │
│  AI Analysis    │ ◀─────────────────┼──│    LLM     │  │
│  - Risk Level   │                   │  │ (Granite)  │  │
│  - Remediation  │                   │  └────────────┘  │
│  - IoC Detection│                   │                  │
└─────────────────┘                   └──────────────────┘
        │
        ▼
┌─────────────────┐
│  Reports        │
│  - Daily PDF    │
│  - Fleet Status │
│  - Audit Trail  │
└─────────────────┘
```

### Database Schema

The compliance database (SQLite by default) stores:

- machines: Registered machine inventory
- compliance_scans: Historical scan results
- control_results: Individual control check outcomes
- security_events: Audit log events
- critical_alerts: Alerts requiring acknowledgment
- compliance_reports: Generated reports

see `./out/*.html` for sample reports# test6
