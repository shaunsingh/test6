FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS base

ARG WITH_TENSORRT=0
ENV WITH_TENSORRT=${WITH_TENSORRT}

# build tools required for native deps
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential git cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1

# helper
RUN cat <<'EOF' >/usr/local/bin/uv-sync && chmod +x /usr/local/bin/uv-sync
#!/bin/sh
# dash on Debian/Ubuntu does not support pipefail
set -eu

BACKEND_EXTRA="vllm"
INDEX_ARGS=""
SOLVER_FLAGS=""

if [ "${WITH_TENSORRT:-0}" = "1" ]; then
  BACKEND_EXTRA="tensorrt"
  INDEX_ARGS="--extra-index-url https://pypi.nvidia.com"
  SOLVER_FLAGS="--prerelease allow --index-strategy unsafe-best-match"
fi

uv sync --group dev "$@" --extra "${BACKEND_EXTRA}" $INDEX_ARGS $SOLVER_FLAGS
EOF

# better caching
COPY pyproject.toml README.md ./
RUN uv-sync --no-install-project

# copy source and install project in editable mode
COPY . .
RUN uv-sync

EXPOSE 8000 8001 8002
CMD ["uv", "run", "server"]