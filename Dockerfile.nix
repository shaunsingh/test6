# syntax=docker/dockerfile:1.19
FROM nixos/nix:2.32.4
ARG WITH_TENSORRT=0

# disable sandboxing and seccomp filters for QEMU
RUN printf "experimental-features = nix-command flakes\naccept-flake-config = true\nsandbox = false\nfilter-syscalls = false\nwarn-dirty = false\n" > /etc/nix/nix.conf

WORKDIR /src
COPY --link . /src

# select backend from WITH_TENSORRT and build it if available
RUN --mount=type=cache,id=nix-profiles,target=/nix/var/nix/profiles/per-user/root \
    --mount=type=cache,id=nix-gcroots,target=/nix/var/nix/gcroots/per-user/root \
    --mount=type=cache,id=nix-cache,target=/root/.cache/nix \
    set -euo pipefail; \
    system="$(nix eval --impure --raw --expr 'builtins.currentSystem')"; \
    backend="vllm"; \
    if [ "${WITH_TENSORRT}" = "1" ]; then backend="tensorrt"; fi; \
    drv=".#packages.${system}.${backend}"; \
    if ! nix eval --quiet "$drv" >/dev/null 2>&1; then \
      echo "[terrabridge] backend '${backend}' not available; using base"; \
      drv=".#packages.${system}.base"; \
    fi; \
    echo "[terrabridge] system=${system} backend=${backend} drv=${drv}"; \
    nix build --print-build-logs "$drv" -o /app/env

WORKDIR /app
ENV PATH="/app/env/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    UV_NO_SYNC=1

EXPOSE 8000 8001 8002

# load everything
CMD ["server"]
