{
  description = "terrabridge mcp server";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{
    self,
    nixpkgs,
    flake-parts,
    pyproject-nix,
    uv2nix,
    pyproject-build-systems,
    ...
  }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;

      perSystem =
        { system, lib, ... }:
        let
          ignoreNames = [
            ".git"
            ".direnv"
            ".venv"
            "venv"
            "result"
            "results"
            "__pycache__"
            ".mypy_cache"
            ".pytest_cache"
            ".ruff_cache"
            ".idea"
            ".vscode"
            "dist"
            "build"
            ".coverage"
          ];

          workspaceRoot = lib.cleanSourceWith {
            src = ./.;
            filter =
              name: type:
              let base = builtins.baseNameOf name; in
              !lib.elem base ignoreNames;
          };

          workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };
          baseDeps = workspace.deps.default;

          withExtra =
            extras:
            baseDeps // {
              "terrabridge-mcp" = (baseDeps."terrabridge-mcp" or [ ]) ++ extras;
            };

          deps = {
            base = withExtra [ "vllm" ];
            vllm = withExtra [ "vllm" ];
            tensorrt = withExtra [ "tensorrt" ];
          };

          pkgs =
            import nixpkgs {
              inherit system;
              config = { 
                allowUnfree = true;
                cudaSupport = true;
              };
              overlays = [
                (
                  final: prev: {
                    python313Packages = prev.python313Packages.overrideScope (
                      _: p: {
                        pgvector = p.pgvector.overridePythonAttrs (_: { doCheck = false; });
                      }
                    );
                    open-webui = prev.open-webui.overrideAttrs (old: {
                      meta = (old.meta or { }) // { broken = false; };
                    });
                  }
                )
              ];
            };

          depsForSystem = if pkgs.stdenv.isLinux then deps.vllm else deps.base;

          pythonOverlays = [
            pyproject-build-systems.overlays.default
            (workspace.mkPyprojectOverlay {
              sourcePreference = "wheel";
              dependencies = depsForSystem;
            })
            (
              final: prev:
              let
                inherit (pkgs) stdenv;
                cudaLibs = lib.optionals stdenv.isLinux (
                  with pkgs.cudaPackages_12;
                  [
                    libcufft
                    libcurand
                    libcusparse
                    libcublas
                    libnvjitlink
                    nccl
                    cudnn
                    libcusolver
                  ]
                );
                addCuda = deps: deps ++ cudaLibs;
              in
              {
                "cupy-cuda12x" =
                  prev."cupy-cuda12x".overrideAttrs (old:
                    lib.optionalAttrs stdenv.isLinux {
                      nativeBuildInputs = addCuda (old.nativeBuildInputs or [ ]);
                      buildInputs = addCuda (old.buildInputs or [ ]);
                      propagatedBuildInputs = addCuda (old.propagatedBuildInputs or [ ]);
                    }
                  );

                "nvidia-cufile-cu12" =
                  prev."nvidia-cufile-cu12".overrideAttrs (old:
                    lib.optionalAttrs stdenv.isLinux {
                      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.autoPatchelfHook ];
                      buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.rdma-core ];
                      propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ [ pkgs.rdma-core ];
                      autoPatchelfExtraLibs = (old.autoPatchelfExtraLibs or [ ]) ++ [ "${pkgs.rdma-core}/lib" ];
                    }
                  );

                "nvidia-cusparse-cu12" =
                  prev."nvidia-cusparse-cu12".overrideAttrs (old:
                    lib.optionalAttrs stdenv.isLinux {
                      nativeBuildInputs = addCuda (old.nativeBuildInputs or [ ]);
                      buildInputs = addCuda (old.buildInputs or [ ]);
                      propagatedBuildInputs = addCuda (old.propagatedBuildInputs or [ ]);
                    }
                  );

                "nvidia-cusolver-cu12" =
                  prev."nvidia-cusolver-cu12".overrideAttrs (old:
                    lib.optionalAttrs stdenv.isLinux {
                      nativeBuildInputs = addCuda (old.nativeBuildInputs or [ ]);
                      buildInputs = addCuda (old.buildInputs or [ ]);
                      propagatedBuildInputs = addCuda (old.propagatedBuildInputs or [ ]);
                    }
                  );

                "nvidia-cutlass-dsl" =
                  prev."nvidia-cutlass-dsl".overrideAttrs (old:
                    lib.optionalAttrs stdenv.isLinux {
                      nativeBuildInputs = addCuda (old.nativeBuildInputs or [ ]);
                      buildInputs = addCuda (old.buildInputs or [ ]);
                      propagatedBuildInputs = addCuda (old.propagatedBuildInputs or [ ]);
                    }
                  );

                "numba" =
                  prev."numba".overrideAttrs (old:
                    lib.optionalAttrs stdenv.isLinux {
                      nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.autoPatchelfHook ];
                      buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.tbb ];
                      propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ [ pkgs.tbb ];
                      autoPatchelfExtraLibs = (old.autoPatchelfExtraLibs or [ ]) ++ [ "${pkgs.tbb}/lib" ];
                    }
                  );

                "terrabridge-mcp" = prev."terrabridge-mcp".overrideAttrs (old: {
                  passthru = (old.passthru or { }) // {
                    tests = (old.tests or { }) // {
                      pytest = pkgs.stdenv.mkDerivation {
                        name = "${final."terrabridge-mcp".name}-pytest";
                        src = final."terrabridge-mcp".src;
                        nativeBuildInputs = [
                          (final.mkVirtualEnv "test-env" { "terrabridge-mcp" = [ "test" ]; })
                        ];
                        dontConfigure = true;
                        buildPhase = "runHook preBuild; SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt pytest -q; runHook postBuild";
                        installPhase = "mkdir -p $out";
                      };
                    };
                  };
                });
              }
            )
          ];

          pyprojectPackages = pkgs.callPackage pyproject-nix.build.packages { python = pkgs.python313; };
          pythonSet = pyprojectPackages.overrideScope (lib.composeManyExtensions pythonOverlays);

          mkEnv = name: deps: pythonSet.mkVirtualEnv name deps;

          baseEnv = mkEnv "mcp-env-base" depsForSystem;
          vllmEnv = if pkgs.stdenv.isLinux then mkEnv "mcp-env-vllm" deps.vllm else null;
          trtEnv = if pkgs.stdenv.isLinux then mkEnv "mcp-env-tensorrt" deps.tensorrt else null;

          mkLauncher =
            {
              name,
              venv,
              withWebui ? true,
              withTensorRT ? false,
              entry ? "server",
            }:
            let
              mlxLib = "${venv}/lib/${pkgs.python313.libPrefix}/site-packages/mlx/lib";
              baseEnv =
                ''
                  : "''${MCP_PORT:=8001}" "''${AGENT_PORT:=8000}" "''${LLM_PORT:=8002}" "''${WEBUI_PORT:=3000}"
                  : "''${CLIENT_ID:=default}" "''${DATA_DIR:=$PWD/.open-webui-data}"
                  ${lib.optionalString pkgs.stdenv.isDarwin ''
                    export DYLD_LIBRARY_PATH="${mlxLib}''${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
                    export MLX_LIBRARY_PATH="${mlxLib}"
                    : "''${LLM_MODEL:=mlx-community/granite-4.0-h-micro-4bit}"
                  ''}
                  ${lib.optionalString pkgs.stdenv.isLinux ''
                    : "''${LLM_MODEL:=ibm-granite/granite-4.0-h-micro}"
                  ''}
                  export LLM_MODEL MCP_PORT AGENT_PORT LLM_PORT CLIENT_ID
                  export WITH_TENSORRT=${if withTensorRT then "1" else "0"}
                '';
            in
            pkgs.writeShellScriptBin name (
              ''
                set -euo pipefail
                ${baseEnv}
              ''
              + lib.optionalString (!withWebui && entry == "server") ''
                exec ${venv}/bin/server --agent-port "$AGENT_PORT" --llm-port "$LLM_PORT" --mcp-port "$MCP_PORT" --client-id "$CLIENT_ID"
              ''
              + lib.optionalString (!withWebui && entry == "mcp-server") ''
                exec ${venv}/bin/mcp-server --mcp-port "$MCP_PORT"
              ''
              + lib.optionalString (!withWebui && entry == "agent") ''
                exec ${venv}/bin/agent --agent-port "$AGENT_PORT" --llm-port "$LLM_PORT" --mcp-port "$MCP_PORT" --client-id "$CLIENT_ID"
              ''
              + lib.optionalString withWebui ''
                cleanup() { echo; echo "[terrabridge] stopping..."; kill "$SERVER_PID" "$WEBUI_PID" 2>/dev/null || true; wait 2>/dev/null || true; }
                trap cleanup EXIT INT TERM

                echo "╔═══════════════════════════════════════════════════════════════╗"
                echo "║              Terrabridge MCP + Open WebUI                     ║"
                echo "╚═══════════════════════════════════════════════════════════════╝"
                echo

                echo "[1/2] Starting server..."
                ${venv}/bin/server --agent-port "$AGENT_PORT" --llm-port "$LLM_PORT" --mcp-port "$MCP_PORT" --client-id "$CLIENT_ID" &
                SERVER_PID=$!
                sleep 4

                echo "[2/2] Starting Open WebUI..."
                mkdir -p "$DATA_DIR"
                export OPENAI_API_BASE="http://localhost:$AGENT_PORT/v1"
                export OPENAI_API_BASE_URLS="http://localhost:$AGENT_PORT/v1"
                export OPENAI_API_KEY="''${OPENAI_API_KEY:-sk-local}"
                export ENABLE_OLLAMA_API=false WEBUI_AUTH=false DATA_DIR
                export OPENWEBUI_ENABLE_USER_MEMORY=true
                export TOOL_SERVER_CONNECTIONS='[{"type":"mcp","url":"http://localhost:'"$MCP_PORT"'/mcp","path":"/mcp","auth_type":"none","info":{"id":"terrabridge-mcp","name":"Terrabridge MCP"},"config":{"enable":true}}]'
                ${pkgs.open-webui}/bin/open-webui serve --port "$WEBUI_PORT" 2>&1 | grep -v "Permission denied" &
                WEBUI_PID=$!
                echo
                echo "[2/2] Waiting for Open WebUI to be ready..."
                start_wait=$(date +%s)
                timeout=120
                while true; do
                  if ${pkgs.curl}/bin/curl -sf "http://localhost:$WEBUI_PORT/api/version" >/dev/null 2>/dev/null; then
                    break
                  fi
                  if ! kill -0 "$WEBUI_PID" 2>/dev/null; then
                    echo "[error] Open WebUI exited before becoming ready" >&2
                    exit 1
                  fi
                  now=$(date +%s)
                  if [ $((now - start_wait)) -ge $timeout ]; then
                    echo "[error] Open WebUI did not become ready within ''${timeout}s" >&2
                    exit 1
                  fi
                  sleep 1
                done

                echo
                echo "✓ Ready"
                echo "  Open WebUI: http://localhost:$WEBUI_PORT"
                echo "  Agent API:  http://localhost:$AGENT_PORT/v1"
                echo "  MCP:        http://localhost:$MCP_PORT/mcp"
                echo "  LLM:        http://localhost:$LLM_PORT/v1"
                echo "  Model:      $LLM_MODEL"
                echo "  Backend:    ${if withTensorRT then "TensorRT-LLM" else "vLLM"}"
                echo
                echo "Ctrl+C to stop"
                wait
              ''
            );

          backendEnv =
            backend:
            if backend == "tensorrt" then
              trtEnv
            else if backend == "vllm" then
              vllmEnv
            else
              baseEnv;

          mkApp =
            {
              label,
              backend ? "base",
              webui ? true,
              entry ? "server",
            }:
            let
              venv = backendEnv backend;
              drv = mkLauncher {
                name = label;
                inherit venv entry;
                withWebui = webui;
                withTensorRT = backend == "tensorrt";
              };
            in
            {
              type = "app";
              program = "${drv}/bin/${label}";
              meta = {
                description = "Terrabridge launcher (${label}, backend=${backend}, webui=${if webui then "on" else "off"})";
              };
            };

          coreBackend = if pkgs.stdenv.isLinux && vllmEnv != null then "vllm" else "base";

          coreApps = {
            default = mkApp {
              label = "terrabridge";
              backend = coreBackend;
              webui = true;
              entry = "server";
            };
            headless = mkApp {
              label = "terrabridge-headless";
              backend = coreBackend;
              webui = false;
              entry = "server";
            };
            mcp-server = mkApp {
              label = "terrabridge-mcp";
              backend = coreBackend;
              webui = false;
              entry = "mcp-server";
            };
            agent = mkApp {
              label = "terrabridge-agent";
              backend = coreBackend;
              webui = false;
              entry = "agent";
            };
          };

          vllmApps = lib.optionalAttrs (pkgs.stdenv.isLinux && vllmEnv != null) (rec {
            vllm-headless = mkApp {
              label = "terrabridge-headless";
              backend = "vllm";
              webui = false;
              entry = "server";
            };
            vllm-mcp-server = mkApp {
              label = "terrabridge-mcp";
              backend = "vllm";
              webui = false;
              entry = "mcp-server";
            };
            vllm-agent = mkApp {
              label = "terrabridge-agent";
              backend = "vllm";
              webui = false;
              entry = "agent";
            };
          });

          tensorrtApps = lib.optionalAttrs (pkgs.stdenv.isLinux && trtEnv != null) (rec {
            tensorrt = mkApp {
              label = "terrabridge-trt";
              backend = "tensorrt";
              webui = true;
              entry = "server";
            };
            tensorrt-headless = mkApp {
              label = "terrabridge-trt-headless";
              backend = "tensorrt";
              webui = false;
              entry = "server";
            };
            tensorrt-mcp-server = mkApp {
              label = "terrabridge-trt-mcp";
              backend = "tensorrt";
              webui = false;
              entry = "mcp-server";
            };
            tensorrt-agent = mkApp {
              label = "terrabridge-trt-agent";
              backend = "tensorrt";
              webui = false;
              entry = "agent";
            };
          });
        in
        {
          packages =
            {
              base = baseEnv;
              default = if vllmEnv != null then vllmEnv else baseEnv;
            }
            // lib.optionalAttrs (vllmEnv != null) { vllm = vllmEnv; }
            // lib.optionalAttrs (trtEnv != null) { tensorrt = trtEnv; };

          devShells.default = pkgs.mkShell {
            packages = [
              (mkEnv "dev-env" depsForSystem)
              pkgs.uv
              pkgs.black
            ];
            env = {
              UV_NO_SYNC = "1";
              UV_PYTHON_DOWNLOADS = "never";
            };
            shellHook = "unset PYTHONPATH; export REPO_ROOT=$(git rev-parse --show-toplevel)";
          };

          apps = coreApps // vllmApps // tensorrtApps;

          formatter = pkgs.nixfmt-rfc-style;
          checks.pytest = pythonSet."terrabridge-mcp".passthru.tests.pytest;
        };
    };
}
