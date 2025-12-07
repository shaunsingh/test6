{
  description = "terrabridge mcp server";

  nixConfig = {
    extra-substituters = [
      "https://cache.flox.dev"
    ];
    extra-trusted-substituters = [
      "https://cache.flox.dev"
    ];
    extra-trusted-public-keys = [
      "flox-cache-public-1:7F4OyH7ZCnFhcze3fJdfyXYLQw/aV7GEed86nQ7IsOs="
    ];
  };

  inputs = {
    nixpkgs.url = "github:flox/nixpkgs/unstable";
    nixpkgs-24-05.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-parts.url = "github:hercules-ci/flake-parts";

    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

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

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      pyproject-nix,
      uv2nix,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { system, lib, ... }:
        let
          workspaceRoot = inputs.gitignore.lib.gitignoreSource ./.;
          workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };
          baseDeps = workspace.deps.default;

          withExtra =
            extras:
            baseDeps
            // {
              "terrabridge-mcp" = (baseDeps."terrabridge-mcp" or [ ]) ++ extras;
            };

          pkgsConfig = {
            allowUnfreePredicate =
              pkg:
              let
                rawLicenses = pkg.meta.license or null;
                licenses = lib.filter (x: x != null) (
                  if builtins.isList rawLicenses then rawLicenses else [ rawLicenses ]
                );
                allowedCudaLicenses = [
                  "Open WebUI License"
                  "CUDA EULA"
                  "cuDNN EULA"
                  "cuTENSOR EULA"
                  "cuSPARSELt EULA"
                  "NVidia OptiX EULA"
                ];
              in
              lib.all (
                license:
                (license.free or false)
                || lib.elem (license.shortName or license.fullName or license.name or "") allowedCudaLicenses
              ) licenses;
            cudaSupport = true;
            cudaVersion = "12";
          };

          overlays = [
            (final: prev: {
              python312Packages = prev.python312Packages.overrideScope (
                _: p: {
                  pgvector = p.pgvector.overridePythonAttrs (_: {
                    doCheck = false;
                  });
                }
              );
              open-webui =
                (import nixpkgs {
                  inherit system;
                  config = pkgsConfig // {
                    allowBroken = prev.stdenv.isDarwin;
                    allowUnsupportedSystem = prev.stdenv.isDarwin;
                  };
                }).open-webui;
            })
          ];

          mkPkgs =
            nixpkgsPath:
            import nixpkgsPath {
              inherit system;
              config = pkgsConfig;
              overlays = overlays;
            };

          pkgs = mkPkgs nixpkgs;
          legacyPkgs = mkPkgs inputs."nixpkgs-24-05";

          runtimeBackends = {
            vllm = {
              label = "vLLM";
              modelDefault = "ibm-granite/granite-4.0-h-micro";
              extras = [ "vllm" ];
            };
            tensorrt = {
              label = "TensorRT-LLM";
              modelDefault = "ibm-granite/granite-4.0-h-micro";
              extras = [ "tensorrt" ];
            };
            mlx = {
              label = "MLX";
              modelDefault = "mlx-community/granite-4.0-h-micro-4bit";
              extras = [ "mlx" ];
            };
          };

          baseRuntime = if pkgs.stdenv.isDarwin then "mlx" else "vllm";

          backendDefs = {
            mlx = {
              runtime = "mlx";
              attrPrefix = "mlx";
              labelPrefix = "terrabridge";
              supports = pkgs.stdenv.isDarwin;
            };
            vllm = {
              runtime = "vllm";
              attrPrefix = "vllm";
              labelPrefix = "terrabridge";
              supports = pkgs.stdenv.isLinux;
            };
            tensorrt = {
              runtime = "tensorrt";
              attrPrefix = "tensorrt";
              labelPrefix = "terrabridge-spark";
              supports = pkgs.stdenv.isLinux;
            };
          };

          runtimeCfgByBackend = lib.mapAttrs (_: cfg: runtimeBackends.${cfg.runtime}) backendDefs;

          mkBackend =
            name: { runtime, supports ? true, ... }@cfg:
            let
              runtimeCfg = runtimeCfgByBackend.${name};
            in
            runtimeCfg
            // cfg
            // {
              inherit name runtime supports;
              extras = runtimeCfg.extras;
            };

          backends = lib.mapAttrs mkBackend backendDefs;
          enabledBackends = lib.filterAttrs (_: backend: backend.supports) backends;

          deps = lib.mapAttrs (_: backend: withExtra backend.extras) enabledBackends;
          defaultDeps =
            lib.attrByPath
              [ baseRuntime ]
              (throw "Default backend ${baseRuntime} not enabled for ${system}.")
              deps;

          pythonOverlays = [
            inputs.pyproject-build-systems.overlays.default
            (workspace.mkPyprojectOverlay {
              sourcePreference = "wheel";
              dependencies = defaultDeps;
            })
            (
              final: prev:
              let
                cudaLibs = (with pkgs.cudaPackages_12; [
                  cudatoolkit
                  cuda_cudart
                  cuda_cupti
                  cuda_nvrtc
                  libcufft
                  libcurand
                  libcusparse
                  libcusparse_lt
                  libcublas
                  libcusolver
                  libcutensor
                  libnvjitlink
                  libcufile
                  libnvshmem
                  nccl
                  cudnn
                ]) ++ (with legacyPkgs.cudaPackages_12; [ 
                  cudnn 
                ]);
                cudaLibPaths = lib.concatMap (x: [
                  "${x}/lib"
                  "${x}/lib64"
                  "${x}/targets/x86_64-linux/lib"
                  "${x}/targets/aarch64-linux/lib"
                ]) cudaLibs;
                hpcLibs = [
                  pkgs.rdma-core
                  pkgs.openmpi
                  pkgs.ucx
                  pkgs.pmix
                  pkgs.libfabric
                ];
                hpcLibPaths = (map (x: "${x}/lib") hpcLibs) ++ (map (x: "${x}/lib64") hpcLibs);
                extendInputs =
                  additions: old:
                  old
                  // lib.mapAttrs (name: extra: (old.${name} or [ ]) ++ extra) additions;
                patchCuda =
                  pkg:
                  pkg.overrideAttrs (old: {
                      autoPatchelfExtraLibs = (old.autoPatchelfExtraLibs or [ ]) ++ cudaLibPaths;
                      autoPatchelfIgnoreMissingDeps = (old.autoPatchelfIgnoreMissingDeps or [ ]) ++ [ "libcuda.so.1" ];
                    }
                    // extendInputs {
                      nativeBuildInputs = [ pkgs.autoPatchelfHook ] ++ cudaLibs;
                      buildInputs = cudaLibs;
                      propagatedBuildInputs = cudaLibs;
                    } old
                  );
                patchHpc =
                  pkg:
                  pkg.overrideAttrs (old: {
                      autoPatchelfExtraLibs = (old.autoPatchelfExtraLibs or [ ]) ++ hpcLibPaths;
                    }
                    // extendInputs {
                      nativeBuildInputs = [ pkgs.autoPatchelfHook ];
                      buildInputs = hpcLibs;
                      propagatedBuildInputs = hpcLibs;
                    } old
                  );
                torchLibPaths =
                  let
                    torch = final."torch";
                    torchLib = lib.getLib torch;
                    pythonLibDir = "${pkgs.python312.libPrefix}/site-packages";
                  in
                  [
                    "${torch}/lib"
                    "${torchLib}/lib"
                    "${torch}/${pythonLibDir}/torch/lib"
                    "${torchLib}/${pythonLibDir}/torch/lib"
                  ];
                patchTorchDeps =
                  pkg:
                  pkg.overrideAttrs (old: {
                      autoPatchelfExtraLibs = lib.unique ((old.autoPatchelfExtraLibs or [ ]) ++ torchLibPaths);
                      autoPatchelfLibs = lib.unique ((old.autoPatchelfLibs or [ ]) ++ torchLibPaths);
                    }
                    // extendInputs {
                      nativeBuildInputs = [ final."torch" ];
                      buildInputs = [ final."torch" ];
                      propagatedBuildInputs = [ final."torch" ];
                    } old
                  );
              in
              lib.optionalAttrs pkgs.stdenv.isLinux {
                "cupy-cuda12x" = patchCuda prev."cupy-cuda12x";
                "nvidia-cusparse-cu12" = patchCuda prev."nvidia-cusparse-cu12";
                "nvidia-cusolver-cu12" = patchCuda prev."nvidia-cusolver-cu12";
                "nvidia-cutlass-dsl" = patchCuda prev."nvidia-cutlass-dsl";
                "torch" = patchCuda prev."torch";
                "triton" = patchCuda prev."triton";

                "nvidia-nvshmem-cu12" = patchHpc prev."nvidia-nvshmem-cu12";
                "nvidia-cufile-cu12" = patchHpc prev."nvidia-cufile-cu12";

                "vllm" = patchTorchDeps (patchCuda prev."vllm");
                "torchvision" = patchTorchDeps (patchCuda prev."torchvision");
                "torchaudio" = patchTorchDeps (patchCuda prev."torchaudio");

                "numba" = prev."numba".overrideAttrs (old: {
                    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.autoPatchelfHook ];
                    buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.tbb ];
                    propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ [ pkgs.tbb ];
                    autoPatchelfExtraLibs = (old.autoPatchelfExtraLibs or [ ]) ++ [ "${pkgs.tbb}/lib" ];
                  });

                "etcd3" = prev."etcd3".overrideAttrs (old: {
                  nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ final."setuptools" ];
                  buildInputs = (old.buildInputs or [ ]) ++ [ final."setuptools" ];
                });

              }
              // {
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
                        buildPhase = "
                          runHook preBuild;
                          SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt pytest -q;
                          runHook postBuild
                        ";
                        installPhase = "mkdir -p $out";
                      };
                    };
                  };
                });
              }
            )
          ];

          pyprojectPackages = pkgs.callPackage pyproject-nix.build.packages { python = pkgs.python312; };
          pythonSet = pyprojectPackages.overrideScope (lib.composeManyExtensions pythonOverlays);

          mkEnv = name: deps: pythonSet.mkVirtualEnv name deps;

          launcherCommonDefaults = {
            MCP_PORT = "8001";
            AGENT_PORT = "8000";
            LLM_PORT = "8002";
            WEBUI_PORT = "3000";
            CLIENT_ID = "default";
            DATA_DIR = "$PWD/.open-webui-data";
          };

          renderDefaults =
            attrs:
            lib.concatStringsSep "\n" (
              lib.mapAttrsToList (name: value: '': "''${${name}:=${value}}"'') attrs
            );

          backendEnvs = lib.mapAttrs (name: _: mkEnv "mcp-env-${name}" deps.${name}) enabledBackends;

          defaultBackend =
            lib.attrByPath
              [ baseRuntime ]
              (throw "Default backend ${baseRuntime} not enabled for ${system}.")
              enabledBackends;

          mkLauncher =
            {
              name,
              venv,
              backend,
              withWebui ? true,
              entry ? "server",
            }:
            let
              backendCfg = enabledBackends.${backend};
              backendLabel = backendCfg.label;
              envBlock =
                let
                  defaultsScript = renderDefaults launcherCommonDefaults;
                  withTensorRT = lib.elem "tensorrt" backendCfg.extras;
                  platformEnv = lib.optionalString (backendCfg.runtime == "mlx") (
                    let
                      mlxLib = "${venv}/lib/${pkgs.python312.libPrefix}/site-packages/mlx/lib";
                    in
                    ''
                      export DYLD_LIBRARY_PATH="${mlxLib}''${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
                      export MLX_LIBRARY_PATH="${mlxLib}"
                    ''
                  );
                in
                ''
                  ${defaultsScript}
                  export LLM_MODEL=${"$"}{LLM_MODEL:=${backendCfg.modelDefault}}
                  ${platformEnv}
                  BACKEND="${backendCfg.runtime}"
                  WITH_TENSORRT="${if withTensorRT then "1" else "0"}"
                  export LLM_MODEL MCP_PORT AGENT_PORT LLM_PORT CLIENT_ID BACKEND WITH_TENSORRT
                '';
              serverCmd = "${venv}/bin/server --agent-port \"$AGENT_PORT\" --llm-port \"$LLM_PORT\" --mcp-port \"$MCP_PORT\" --client-id \"$CLIENT_ID\"";
              entryCommands = {
                server = ''exec ${serverCmd}'';
                "mcp-server" = ''exec ${venv}/bin/mcp-server --mcp-port "$MCP_PORT"'';
                agent = ''exec ${venv}/bin/agent --agent-port "$AGENT_PORT" --llm-port "$LLM_PORT" --mcp-port "$MCP_PORT" --client-id "$CLIENT_ID"'';
              };
              scriptBody = ''
                set -euo pipefail
                ${envBlock}
              ''
              + lib.optionalString (!withWebui) entryCommands.${entry}
              + lib.optionalString withWebui ''
                cleanup() { echo; echo "[terrabridge] stopping..."; kill "$SERVER_PID" "$WEBUI_PID" 2>/dev/null || true; wait 2>/dev/null || true; }
                trap cleanup EXIT INT TERM

                echo "╔═══════════════════════════════════════════════════════════════╗"
                echo "║              Terrabridge MCP + Open WebUI                     ║"
                echo "╚═══════════════════════════════════════════════════════════════╝"
                echo

                echo "[1/2] Starting server..."
                ${serverCmd} &
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
                  if curl -sf "http://localhost:$WEBUI_PORT/api/version" >/dev/null 2>/dev/null; then
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
                echo "  Backend:    ${backendLabel}"
                echo
                echo "Ctrl+C to stop"
                wait
              '';
            in
            pkgs.writeShellApplication {
              inherit name;
              text = scriptBody;
              runtimeInputs = [
                pkgs.coreutils
                pkgs.gnugrep
                pkgs.curl
                pkgs.procps
              ];
            };

          mkApp =
            {
              label,
              backend,
              webui ? true,
              entry ? "server",
            }:
            let
              venv = backendEnvs.${backend};
              drv = mkLauncher {
                name = label;
                inherit venv entry backend;
                withWebui = webui;
              };
            in
            {
              type = "app";
              program = "${drv}/bin/${label}";
              meta = {
                description = "Terrabridge launcher (${label}, backend=${backend}, webui=${if webui then "on" else "off"})";
              };
            };

          appVariants = [
            {
              key = "default";
              labelSuffix = "";
              webui = true;
              entry = "server";
            }
            {
              key = "headless";
              labelSuffix = "-headless";
              webui = false;
              entry = "server";
            }
            {
              key = "mcp-server";
              labelSuffix = "-mcp";
              webui = false;
              entry = "mcp-server";
            }
            {
              key = "agent";
              labelSuffix = "-agent";
              webui = false;
              entry = "agent";
            }
          ];

          mkVariantName =
            attrPrefix: key:
            if key == "default" then
              (if attrPrefix == "" then "default" else attrPrefix)
            else if attrPrefix == "" then
              key
            else
              "${attrPrefix}-${key}";

          mkAppsForBackend =
            {
              backend,
              attrPrefix ? backend.attrPrefix,
              labelPrefix ? backend.labelPrefix,
            }:
            lib.listToAttrs (
              map (variant: {
                name = mkVariantName attrPrefix variant.key;
                value =
                  mkApp {
                    label = "${labelPrefix}${variant.labelSuffix}";
                    backend = backend.name;
                    webui = variant.webui;
                    entry = variant.entry;
                  };
              }) appVariants
            );

          prefixedBackends = lib.filter (backend: backend.attrPrefix != "") (lib.attrValues enabledBackends);

          allApps =
            lib.foldl' lib.recursiveUpdate { }
              (
                [
                  (mkAppsForBackend {
                    backend = defaultBackend;
                    attrPrefix = "";
                    labelPrefix = defaultBackend.labelPrefix;
                  })
                ]
                ++ map
                  (backend:
                    mkAppsForBackend {
                      inherit backend;
                      attrPrefix = backend.attrPrefix;
                      labelPrefix = backend.labelPrefix;
                    })
                  prefixedBackends
              );
        in
        {
          packages =
            backendEnvs // {
              default = backendEnvs.${defaultBackend.name};
            };

          devShells.default = pkgs.mkShell {
            packages = [
              (mkEnv "dev-env" defaultDeps)
              pkgs.uv
              pkgs.black
              pkgs.git
            ];
            env = {
              UV_NO_SYNC = "1";
              UV_PYTHON_DOWNLOADS = "never";
            };
            shellHook = "unset PYTHONPATH; export REPO_ROOT=${builtins.toString workspaceRoot}";
          };

          apps = allApps;

          formatter = pkgs.nixfmt-rfc-style;
          checks.pytest = pythonSet."terrabridge-mcp".passthru.tests.pytest;
        };
    };
}
