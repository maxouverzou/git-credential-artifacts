{
  description = "Cloudflare Artifacts Git credential generator";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forEachSupportedSystem =
        f:
        nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ self.overlays.default ];
            };
          }
        );
    in
    {
      overlays.default = final: prev: {
        go = prev.go_1_27;
        buildGoModule = prev.buildGoModule.override { go = final.go; };
        gotools = prev.gotools.override {
          inherit (final) go buildGoModule;
        };
      };

      packages = forEachSupportedSystem (
        { pkgs, ... }:
        {
          # Explicit test tool, separate from the locked current Git.
          git-245 = pkgs.callPackage ./nix/git-245.nix { };
          default = pkgs.buildGoModule {
            pname = "git-credential-artifacts";
            version = "0.0.0-dev";
            # Allow only build inputs. No .git, .direnv, docs, or local auth files.
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./go.mod
                ./go.sum
                (pkgs.lib.fileset.fileFilter (file: file.hasExt "go") ./cmd)
                (pkgs.lib.fileset.fileFilter (file: file.hasExt "go") ./internal)
                (pkgs.lib.fileset.fileFilter (file: file.hasExt "go") ./integration)
              ];
            };
            vendorHash = "sha256-ELqshwQnmx00Ho2PPFI2WV8m8TD5yi96PiL6d2Xi14s=";
            subPackages = [ "cmd/git-credential-artifacts" ];
            env.GOTOOLCHAIN = "local";
            preCheck = ''
              export HOME=$(mktemp -d)
              export GOCACHE=$(mktemp -d)
            '';
            meta = {
              description = "Generate repository-scoped Git credentials for Cloudflare Artifacts";
              mainProgram = "git-credential-artifacts";
              platforms = supportedSystems;
            };
          };
        }
      );

      apps = forEachSupportedSystem (
        { system, ... }:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/git-credential-artifacts";
            meta.description = "Cloudflare Artifacts Git credential generator";
          };
        }
      );

      checks = forEachSupportedSystem (
        { pkgs, system }:
        let
          package = self.packages.${system}.default;
          goCheck =
            name: command:
            package.overrideAttrs {
              pname = "artifacts-${name}";
              goModules = package.goModules;
              subPackages = [ ];
              doCheck = false;
              buildPhase = ''
                runHook preBuild
                export HOME=$(mktemp -d)
                export GOCACHE=$(mktemp -d)
                export GOPATH=$(mktemp -d)
                export GOMAXPROCS=2
                ${command}
                runHook postBuild
              '';
              installPhase = ''
                mkdir -p "$out"
                touch "$out/passed"
              '';
            };
          instrumentedCheck =
            name: command:
            (goCheck name command).overrideAttrs (old: {
              nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.stdenv.cc ];
              env = (old.env or { }) // {
                CGO_ENABLED = "1";
              };
            });
          gitCheck =
            name: git:
            instrumentedCheck name ''
              harnessDir=$(mktemp -d)
              go build -race -o "$harnessDir/artifacts-test-harness" ./integration/harness
              export ARTIFACTS_INTEGRATION_REQUIRED=1
              export ARTIFACTS_TEST_GIT=${git}/bin/git
              export ARTIFACTS_TEST_GIT_VERSION=${git.version}
              export ARTIFACTS_TEST_HELPER="$harnessDir/artifacts-test-harness"
              export ARTIFACTS_TEST_PRODUCTION_HELPER=${package}/bin/git-credential-artifacts
              go test -race -v -count=1 -timeout=2m ./integration
            '';
        in
        {
          package = package;
          unit = goCheck "unit" "go test ./...";
          vet = goCheck "vet" "go vet ./...";
          # All declared targets support Go's race runtime; compilation uses the
          # explicitly supplied native stdenv compiler, never a host fallback.
          race = instrumentedCheck "race" "go test -race -count=1 ./...";
          fuzz = instrumentedCheck "fuzz" ''
            go test ./internal/credential -run '^$' -fuzz '^FuzzParse$' -fuzztime=10s -parallel=2 -timeout=2m
            go test ./internal/credential -run '^$' -fuzz '^FuzzWriteResponse$' -fuzztime=10s -parallel=2 -timeout=2m
            go test ./internal/artifacts -run '^$' -fuzz '^FuzzResolve$' -fuzztime=10s -parallel=2 -timeout=2m
            go test ./internal/artifacts -run '^$' -fuzz '^FuzzValidateToken$' -fuzztime=10s -parallel=2 -timeout=2m
          '';
          go-format = goCheck "go-format" ''
            unformatted=$(gofmt -l cmd internal integration)
            if [ -n "$unformatted" ]; then
              printf '%s\n' "$unformatted"
              exit 1
            fi
          '';
          nix-format = pkgs.runCommand "artifacts-nix-format" { nativeBuildInputs = [ pkgs.nixfmt ]; } ''
            nixfmt --check ${./flake.nix} ${./nix/git-245.nix}
            touch "$out"
          '';
          workflow =
            pkgs.runCommand "artifacts-workflow-lint"
              {
                nativeBuildInputs = [
                  pkgs.actionlint
                  pkgs.shellcheck
                ];
              }
              ''
                actionlint -shellcheck=${pkgs.shellcheck}/bin/shellcheck ${./.github/workflows/ci.yml}
                touch "$out"
              '';
          git-current = gitCheck "git-current" pkgs.git;
          git-245 = gitCheck "git-245" self.packages.${system}.git-245;
        }
      );

      devShells = forEachSupportedSystem (
        { pkgs, system }:
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gotools
              pkgs.git
              self.formatter.${system}
            ];
            GOTOOLCHAIN = "local";
            # mkShell supplies stdenv's native compiler for race-enabled tests.
          };
        }
      );

      formatter = forEachSupportedSystem (
        { pkgs, ... }:
        pkgs.writeShellApplication {
          name = "format-nix";
          runtimeInputs = [ pkgs.nixfmt ];
          text = ''
            if [ "$#" -eq 0 ]; then
              set -- flake.nix nix/git-245.nix
            fi
            exec nixfmt "$@"
          '';
        }
      );
    };
}
