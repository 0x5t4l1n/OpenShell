# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  description = "OpenShell development environment";

  nixConfig = {
    extra-substituters = [ "https://openshell.cachix.org" ];
    extra-trusted-public-keys = [
      "openshell.cachix.org-1:OAr5MunsfH5PZvUsfD08OtGx5RtcwdNZGJdU5FqLm5w="
    ];
  };

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Keep the QEMU and OVMF runtime used by Apple Silicon test guests on a
    # known-good release. Development shells and cross toolchains use nixpkgs.
    nixpkgs-test-guest.url = "github:NixOS/nixpkgs/0954f7ee2f6bb3dc7d4e3d0d8bcb8fd4bde4cfc5";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs =
    {
      flake-utils,
      nixpkgs,
      nixpkgs-test-guest,
      treefmt-nix,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        testGuestPkgs = import nixpkgs-test-guest { inherit system; };
        tmachineRuntimePkgs = if pkgs.stdenv.hostPlatform.isDarwin then testGuestPkgs else pkgs;
        patchedCa = pkgs.cacert.overrideAttrs {
          version = "3.131.1";
          src = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/nss-dev/nss/refs/tags/NSS_3_131_1_RTM/lib/ckfw/builtins/certdata.txt";
            hash = "sha256-PsK00kDcEsdH6vRQBh24SvdXxIO72jAvninOtdcL5RA=";
          };
        };
        patchedUv = pkgs.uv.overrideAttrs (
          finalAttrs: _: {
            version = "0.13.4";
            src = pkgs.fetchFromGitHub {
              owner = "astral-sh";
              repo = "uv";
              tag = finalAttrs.version;
              hash = "sha256-US3SjwhWE3v4/i46YuBon2GA6PupC4Z0NRUqcV9CPLM=";
            };
            cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
              inherit (finalAttrs) pname version src;
              hash = "sha256-9L47CTlkOVYfGuzE4e7e2FYAI192pAsipzzScF7B1j4=";
            };
          }
        );
        commonDevShellPackages = with pkgs; [
          patchedCa
          actionlint
          cargo-auditable
          cargo-deny
          cargo-nextest
          # Assemble Debian artifacts on macOS and Linux.
          dpkg
          # Build and inspect ext4 images in VM driver tests.
          e2fsprogs
          git
          # Required to find packages.
          pkg-config
          # Coverage.
          lcov
          # mise dependencies
          mise
          cmakeMinimal
          zlib
          openssl_3_5
          xz
          gh
          kubernetes-helm
          syft
          trivy
          patchedUv
          yq-go
          zizmor
          zstd
        ];
        commonDevShell = {
          packages = [ rustToolchain ] ++ commonDevShellPackages;
          env =
            (pkgs.lib.foldl' (env: toolchain: env // toolchain.env) { } (builtins.attrValues toolchains))
            // {
              SSL_CERT_FILE = "${patchedCa}/etc/ssl/certs/ca-bundle.crt";
              NIX_SSL_CERT_FILE = "${patchedCa}/etc/ssl/certs/ca-bundle.crt";
            };
        };
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
        rustToolchain =
          ((pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
            targets = map (toolchain: toolchain.target) (builtins.attrValues toolchains);
          }).overrideAttrs
            {
              propagatedBuildInputs = [ ];
              depsHostHostPropagated = [ ];
              depsTargetTargetPropagated = [ ];
            };
        buildInputs = { pkgs, stdenv }: [
          (pkgs.callPackage ./nix/pkgs/z3.nix { inherit stdenv; })
          (pkgs.callPackage ./nix/pkgs/aws-lc.nix { inherit stdenv; })
        ];
        inherit (import ./nix/toolchain) mkToolchain;
        toolchains = {
          x86_64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.gnu64;
            inherit buildInputs;
          };
          x86_64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.musl64;
            inherit buildInputs;
          };
          aarch64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform;
            inherit buildInputs;
          };
          aarch64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            inherit buildInputs;
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
          aarch64-darwin = mkToolchain {
            inherit pkgs buildInputs;
          };
        };
        vmRuntime = pkgs.callPackage ./nix/pkgs/vm-runtime.nix { };
        testGuest = import ./nix/test-guest {
          inherit pkgs;
          qemuPkgs = testGuestPkgs;
          firmwarePkgs = testGuestPkgs;
        };
        testMachines = import ./tests/config.nix {
          inherit pkgs toolchains;
          qemuPkgs = tmachineRuntimePkgs;
          firmwarePkgs = tmachineRuntimePkgs;
        };
        artifacts = pkgs.callPackage ./tests/artifacts.nix { inherit rustToolchain toolchains; };
        checkProtobufCompatibility = pkgs.writeShellApplication {
          name = "check-protobuf-compatibility";
          runtimeInputs = [
            pkgs.buf
            pkgs.git
          ];
          text = ''
            exec ${pkgs.python3}/bin/python3 ${./tasks/scripts}/check_proto_compatibility.py "$@"
          '';
        };
      in
      {
        apps = {
          check-protobuf-compatibility = {
            type = "app";
            program = "${checkProtobufCompatibility}/bin/check-protobuf-compatibility";
          };
          build-artifacts = {
            type = "app";
            program = "${artifacts.all}/bin/build-artifacts";
          };
          build-artifacts-binaries = {
            type = "app";
            program = "${artifacts.binaries}/bin/build-artifacts-binaries";
          };
          build-artifacts-vm-driver = {
            type = "app";
            program = "${artifacts.vmDriver}/bin/build-artifacts-vm-driver";
          };
          build-artifacts-deb = {
            type = "app";
            program = "${artifacts.deb}/bin/build-artifacts-deb";
          };
          build-artifacts-rpm = {
            type = "app";
            program = "${artifacts.rpm}/bin/build-artifacts-rpm";
          };
          build-artifacts-test-archives = {
            type = "app";
            program = "${artifacts.testArchives}/bin/build-artifacts-test-archives";
          };
          build-artifacts-test-images = {
            type = "app";
            program = "${artifacts.testImages}/bin/build-artifacts-test-images";
          };
          generate-podman-e2e-ci-tests = {
            type = "app";
            program = "${artifacts.podmanE2eCiTests}/bin/generate-podman-e2e-ci-tests";
          };
          build-artifacts-helm = {
            type = "app";
            program = "${artifacts.helm}/bin/build-artifacts-helm";
          };
          build-artifacts-images = {
            type = "app";
            program = "${artifacts.images}/bin/build-artifacts-images";
          };
          test-guest = testGuest.app;
          test-guest-cache = testGuest.cacheApp;
        };

        packages = {
          # Expose app derivations so CI can prepare them before executing once.
          check-protobuf-compatibility = checkProtobufCompatibility;
          build-artifacts-test-archives = artifacts.testArchives;
          build-artifacts-test-images = artifacts.testImages;
          build-artifacts-helm = artifacts.helm;
          vm-runtime = vmRuntime;
          tmachine = testMachines.package;
          tmachine-config = testMachines.config;
          tmachine-unwrapped = testMachines.unwrapped;
        };

        devShells = {
          default = pkgs.mkShellNoCC commonDevShell;

          testing = pkgs.mkShellNoCC (
            commonDevShell
            // {
              packages = commonDevShell.packages ++ [
                pkgs.ansible
                pkgs.skopeo
                pkgs.sshpass
                testMachines.package
              ];

              shellHook = ''
                export ANSIBLE_CONFIG="$(git rev-parse --show-toplevel)/tests/ansible/ansible.cfg"
              '';
            }
          );
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
