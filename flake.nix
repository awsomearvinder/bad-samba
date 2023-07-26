# SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
#
# SPDX-License-Identifier: CC0-1.0
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    crate2nix = {
      url = "github:kolloch/crate2nix";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    crate2nix,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};

      inherit
        (import "${crate2nix}/tools.nix" {inherit pkgs;})
        generatedCargoNix
        ;

      project =
        import (generatedCargoNix {
          name = "bad-samba";
          src = ./.;
        }) {
          inherit pkgs;
          defaultCrateOverrides =
            pkgs.defaultCrateOverrides
            // {
            };
        };
    in {
      packages.smb-server = project.workspaceMembers.smb-server.build;
      packages.smb = project.workspaceMembers.smb.build;

      defaultPackage = self.packages.${system}.smb-server;

      devShell = pkgs.mkShell {
        inputsFrom = builtins.attrValues self.packages.${system};
        buildInputs = [pkgs.cargo pkgs.rust-analyzer pkgs.clippy pkgs.rustfmt];
      };
    });
}
