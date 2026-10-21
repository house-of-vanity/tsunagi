{
  description = "tsunagi: serverless mesh VPN. A network name and a secret are all it takes.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        tsunagi = pkgs.callPackage ./nix/package.nix { };
        tsunagi-cli = pkgs.callPackage ./nix/package.nix { withTray = false; };
        default = tsunagi;
      });

      overlays.default = final: _prev: {
        tsunagi = final.callPackage ./nix/package.nix { };
        tsunagi-cli = final.callPackage ./nix/package.nix { withTray = false; };
      };

      nixosModules.default = import ./nix/module.nix self;

      devShells = forAllSystems (
        pkgs:
        let
          trayPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.tsunagi;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ trayPackage ];
            packages = [
              pkgs.rustfmt
              pkgs.clippy
            ]
            ++ trayPackage.trayRuntimeLibs;
            # Cargo binaries have no installed wrapper. Expose runtime-loaded
            # libraries here too, while preserving the caller's library path.
            shellHook = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath trayPackage.trayRuntimeLibs}:/run/opengl-driver/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '';
          };
        }
      );
    };
}
