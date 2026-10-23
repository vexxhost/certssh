{
  description = "SSH agent that signs certificates from OpenBao or Vault on demand, picking the right one for each host";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = self.shortRev or self.dirtyShortRev or "dev";
      mkCertssh = pkgs: pkgs.callPackage ./nix/package.nix { inherit version; src = self; };
    in
    {
      packages = forAllSystems (pkgs: rec {
        certssh = mkCertssh pkgs;
        default = certssh;
      });

      overlays.default = final: _prev: { certssh = mkCertssh final; };

      homeManagerModules = rec {
        certssh = import ./nix/home-manager.nix self;
        default = certssh;
      };
      homeModules = self.homeManagerModules;

      checks = forAllSystems (pkgs: {
        certssh = self.packages.${pkgs.stdenv.hostPlatform.system}.certssh;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            go
            golangci-lint
            openbao
            openssh
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
