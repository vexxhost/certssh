{
  description = "Checks for the certssh home-manager module; run with --override-input certssh path:$PWD";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    certssh = {
      url = "github:vexxhost/certssh";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      home-manager,
      certssh,
      ...
    }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      home =
        (home-manager.lib.homeManagerConfiguration {
          inherit pkgs;
          modules = [
            certssh.homeManagerModules.default
            {
              home.username = "alice";
              home.homeDirectory = "/home/alice";
              home.stateVersion = "25.05";
              programs.ssh.enable = true;
              programs.certssh = {
                enable = true;
                agent.upstream = "~/.1password/agent.sock";
                settings.contexts."openbao.example.com".address = "https://openbao.example.com";
              };
            }
          ];
        }).activationPackage;
    in
    {
      checks.x86_64-linux.home-manager = pkgs.runCommand "certssh-home-manager" { } ''
        files=${home}/home-files
        grep -qx '  IdentityAgent /home/alice/.certssh/agent.sock' $files/.ssh/config
        grep -q 'upstream: ~/.1password/agent.sock' $files/.config/certssh/config.yaml
        grep -q 'address: https://openbao.example.com' $files/.config/certssh/config.yaml
        grep -q '^ExecStart=.*/bin/certssh agent$' $files/.config/systemd/user/certssh-agent.service
        touch $out
      '';
    };
}
