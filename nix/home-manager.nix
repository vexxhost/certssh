self:
{
  config,
  lib,
  options,
  pkgs,
  ...
}:

let
  cfg = config.programs.certssh;
  yaml = pkgs.formats.yaml { };

  settings = lib.recursiveUpdate cfg.settings (
    lib.optionalAttrs (cfg.agent.upstream != null) { agent.upstream = cfg.agent.upstream; }
  );
  managed = settings != { };
  configFile = yaml.generate "certssh-config.yaml" settings;
  socket = settings.agent.socket or "${config.home.homeDirectory}/.certssh/agent.sock";

  # home-manager renamed programs.ssh.matchBlocks to programs.ssh.settings,
  # which takes OpenSSH's own directive names.
  sshAgentSetting =
    if options.programs.ssh ? settings then
      { programs.ssh.settings."*".IdentityAgent = socket; }
    else
      { programs.ssh.matchBlocks."*".identityAgent = socket; };
in
{
  options.programs.certssh = {
    enable = lib.mkEnableOption "certssh, an SSH agent for SSH certificate authorities in OpenBao or Vault";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.certssh;
      defaultText = lib.literalExpression "certssh.packages.\${system}.certssh";
      description = "The certssh package to use.";
    };

    settings = lib.mkOption {
      inherit (yaml) type;
      default = { };
      example = lib.literalExpression ''
        {
          current = "openbao.example.com";
          contexts."openbao.example.com" = {
            address = "https://openbao.example.com";
            login.human.mount = "oidc";
            principal_patterns.agent = [ "agent:*" ];
          };
        }
      '';
      description = ''
        Contents of {file}`~/.config/certssh/config.yaml`. When anything is
        set, the file is managed by Nix: declare contexts here, and
        `certssh login` logs in to them without changing the file.
        Leave it empty to let `certssh login <address>` create contexts.
      '';
    };

    agent = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether to run the agent as a user service (systemd on Linux, launchd on macOS).";
      };

      upstream = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "~/.1password/agent.sock";
        description = ''
          Another agent whose keys stay available through certssh, usually
          the one `IdentityAgent` pointed at before (1Password, Secretive,
          gpg-agent). Without it the agent uses `SSH_AUTH_SOCK`.
        '';
      };
    };

    enableSshIntegration = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Whether to point ssh at the certssh agent with `IdentityAgent` in the
        `Host *` block of {option}`programs.ssh`. Move an `IdentityAgent` you
        set yourself to {option}`programs.certssh.agent.upstream`.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      { home.packages = [ cfg.package ]; }

      (lib.mkIf managed { xdg.configFile."certssh/config.yaml".source = configFile; })

      (lib.mkIf (cfg.agent.enable && pkgs.stdenv.hostPlatform.isLinux) {
        systemd.user.services.certssh-agent = {
          Unit = {
            Description = "certssh SSH agent";
            Documentation = "https://github.com/vexxhost/certssh";
            X-Restart-Triggers = lib.optional managed "${configFile}";
          };
          Service = {
            ExecStart = "${lib.getExe cfg.package} agent";
            Restart = "on-failure";
          };
          Install.WantedBy = [ "default.target" ];
        };
      })

      (lib.mkIf (cfg.agent.enable && pkgs.stdenv.hostPlatform.isDarwin) {
        launchd.agents.certssh = {
          enable = true;
          config = {
            ProgramArguments = [
              (lib.getExe cfg.package)
              "agent"
            ];
            RunAtLoad = true;
            KeepAlive = true;
            ProcessType = "Interactive";
            StandardErrorPath = "${config.home.homeDirectory}/.local/state/certssh/agent.log";
          };
        };
      })

      (lib.mkIf cfg.enableSshIntegration (
        sshAgentSetting
        // {
          warnings = lib.optional (!config.programs.ssh.enable) ''
            programs.certssh.enableSshIntegration only takes effect with programs.ssh.enable;
            otherwise set IdentityAgent ${socket} in your ssh config yourself.
          '';
        }
      ))
    ]
  );
}
