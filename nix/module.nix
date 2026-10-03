flake:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.tsunagi;
  socket = "/run/tsunagi/agent.sock";
in
{
  options.services.tsunagi = {
    enable = lib.mkEnableOption "the tsunagi mesh agent";

    package = lib.mkOption {
      type = lib.types.package;
      default =
        if cfg.tray.enable then
          flake.packages.${pkgs.stdenv.hostPlatform.system}.tsunagi
        else
          flake.packages.${pkgs.stdenv.hostPlatform.system}.tsunagi-cli;
      defaultText = lib.literalExpression "tsunagi.packages.\${system}.tsunagi (tsunagi-cli without the tray)";
      description = "The tsunagi package to run.";
    };

    tray.enable = lib.mkEnableOption "the tray client, started with every graphical session";

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = ''
        Users allowed to talk to the agent without sudo (`tsng status`, `tsng join`,
        the tray). They are added to the `tsunagi` group.
      '';
    };

    protocols = lib.mkOption {
      type = lib.types.nullOr (lib.types.listOf lib.types.str);
      default = null;
      example = [
        "wg-quic"
        "wg"
      ];
      description = "Packet protocols for `tsng up --protocol`, best first. Null keeps the agent's default.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.tsunagi = { };
    users.users = {
      tsunagi = {
        isSystemUser = true;
        group = "tsunagi";
        home = "/var/lib/tsunagi";
        description = "tsunagi agent";
      };
    }
    // lib.genAttrs cfg.users (_: {
      extraGroups = [ "tsunagi" ];
    });

    systemd.services.tsunagi = {
      description = "tsunagi mesh agent";
      documentation = [ "https://github.com/house-of-vanity/tsunagi" ];
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment = {
        TSUNAGI_STATE_DIR = "/var/lib/tsunagi";
        TSUNAGI_CACHE_DIR = "/var/cache/tsunagi";
        TSUNAGI_CONTROL_SOCKET = socket;
        TSUNAGI_CONTROL_GROUP = "tsunagi";
      };
      serviceConfig = {
        ExecStart = lib.concatStringsSep " " (
          [ "${cfg.package}/bin/tsng up" ]
          ++ lib.optional (cfg.protocols != null) "--protocol ${lib.concatStringsSep "," cfg.protocols}"
        );
        User = "tsunagi";
        Group = "tsunagi";
        AmbientCapabilities = [
          "CAP_NET_ADMIN"
          "CAP_NET_BIND_SERVICE"
        ];
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_NET_BIND_SERVICE"
        ];
        StateDirectory = "tsunagi";
        StateDirectoryMode = "0700";
        CacheDirectory = "tsunagi";
        RuntimeDirectory = "tsunagi";
        RuntimeDirectoryMode = "0755";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

    # Exit nodes: the agent looks for iptables only in fixed FHS directories.
    systemd.tmpfiles.rules = [
      "L+ /usr/bin/iptables - - - - ${pkgs.iptables}/bin/iptables"
    ];

    # Names of mesh members are served locally and handed to the system resolver.
    services.resolved.enable = lib.mkDefault true;

    # polkit decides by group, not capability, who may configure systemd-resolved.
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
          var allowed = [
              "org.freedesktop.resolve1.set-dns-servers",
              "org.freedesktop.resolve1.set-domains",
              "org.freedesktop.resolve1.set-default-route",
              "org.freedesktop.resolve1.revert"
          ];
          if (allowed.indexOf(action.id) >= 0 && subject.isInGroup("tsunagi")) {
              return polkit.Result.YES;
          }
      });
    '';

    environment.systemPackages = [ cfg.package ];
    environment.sessionVariables.TSUNAGI_CONTROL_SOCKET = socket;

    environment.etc."xdg/autostart/tsunagi-tray.desktop" = lib.mkIf cfg.tray.enable {
      source = "${cfg.package}/share/applications/tsunagi-tray.desktop";
    };
  };
}
