# The disk image of the "nixos" VM flavor (built by nixos.sh's image_build):
# a NixOS machine as its owner has it right before running install.sh (the two
# lines install.sh asks a NixOS owner to add), plus what the VM test needs to
# log in: sshd and a passwordless-sudo "ci" user with the test's key.
#   nix-build tests/vm/flavors/nixos.nix --argstr nixpkgsUrl <tarball> --argstr sshKey "<key>"
{ nixpkgsUrl, sshKey }:
let
  nixpkgs = builtins.fetchTarball nixpkgsUrl;
  nixos = import "${nixpkgs}/nixos" {
    system = "x86_64-linux";
    configuration = { config, lib, pkgs, modulesPath, ... }: {
      imports = [ "${modulesPath}/profiles/qemu-guest.nix" ];

      # What install.sh asks for on NixOS (nixos_deps)
      security.auditd.enable = true;
      environment.systemPackages = with pkgs; [ python3 nftables ];

      # VM test plumbing (tests/vm/run.sh)
      networking.hostName = "nas01";
      services.openssh.enable = true;
      users.users.ci = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
        openssh.authorizedKeys.keys = [ sshKey ];
      };
      security.sudo.wheelNeedsPassword = false;

      # BIOS boot (run.sh starts QEMU without UEFI); the root filesystem grows
      # to the size of run.sh's overlay disk at first boot
      boot.loader.grub.device = "/dev/vda";
      boot.growPartition = true;
      fileSystems."/" = {
        device = "/dev/disk/by-label/nixos";
        fsType = "ext4";
        autoResize = true;
      };
      documentation.enable = false;
      system.stateVersion = lib.trivial.release;

      system.build.qcow2 = import "${nixpkgs}/nixos/lib/make-disk-image.nix" {
        inherit config lib pkgs;
        format = "qcow2";
        partitionTableType = "legacy";
        copyChannel = false;
        additionalSpace = "1G";
      };
    };
  };
in
nixos.config.system.build.qcow2
