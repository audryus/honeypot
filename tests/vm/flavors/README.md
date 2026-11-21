# VM flavors

One file per distribution the VM test (`tests/vm/run.sh`, `.github/workflows/vm.yml`)
boots. Adding a distribution = adding a `<name>.sh` here: the workflow lists this
folder, so the new flavor runs in parallel with the others with no other change.

A flavor is sourced by `tests/vm/run.sh` and defines:

- `image_url`: prints the URL of the distribution's official
  **cloud image** (qcow2, with cloud-init: the VM gets its user and ssh key
  from a NoCloud seed).
- or `image_build OUT.qcow2 KEY.pub`, for a distribution without such an image:
  builds the qcow2 itself, with a passwordless-sudo `ci` user that accepts that
  key and sshd running (nixos: with Nix from `nixos.nix`). The workflow installs
  Nix for every flavor that defines `image_build`.
- `prepare` (optional): runs after the first boot, before the test. `vm_ssh CMD`
  runs a command in the VM as the `ci` user (passwordless sudo) and
  `wait_ssh` waits for it to come back after a reboot.

The integration test inside the VM installs its packages with apt-get, dnf or
pacman (`tests/integration/run.sh`; on NixOS the image already has them); a
distribution with another package manager needs a branch there too, and in
`install_deps` in `install.sh`.

Try one locally (needs qemu-system-x86_64, qemu-img, cloud-localds, ideally
/dev/kvm; everything happens inside the VM): `tests/vm/run.sh debian`.
