# VM flavors

One file per distribution the VM test (`tests/vm/run.sh`, `.github/workflows/vm.yml`)
boots. Adding a distribution = adding a `<name>.sh` here: the workflow lists this
folder, so the new flavor runs in parallel with the others with no other change.

A flavor is sourced by `tests/vm/run.sh` and defines:

- `image_url` (required): prints the URL of the distribution's official
  **cloud image** (qcow2, with cloud-init: the VM gets its user and ssh key
  from a NoCloud seed).
- `prepare` (optional): runs after the first boot, before the test. `vm_ssh CMD`
  runs a command in the VM as the `ci` user (passwordless sudo) and
  `wait_ssh` waits for it to come back after a reboot.

The integration test inside the VM installs its packages with apt-get, dnf or
pacman (`tests/integration/run.sh`); a distribution with another package
manager needs a branch there too, and in `install_deps` in `install.sh`.

Try one locally (needs qemu-system-x86_64, qemu-img, cloud-localds, ideally
/dev/kvm; everything happens inside the VM): `tests/vm/run.sh debian`.
