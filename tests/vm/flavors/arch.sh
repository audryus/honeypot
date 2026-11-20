# Arch Linux (rolling)
image_url() { echo https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2; }

# The image is behind the repos: the test's package installs would upgrade the
# kernel under the running one, whose modules (nftables, dummy) then can't
# load. Upgrade first and boot the new kernel.
prepare() {
  vm_ssh 'sudo pacman -Syu --noconfirm >/dev/null && sudo systemctl reboot' || true
  sleep 15
  wait_ssh 60 || { echo "::error::the VM didn't come back after the upgrade" >&2; return 1; }
}
