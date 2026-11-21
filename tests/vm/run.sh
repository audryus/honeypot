#!/usr/bin/env bash
# Run the integration test (tests/integration/run.sh) inside a VM of another
# distribution: boots its official cloud image under QEMU/KVM (or an image the
# flavor builds itself, e.g. NixOS), copies this repo in and runs the test there
# as root. Used by .github/workflows/vm.yml.
#   tests/vm/run.sh <flavor>        flavors: tests/vm/flavors/<flavor>.sh
# Needs qemu-system-x86_64, qemu-img, cloud-localds and (for speed) /dev/kvm;
# flavors that build their image (image_build) need what they say (nixos: Nix).
# Everything happens in a throwaway VM; this machine is not changed.
set -euo pipefail

FLAVOR=${1:?usage: tests/vm/run.sh <flavor> (see tests/vm/flavors/)}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=${VM_WORKDIR:-$(mktemp -d /tmp/hp-vm.XXXXXX)}
PORT=${VM_SSH_PORT:-2222}
mkdir -p "$W"

[[ $FLAVOR =~ ^[a-z0-9][a-z0-9._-]*$ && -f $ROOT/tests/vm/flavors/$FLAVOR.sh ]] \
  || { echo "unknown flavor: $FLAVOR (have: $(cd "$ROOT/tests/vm/flavors" && ls -- *.sh | sed 's/\.sh$//' | tr '\n' ' '))" >&2; exit 2; }
prepare() { :; }   # a flavor may override it
image_url() { :; } # a flavor defines this, or image_build
# shellcheck source=/dev/null
. "$ROOT/tests/vm/flavors/$FLAVOR.sh"

group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

vm_ssh() {
  ssh -i "$W/id" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o ServerAliveInterval=15 -o LogLevel=ERROR ci@127.0.0.1 "$@"
}

console() {
  group "VM console (last 80 lines)"
  tail -n 80 "$W/console.log" 2>/dev/null
  endgroup
}

wait_ssh() { # tries (5 s apart)
  local i
  for ((i = 0; i < $1; i++)); do
    vm_ssh true 2>/dev/null && return 0
    sleep 5
  done
  return 1
}

stop_vm() {
  [[ -f $W/qemu.pid ]] && kill "$(cat "$W/qemu.pid")" 2>/dev/null
  return 0
}
trap stop_vm EXIT

# ------------------------------------------------------------- image, seed
group "image"
ssh-keygen -q -t ed25519 -N '' -f "$W/id" <<<y >/dev/null
if declare -F image_build >/dev/null; then
  # built with this run's ssh key baked in (no cloud-init), so never reused
  echo "$FLAVOR: building the image"
  rm -f "$W/base.qcow2"
  image_build "$W/base.qcow2" "$W/id.pub"
else
  url=$(image_url)
  echo "$FLAVOR: $url"
  [[ -s $W/base.qcow2 ]] || curl -fsSL --retry 3 -o "$W/base.qcow2" "$url"
fi
qemu-img create -q -f qcow2 -F qcow2 -b "$W/base.qcow2" "$W/disk.qcow2" 12G
cat >"$W/user-data" <<EOF
#cloud-config
users:
  - name: ci
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$W/id.pub")"]
ssh_pwauth: false
EOF
printf 'instance-id: hp-%s\nlocal-hostname: nas01\n' "$FLAVOR" >"$W/meta-data"
cloud-localds "$W/seed.img" "$W/user-data" "$W/meta-data"
endgroup

# ------------------------------------------------------------- boot
group "boot"
accel=(-machine accel=tcg)
if [[ -w /dev/kvm ]]; then accel=(-enable-kvm -cpu host); else echo "no /dev/kvm: emulating (slow)"; fi
qemu-system-x86_64 "${accel[@]}" -m 2048 -smp 2 \
  -drive file="$W/disk.qcow2",if=virtio,format=qcow2 \
  -drive file="$W/seed.img",if=virtio,format=raw \
  -nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$PORT"-:22 \
  -display none -serial file:"$W/console.log" -daemonize -pidfile "$W/qemu.pid"
wait_ssh 120 || { echo "::error::$FLAVOR VM never answered on ssh"; console; exit 1; }   # 10 minutes
vm_ssh 'sudo cloud-init status --wait >/dev/null 2>&1; true'
endgroup

group "prepare ($FLAVOR)"
prepare || { echo "::error::$FLAVOR: prepare failed"; console; exit 1; }
endgroup
vm_ssh 'grep PRETTY_NAME /etc/os-release; uname -r'

# ------------------------------------------------------------- test
tar -C "$ROOT" --exclude=.git -czf - . | vm_ssh 'rm -rf ~/hp && mkdir ~/hp && tar -C ~/hp -xzf -'
rc=0
vm_ssh 'sudo HP_FORCE=1 ~/hp/tests/integration/run.sh' || rc=$?
[[ $rc -eq 0 ]] || { echo "::error::integration test failed in the $FLAVOR VM (exit $rc)"; console; }
exit "$rc"
