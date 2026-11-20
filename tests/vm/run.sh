#!/usr/bin/env bash
# Run the integration test (tests/integration/run.sh) inside a VM of another
# distribution: boots its official cloud image under QEMU/KVM, copies this repo
# in and runs the test there as root. Used by .github/workflows/vm.yml.
#   tests/vm/run.sh <distro>        distros: see image_url below
# Needs qemu-system-x86_64, qemu-img, cloud-localds and (for speed) /dev/kvm.
# Everything happens in a throwaway VM; this machine is not changed.
set -euo pipefail

DISTRO=${1:?usage: tests/vm/run.sh <distro>}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=${VM_WORKDIR:-$(mktemp -d /tmp/hp-vm.XXXXXX)}
PORT=${VM_SSH_PORT:-2222}
mkdir -p "$W"

group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

fedora_url() { # newest released Fedora Cloud Base qcow2 for x86_64
  python3 -I - <<'PY'
import json, urllib.request
rel = json.load(urllib.request.urlopen("https://fedoraproject.org/releases.json", timeout=30))
imgs = [r for r in rel if r.get("arch") == "x86_64" and r.get("variant") == "Cloud"
        and r.get("link", "").endswith(".qcow2") and str(r.get("version", "")).isdigit()]
print(max(imgs, key=lambda r: int(r["version"]))["link"])
PY
}

image_url() {
  case $1 in
    debian-12) echo https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2 ;;
    debian-13) echo https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2 ;;
    rocky-9)   echo https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2 ;;
    rocky-10)  echo https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2 ;;
    fedora)    fedora_url ;;
    arch)      echo https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2 ;;
    *) echo "unknown distro: $1" >&2; return 1 ;;
  esac
}

vm_ssh() {
  ssh -i "$W/id" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o ServerAliveInterval=15 -o LogLevel=ERROR ci@127.0.0.1 "$@"
}

console() {
  group "VM console (last 80 lines)"
  tail -n 80 "$W/console.log" 2>/dev/null
  endgroup
}

stop_vm() {
  [[ -f $W/qemu.pid ]] && kill "$(cat "$W/qemu.pid")" 2>/dev/null
  return 0
}
trap stop_vm EXIT

# ------------------------------------------------------------- image, seed
group "image"
url=$(image_url "$DISTRO")
echo "$DISTRO: $url"
[[ -s $W/base.qcow2 ]] || curl -fsSL --retry 3 -o "$W/base.qcow2" "$url"
qemu-img create -q -f qcow2 -F qcow2 -b "$W/base.qcow2" "$W/disk.qcow2" 12G
ssh-keygen -q -t ed25519 -N '' -f "$W/id" <<<y >/dev/null
cat >"$W/user-data" <<EOF
#cloud-config
users:
  - name: ci
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$W/id.pub")"]
ssh_pwauth: false
EOF
printf 'instance-id: hp-%s\nlocal-hostname: nas01\n' "$DISTRO" >"$W/meta-data"
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
up=no
for _ in $(seq 120); do   # up to 10 minutes
  if vm_ssh true 2>/dev/null; then up=yes; break; fi
  sleep 5
done
[[ $up == yes ]] || { echo "::error::$DISTRO VM never answered on ssh"; console; exit 1; }
vm_ssh 'sudo cloud-init status --wait >/dev/null 2>&1; true'
endgroup

# A rolling release's image is behind its repos: the test's package installs
# would upgrade the kernel under the running one, whose modules (nftables,
# dummy) then can't load. Upgrade first and boot the new kernel.
if [[ $DISTRO == arch ]]; then
  group "upgrade and reboot"
  vm_ssh 'sudo pacman -Syu --noconfirm >/dev/null && sudo systemctl reboot' || true
  sleep 15
  up=no
  for _ in $(seq 60); do
    if vm_ssh true 2>/dev/null; then up=yes; break; fi
    sleep 5
  done
  [[ $up == yes ]] || { echo "::error::$DISTRO VM didn't come back after the upgrade"; console; exit 1; }
  endgroup
fi
vm_ssh 'grep PRETTY_NAME /etc/os-release; uname -r' 

# ------------------------------------------------------------- test
tar -C "$ROOT" --exclude=.git -czf - . | vm_ssh 'rm -rf ~/hp && mkdir ~/hp && tar -C ~/hp -xzf -'
rc=0
vm_ssh 'sudo HP_FORCE=1 ~/hp/tests/integration/run.sh' || rc=$?
[[ $rc -eq 0 ]] || { echo "::error::integration test failed in the $DISTRO VM (exit $rc)"; console; }
exit "$rc"
