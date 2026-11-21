# NixOS, the current stable release
# NixOS publishes no generic cloud image (cloud-init, NoCloud), so the image is
# built here with Nix from nixos.nix: the machine as its owner has it before
# running install.sh, with the test's ssh key baked in. Needs nix-build with
# KVM (vm.yml installs Nix for every flavor that defines image_build).

# "<channel> <revision>" of the newest stable NixOS channel (what status.nixos.org shows)
nixos_stable() {
  python3 -I - <<'PY'
import json, re, urllib.request
q = "https://prometheus.nixos.org/api/v1/query?query=channel_revision"
res = json.load(urllib.request.urlopen(q, timeout=30))["data"]["result"]
chans = [r["metric"] for r in res
         if r["metric"].get("status") == "stable" and re.fullmatch(r"nixos-\d+\.\d+", r["metric"].get("channel", ""))]
best = max(chans, key=lambda m: [int(x) for x in m["channel"][6:].split(".")])
print(best["channel"], best["revision"])
PY
}

image_build() { # out.qcow2 ssh-public-key
  local stable chan rev out
  stable=$(nixos_stable) || return 1
  read -r chan rev <<<"$stable"
  echo "$chan at $rev"
  out=$(nix-build --no-out-link "$ROOT/tests/vm/flavors/nixos.nix" \
          --argstr nixpkgsUrl "https://github.com/NixOS/nixpkgs/archive/$rev.tar.gz" \
          --argstr sshKey "$(cat "$2")") || return 1
  cp "$out/nixos.qcow2" "$1"
  chmod u+w "$1"
}
