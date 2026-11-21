#!/usr/bin/env bash
# End-to-end test of the real thing: install, trigger, contain, ban, health,
# re-install, failed install, uninstall --purge. Runs as root and changes the
# machine (packages, users, audit rules, nftables, an sshd, a dummy interface):
# only on a throwaway CI machine.
#   sudo tests/integration/run.sh            (refuses outside GitHub Actions)
#   sudo HP_FORCE=1 tests/integration/run.sh (a disposable VM of your own)
set -uo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true || ${HP_FORCE:-} == 1 ]] || {
  echo "refusing: this test installs the tripwire and kills sessions. Use a throwaway VM (HP_FORCE=1)" >&2
  exit 2
}

SRC=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d /tmp/hp-it.XXXXXX)
REPO=$W/repo            # the "downloaded" copy that gets installed (and deleted)
ALERTS=$W/alerts.jsonl
PORT=8765
U=hpalice               # bait owner
UHOME=/home/$U
KEY=$W/id_ed25519
IP2=10.99.0.1           # extra local address: a source the handler may ban (see setup)
FAILS=0

# Names used by the install (the example's defaults)
SERVICE=polkit-agent-helper
HANDLER=/usr/lib/polkit-1/polkit-agent-helper
CONF=/etc/polkit-1/agent-helper.conf
REPORTS=/var/lib/polkit-1/agent-cache
RULES=/etc/audit/rules.d/50-polkit.rules
AKEY=pk-auth
TABLE=raw_filter
# NixOS: /etc/systemd/system is read-only (built from configuration.nix), the
# unit goes to the control folder; NixOS loads its own audit rules with
# audit-rules-nixos.service, never augenrules.
NIXOS=no; [[ -e /etc/NIXOS ]] && NIXOS=yes
UNITDIR=/etc/systemd/system; [[ $NIXOS == yes ]] && UNITDIR=/etc/systemd/system.control
UNIT=$UNITDIR/$SERVICE.service
NIXOS_RULES_UNIT=audit-rules-nixos.service

# ------------------------------------------------------------- helpers
group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }
pass() { echo "  ok   $*"; }
fail() { echo "  FAIL $*"; echo "::error::$*"; FAILS=$((FAILS + 1)); }
check() { # description command...
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}
check_not() {
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi
}
die() { fail "$*"; exit 1; }

# NEVER read a bait from this script while the service runs: this process has
# no login session, so the handler kills the reader AND its parent shell, which
# is this script (its process name is "bash"). Read baits through offline().
offline() { # command...: run it with the service stopped
  local r
  systemctl stop "$SERVICE"
  "$@"; r=$?
  systemctl start "$SERVICE"
  return $r
}

ssh_as() { # [ip] -- command
  local ip=127.0.0.1
  [[ $1 != -- ]] && { ip=$1; shift; }
  shift
  ssh -i "$KEY" -b "$ip" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -o LogLevel=ERROR "$U@$ip" "$@"
}
alerts() { cat "$ALERTS" 2>/dev/null || true; }
alert_count() { local n; n=$(grep -c "\"$1" "$ALERTS" 2>/dev/null); echo "${n:-0}"; }
wait_alert() { # title-prefix expected-count timeout
  local i
  for ((i = 0; i < $3 * 2; i++)); do
    [[ $(alert_count "$1") -ge $2 ]] && return 0
    sleep 0.5
  done
  return 1
}
last_alert() { grep "\"$1" "$ALERTS" | tail -n1; }
wait_health() { # timeout: the handler may still be loading its rules (NixOS)
  local i
  for ((i = 0; i < $1; i++)); do "$HANDLER" --health >/dev/null 2>&1 && return 0; sleep 1; done
  "$HANDLER" --health
}
wait_active() { # timeout
  local i
  for ((i = 0; i < $1; i++)); do systemctl is-active --quiet "$SERVICE" && return 0; sleep 1; done
  return 1
}
install_args=(-u "$U" -e password.txt -e vpn -f "$UHOME/notes.txt")
run_install() { # every run's output is kept in install-all.log for the diagnostics
  local r
  (cd "$REPO" && ./install.sh "$@") >"$W/install.log" 2>&1; r=$?
  { echo "=== install.sh $* (exit $r)"; cat "$W/install.log"; } >>"$W/install-all.log"
  return $r
}

diagnostics() {
  group "diagnostics"
  echo "--- install outputs"; tail -n 250 "$W/install-all.log" 2>/dev/null
  echo "--- alerts"; alerts
  echo "--- service"; systemctl status "$SERVICE" --no-pager 2>&1 | head -20
  echo "--- journal"; journalctl -u "$SERVICE" --no-pager -n 50 2>&1
  echo "--- audit rules"; auditctl -l 2>&1
  echo "--- audit status"; auditctl -s 2>&1
  echo "--- nft"; nft list table inet "$TABLE" 2>&1
  echo "--- reports"; ls -la "$REPORTS" 2>&1; tail -n 40 "$REPORTS"/*.log 2>/dev/null
  echo "--- auditd.conf"; grep -vE '^\s*(#|$)' /etc/audit/auditd.conf 2>&1
  echo "--- audit log"; ls -la /var/log/audit 2>&1; tail -n 15 /var/log/audit/audit.log 2>&1
  echo "--- ausearch key"; ausearch --input-logs -k "$AKEY" -ts recent 2>&1 | tail -n 20
  echo "--- probe: watch a temp file, cat it, look for it"
  local p=/root/hp-probe.txt; echo x >"$p"
  auditctl -a always,exit -F arch=b64 -S openat -F path="$p" -k hp-probe 2>&1
  cat "$p" >/dev/null; sleep 2
  ausearch --input-logs -k hp-probe -i 2>&1 | tail -n 8; grep -c hp-probe /var/log/audit/audit.log
  auditctl -D -k hp-probe >/dev/null 2>&1
  echo "--- kernel"; uname -r; cat /proc/cmdline; dmesg 2>/dev/null | grep -i audit | tail -n 10
  echo "--- auditd"; systemctl status auditd --no-pager 2>&1 | head -15
  endgroup
}
finish() {
  [[ $FAILS -eq 0 ]] || diagnostics
  [[ -n ${SINK_PID:-} ]] && kill "$SINK_PID" 2>/dev/null
  echo
  if [[ $FAILS -eq 0 ]]; then echo "ALL INTEGRATION CHECKS PASSED"; else echo "$FAILS CHECK(S) FAILED"; fi
  [[ $FAILS -eq 0 ]]
}
trap 'finish; exit $?' EXIT

# ------------------------------------------------------------- machine setup
group "setup"
# Any systemd distro with apt, dnf or pacman, or NixOS (the VM tests run this too)
if [[ $NIXOS == yes ]]; then
  # packages come from configuration.nix: tests/vm/flavors/nixos.nix
  for t in ssh auditctl ausearch nft ip ss python3 pgrep; do
    command -v "$t" >/dev/null || die "NixOS: $t missing (see tests/vm/flavors/nixos.nix)"
  done
elif command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq openssh-server openssh-client auditd nftables iproute2 python3 >/dev/null || die "apt install"
elif command -v dnf >/dev/null; then
  dnf install -y -q openssh-server openssh-clients audit nftables iproute python3 procps-ng >/dev/null || die "dnf install"
elif command -v pacman >/dev/null; then
  pacman -Syu --needed --noconfirm openssh audit nftables iproute2 python procps-ng >/dev/null || die "pacman install"
else
  die "no apt-get, dnf or pacman"
fi
systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1
systemctl is-active --quiet ssh || systemctl is-active --quiet sshd || die "sshd not running"
systemctl is-active --quiet auditd || systemctl start auditd || die "auditd won't start"
auditctl -s | grep -q '^enabled 1' || die "kernel auditing not enabled on this machine"
echo "$(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r), $(python3 --version)"

USHELL=/bin/bash; [[ -x $USHELL ]] || USHELL=$(command -v bash)   # NixOS has no /bin/bash
id "$U" >/dev/null 2>&1 || useradd -m -s "$USHELL" "$U"
echo "my real notes" >"$UHOME/notes.txt"; chown "$U:" "$UHOME/notes.txt"
ssh-keygen -q -t ed25519 -N '' -f "$KEY"
UGRP=$(id -gn "$U")   # NixOS: no per-user group, users go in "users"
install -d -m 700 -o "$U" -g "$UGRP" "$UHOME/.ssh"
install -m 600 -o "$U" -g "$UGRP" "$KEY.pub" "$UHOME/.ssh/authorized_keys"
command -v restorecon >/dev/null && restorecon -R "$UHOME/.ssh"   # SELinux: ssh_home_t
# A second, non-loopback local address to connect from, so the handler has a
# source it may ban: a dummy interface, else this machine's own address (some
# cloud kernels lack the dummy module). Banning our own address only blocks
# connections we make to ourselves from it.
if ip link add hp0 type dummy 2>/dev/null; then
  ip addr add "$IP2/32" dev hp0 && ip link set hp0 up
else
  IP2=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
  [[ -n $IP2 ]] || die "no dummy interface and no global IPv4 address"
  echo "no dummy interface: using $IP2"
fi
ssh_as -- true || die "ssh to $U@127.0.0.1 doesn't work"
ssh_as "$IP2" -- true || die "ssh to $U@$IP2 doesn't work"

python3 "$SRC/tests/integration/webhook.py" "$PORT" "$ALERTS" &
SINK_PID=$!

cp -a "$SRC" "$REPO"
rm -rf "$REPO/.git"
{
  cat "$REPO/honeypot.conf.example"
  echo "WEBHOOK_URL=http://127.0.0.1:$PORT/"
  echo "IP_LOOKUP=no"
  echo "DEBOUNCE_SECONDS=0"
  echo "HEARTBEAT_DAYS=0"
} >"$REPO/honeypot.conf"
sleep 1
endgroup

# ------------------------------------------------------------- silenced auditing
# Fedora ships "-a task,never" (no syscall auditing at all): the installer must
# refuse before creating anything. Elsewhere, plant such a rule to test that.
NEVER_RE='^[[:space:]]*-a[[:space:]]+(never,task|task,never)[[:space:]]*$'
group "refuses a system where syscall auditing is off (-a task,never)"
if [[ $NIXOS == yes ]]; then
  # NixOS's rules come from configuration.nix (security.audit.rules): plant a loaded one
  auditctl -a task,never >/dev/null
  planted=loaded
elif grep -qxE "$NEVER_RE" /etc/audit/rules.d/*.rules 2>/dev/null; then
  echo "this distribution ships it: $(grep -lxE "$NEVER_RE" /etc/audit/rules.d/*.rules)"
  planted=no
else
  echo "-a task,never" >/etc/audit/rules.d/10-hp-never.rules
  augenrules --load >/dev/null 2>&1
  planted=yes
fi
check_not "install.sh refuses" run_install "${install_args[@]}"
check "it says why" grep -q "task,never" "$W/install.log"
check_not "no bait was created" test -e "$UHOME/password.txt"
check_not "no config was installed" test -e "$CONF"
check_not "no service was installed" test -e "$UNIT"
# Then do what the message says (on Fedora: what its user would do)
if [[ $planted == yes ]]; then
  rm -f /etc/audit/rules.d/10-hp-never.rules
elif [[ $planted == no ]]; then
  sed -i -E "s/$NEVER_RE/# &/" /etc/audit/rules.d/*.rules
fi
[[ $NIXOS == yes ]] || augenrules --load >/dev/null 2>&1
# augenrules only clears loaded rules if the rules have a -D line (Arch's don't)
auditctl -d task,never >/dev/null 2>&1; auditctl -d never,task >/dev/null 2>&1
check_not "rule gone" bash -c "auditctl -l | grep -qxE '$NEVER_RE'"
endgroup

# ------------------------------------------------------------- install
group "install"
if run_install "${install_args[@]}"; then pass "install.sh succeeds"; else cat "$W/install.log"; die "install.sh failed"; fi
tail -n 25 "$W/install.log"
check "service is active" systemctl is-active --quiet "$SERVICE"
check "unit installed in $UNITDIR" test -f "$UNIT"
check "systemd never stops restarting it (no start limit)" test "$(systemctl show -p StartLimitIntervalUSec --value "$SERVICE")" = 0
check "service starts at boot (multi-user.target wants it)" bash -c "systemctl show -p WantedBy --value '$SERVICE' | grep -qw multi-user.target"
check "rules file is root-only (640)" test "$(stat -c '%a %U' "$RULES")" = "640 root"
check "handler is root-only (700)" test "$(stat -c '%a %U' "$HANDLER")" = "700 root"
check "config is root-only (600)" test "$(stat -c '%a %U' "$CONF")" = "600 root"
check "handler has the config path baked in" grep -qF "\"$CONF\")" "$HANDLER"
check "--health passes" "$HANDLER" --health
check "install sent the test notification" wait_alert "title\": \"Honeypot test" 1 10
check_not "install's own end-to-end test raised no alert" grep -q "Honeypot triggered" "$ALERTS"

BAITS=$(grep '^BAIT_FILE=' "$CONF" | cut -d= -f2-)
CREATED=$(grep '^BAIT_CREATED=' "$CONF" | cut -d= -f2-)
check "password.txt is a bait" grep -qw -- "$UHOME/password.txt" <<<"$BAITS"
check "vpn decoy is a bait" grep -qw -- "$UHOME/vpn/office-wg0.conf" <<<"$BAITS"
check "notes.txt (-f) is a bait" grep -qw -- "$UHOME/notes.txt" <<<"$BAITS"
check_not "notes.txt is not marked created" grep -qw -- "$UHOME/notes.txt" <<<"$CREATED"
check "notes.txt content untouched" offline grep -qx "my real notes" "$UHOME/notes.txt"
check "baits belong to $U" test "$(stat -c %U "$UHOME/password.txt" "$UHOME/vpn/office-wg0.conf" | sort -u)" = "$U"
check "decoy has no leftover @@tokens@@" offline bash -c "! grep -q '@@' '$UHOME/vpn/office-wg0.conf' '$UHOME/password.txt'"
old() { (( $(date +%s) - $(stat -c %Y "$1") > 90 * 86400 )); }
check "created bait is backdated" old "$UHOME/password.txt"
check "created folder is backdated" old "$UHOME/vpn"
for b in $BAITS; do
  check "open rule loaded for $b" bash -c "auditctl -l | grep -F 'path=$b ' | grep -q -- '-S [^ ]*open'"
done
endgroup

# ------------------------------------------------------------- stealth
group "stealth"
check_not "unit file doesn't say honeypot" grep -qi honeypot "$UNIT"
check_not "rules file doesn't say honeypot" grep -qi honeypot "$RULES"
# (not the whole process list: this runner checks the repo out under .../honeypot/)
check_not "handler's command line doesn't say honeypot" bash -c "ps -o args= -p \"\$(systemctl show -p MainPID --value '$SERVICE')\" | grep -qi honeypot"
check_not "nft ruleset doesn't say honeypot" bash -c "nft list ruleset | grep -qi honeypot"
check_not "no file installed under a honeypot name" bash -c "ls '$UNITDIR' /usr/local/sbin /usr/lib/polkit-1 /etc/polkit-1 /etc/audit/rules.d | grep -qi honeypot"
check_not "the (world-readable) unit names no bait" grep -qF "$UHOME" "$UNIT"
endgroup

# ------------------------------------------------------------- no false alarm
group "metadata access must not trigger"
ssh_as -- "ls -l ~/password.txt ~/vpn; stat ~/notes.txt; getfattr -d ~/password.txt 2>/dev/null; true" >/dev/null
sleep 5
check_not "ls -l / stat raise no alert" grep -q "Honeypot triggered" "$ALERTS"
endgroup

# ------------------------------------------------------------- trigger: contain
group "trigger over ssh from loopback (session killed, loopback never banned)"
ssh_as -- 'cat ~/password.txt; sleep 30' >/dev/null 2>&1
rc=$?
check "the intruder's ssh session was cut (no 30s sleep)" test "$rc" -ne 0
check "alert received" wait_alert "title\": \"Honeypot triggered" 1 20
A=$(last_alert "title\": \"Honeypot triggered")
check "alert names the bait" grep -qF "File:     $UHOME/password.txt" <<<"$A"
check "alert says OPENED" grep -qF "OPENED" <<<"$A"
check "alert shows the command" grep -qF "cat" <<<"$A"
check "alert shows the login user" grep -qF "$U" <<<"$A"
check "session was terminated" grep -qF "terminated login session" <<<"$A"
check "loopback not banned" grep -qF "NOT banned 127.0.0.1" <<<"$A"
check "a root-only report was written" bash -c "ls '$REPORTS'/*.log && test \"\$(stat -c %a '$REPORTS'/*.log | sort -u)\" = 600"
check_not "journal has no details (bait path)" bash -c "journalctl -u '$SERVICE' --no-pager | grep -qF password.txt"
check_not "handler has no child processes" pgrep -P "$(systemctl show -p MainPID --value "$SERVICE")"
endgroup

# ------------------------------------------------------------- trigger: ban
group "trigger from a non-loopback address (banned, then unbanned)"
ssh_as "$IP2" -- 'cat ~/vpn/office-wg0.conf; sleep 30' >/dev/null 2>&1
check "alert received" wait_alert "title\": \"Honeypot triggered" 2 20
A=$(last_alert "title\": \"Honeypot triggered")
check "alert names the decoy" grep -qF "$UHOME/vpn/office-wg0.conf" <<<"$A"
check "source found" grep -qF "Source:   $IP2" <<<"$A"
check "source banned" grep -qF "banned $IP2 for" <<<"$A"
check "--bans lists it" bash -c "'$HANDLER' --bans | grep -qF '$IP2'"
check_not "banned address can't connect any more" ssh_as "$IP2" -- true
check "--unban works" bash -c "'$HANDLER' --unban '$IP2' | grep -qx unbanned"
check "unbanned address connects again" ssh_as "$IP2" -- true
endgroup

# ------------------------------------------------------------- write access
group "write access triggers too"
before=$(alert_count "title\": \"Honeypot triggered")
ssh_as -- 'echo x >> ~/notes.txt; sleep 30' >/dev/null 2>&1
check "alert for a write" wait_alert "title\": \"Honeypot triggered" $((before + 1)) 20
endgroup

# ------------------------------------------------------------- health
group "health checks"
auditctl -e 0 >/dev/null
check_not "--health fails while auditing is disabled" "$HANDLER" --health
auditctl -e 1 >/dev/null
check "--health recovers" "$HANDLER" --health
auditctl -D -k "$AKEY" >/dev/null
check_not "--health fails when the rules are unloaded" "$HANDLER" --health
if [[ $NIXOS == yes ]]; then
  systemctl restart "$SERVICE"   # NixOS: the handler loads its rules file at start
  check "--health recovers after a service restart (handler reloads the rules)" wait_health 20
else
  augenrules --load >/dev/null 2>&1 || auditctl -R "$RULES" >/dev/null
  check "--health recovers after reload" "$HANDLER" --health
fi
endgroup

# ------------------------------------------------------------- NixOS rule reloads
# NixOS reloads its own audit rules at boot and on a nixos-rebuild that changes
# them: audit-rules-nixos.service deletes EVERY rule when it stops (ours too).
# nixos-rebuild stops and starts it; a plain restart is the other path.
if [[ $NIXOS == yes ]]; then
  group "NixOS: our rules come back when NixOS reloads its own"
  check "$NIXOS_RULES_UNIT wants the service" bash -c "systemctl show -p WantedBy --value '$SERVICE' | grep -qw '$NIXOS_RULES_UNIT'"
  systemctl restart "$NIXOS_RULES_UNIT"
  check "restart: service active again" wait_active 20
  check "restart: --health passes (rules reloaded)" wait_health 20
  systemctl stop "$NIXOS_RULES_UNIT"
  check_not "stop: every rule deleted, ours too (what NixOS does)" bash -c "auditctl -l | grep -q '$AKEY'"
  check_not "stop: the service stopped with it (PartOf)" systemctl is-active --quiet "$SERVICE"
  systemctl start "$NIXOS_RULES_UNIT"
  check "start: service started again with it" wait_active 20
  check "start: --health passes (rules reloaded)" wait_health 20
  before=$(alert_count "title\": \"Honeypot triggered")
  ssh_as -- 'cat ~/password.txt; sleep 30' >/dev/null 2>&1
  check "a read after the reload still triggers" wait_alert "title\": \"Honeypot triggered" $((before + 1)) 20
  endgroup
fi

# ------------------------------------------------------------- re-install
group "re-install (idempotent)"
sum=$(offline sha256sum "$UHOME/password.txt" "$UHOME/vpn/office-wg0.conf")
mt=$(stat -c %Y "$UHOME/password.txt")
check "second install.sh succeeds" run_install "${install_args[@]}"
check "bait content kept" test "$(offline sha256sum "$UHOME/password.txt" "$UHOME/vpn/office-wg0.conf")" = "$sum"
check "bait date kept" test "$(stat -c %Y "$UHOME/password.txt")" = "$mt"
check "service active again" systemctl is-active --quiet "$SERVICE"
check "--health passes" "$HANDLER" --health
endgroup

# ------------------------------------------------------------- failed install
group "failed install leaves the trap armed"
cp "$CONF" "$W/conf.bak"
echo "AUDIT_LOG=/var/log/audit/nope.log" >>"$CONF"
check_not "install.sh fails on a wrong AUDIT_LOG" run_install "${install_args[@]}"
check "it said why" grep -q "AUDIT_LOG=/var/log/audit/nope.log doesn't exist" "$W/install.log"
check "rules still loaded" bash -c "auditctl -l | grep -q -- '-k $AKEY\$\\|key=$AKEY\$'"
check "service restarted" systemctl is-active --quiet "$SERVICE"
cp "$W/conf.bak" "$CONF"
systemctl restart "$SERVICE"
check "--health passes again" "$HANDLER" --health
endgroup

group "refusals"
echo "real data" >"$UHOME/.git-credentials"; chown "$U:" "$UHOME/.git-credentials"
check_not "refuses to overwrite a real file with a decoy" run_install -u "$U" -e .git-credentials
check "the real file is untouched" grep -qx "real data" "$UHOME/.git-credentials"
mkdir -p /root/hp-target; ln -s /root/hp-target "$UHOME/.aws"
check_not "refuses a decoy through a symlink" run_install -u "$U" -e .aws
check "nothing created through the symlink" test -z "$(ls -A /root/hp-target)"
rm -f "$UHOME/.aws" "$UHOME/.git-credentials"
check "trap still healthy after refused runs" "$HANDLER" --health
endgroup

# ------------------------------------------------------------- uninstall
group "uninstall --purge"
check "uninstall.sh --purge succeeds" bash -c "cd '$REPO' && ./uninstall.sh --purge"
check_not "unit removed" test -e "$UNIT"
check_not "no .wants link left" bash -c "ls '$UNITDIR'/*.wants/'$SERVICE.service' 2>/dev/null | grep -q ."
check_not "service gone" systemctl is-active --quiet "$SERVICE"
check_not "handler removed" test -e "$HANDLER"
check_not "rules file removed" test -e "$RULES"
check_not "rules unloaded" bash -c "auditctl -l | grep -q '$AKEY'"
check_not "nft table removed" nft list table inet "$TABLE"
check_not "config removed" test -e "$CONF"
check_not "reports removed" bash -c "ls '$REPORTS'/*.log"
check_not "created bait removed" test -e "$UHOME/password.txt"
check_not "decoy removed" test -e "$UHOME/vpn/office-wg0.conf"
check_not "emptied decoy folder removed" test -e "$UHOME/vpn"
check "the -f file (user's own) kept" test -e "$UHOME/notes.txt"
check "home folder kept" test -d "$UHOME"
endgroup
