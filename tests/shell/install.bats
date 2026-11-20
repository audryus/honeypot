#!/usr/bin/env bats
# Unit tests for install.sh's functions. No root needed: install.sh is sourced
# (main doesn't run), baits go to a temp "home" owned by the current user, and
# the system tools it calls (systemctl, auditctl, augenrules, ausyscall, nft)
# are fake scripts on PATH that log their arguments to $T/calls.

setup() {
  T=$(mktemp -d)
  T=$(realpath "$T")   # baits are compared in canonical form
  ROOT=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  # shellcheck source=../../install.sh
  . "$ROOT/install.sh"
  FAKEBIN=$T/bin
  mkdir -p "$FAKEBIN" "$T/home"
  for cmd in systemctl auditctl augenrules nft; do fake "$cmd" ""; done
  fake ausyscall 'exit 0'   # knows every syscall
  PATH="$FAKEBIN:$PATH"

  TARGET_USER=$(id -un); TARGET_GROUP=$(id -gn)
  HOME_DIR=$T/home
  HOST_SHORT=testhost
  AUDIT_KEY=k1
  CONF_PATH=$T/etc/agent.conf
  LEGACY_CONF=$T/legacy.conf
  RULES_FILE=$T/rules
  LEGACY_RULES=$T/legacy.rules
  SERVICE_NAME=svc
}

teardown() {
  rm -rf "$T"
}

# `! cmd` and `[ a ] && [ b ]` never fail a bats test (set -e ignores both),
# so negative checks use `not cmd` and checks are one per line.
not() { if "$@"; then echo "unexpectedly succeeded: $*"; return 1; fi; }

fake() { # name body: a fake tool that logs "name args" to $T/calls, then runs body
  printf '#!/bin/bash\necho "%s $*" >>"%s/calls"\n%s\n' "$1" "$T" "$2" >"$FAKEBIN/$1"
  chmod +x "$FAKEBIN/$1"
}

mtime() { stat -c %Y "$1"; }
is_old() { (( $(date +%s) - $(mtime "$1") > 90 * 86400 )); }

# ------------------------------------------------------------- parse_args
@test "parse_args: no -e/-f means -e password.txt" {
  parse_args
  [ "${EXAMPLES[*]}" = password.txt ]
  [ ${#FILES[@]} -eq 0 ]
}

@test "parse_args: options, repeated, trailing slash and ./ trimmed" {
  parse_args -u bob -e .aws/ -e ./vpn -f a.txt -f /x/b.txt -d "1 year ago"
  [ "$TARGET_USER" = bob ]
  [ "${EXAMPLES[*]}" = ".aws vpn" ]
  [ "${FILES[*]}" = "a.txt /x/b.txt" ]
  [ "$FAKE_DATE" = "1 year ago" ]
}

@test "parse_args: -f only doesn't add the default decoy" {
  parse_args -f notes.txt
  [ ${#EXAMPLES[@]} -eq 0 ]
}

@test "parse_args: unknown option or stray argument shows usage" {
  run parse_args -x
  [ "$status" -eq 1 ]
  [[ $output == *"sudo ./install.sh"* ]]
  run parse_args -e vpn stray
  [ "$status" -eq 1 ]
  [[ $output == *"unexpected argument: stray"* ]]
}

# ------------------------------------------------------------- add_bait
@test "add_bait: a new file is created and marked created" {
  add_bait "$T/home/a" tpl
  [ "${BAITS[*]}" = "$T/home/a" ]
  [ "${PAIRS[*]}" = "tpl $T/home/a" ]
  [ "${CREATED[*]}" = "$T/home/a" ]
}

@test "add_bait: an existing file is watched, never marked created" {
  touch "$T/home/real"
  add_bait "$T/home/real" tpl
  [ "${BAITS[*]}" = "$T/home/real" ]
  [ ${#PAIRS[@]} -eq 0 ]
  [ ${#CREATED[@]} -eq 0 ]
}

@test "add_bait: an existing file an earlier install created stays created" {
  touch "$T/home/old"
  PREV_CREATED=" $T/home/old "
  add_bait "$T/home/old" tpl
  [ "${CREATED[*]}" = "$T/home/old" ]
  [ ${#PAIRS[@]} -eq 0 ]
}

@test "add_bait: the same path twice is added once" {
  add_bait "$T/home/a" tpl
  add_bait "$T/home/a" tpl
  [ ${#BAITS[@]} -eq 1 ]
  [ ${#PAIRS[@]} -eq 2 ]
}

@test "add_bait: refuses blanks, globs, folders and symlinks" {
  run add_bait "$T/home/a b" tpl
  [ "$status" -eq 1 ]
  [[ $output == *"can't contain spaces"* ]]
  run add_bait "$T/home/a*" tpl
  [ "$status" -eq 1 ]
  run add_bait "$T/home" tpl
  [ "$status" -eq 1 ]
  [[ $output == *"is a directory"* ]]
  mkdir "$T/elsewhere"; ln -s "$T/elsewhere" "$T/home/.aws"
  run add_bait "$T/home/.aws/credentials" tpl
  [ "$status" -eq 1 ]
  [[ $output == *"goes through a symlink"* ]]
}

# ------------------------------------------------------------- add_example / add_file
@test "add_example: every file of the decoy, under the home folder" {
  add_example .aws
  [ "${BAITS[*]}" = "$T/home/.aws/config $T/home/.aws/credentials" ]
  [ "${PAIRS[0]}" = "$ROOT/examples/.aws/config" ]
}

@test "add_example: refuses to overwrite a real file" {
  mkdir -p "$T/home/vpn"; echo real >"$T/home/vpn/office-wg0.conf"
  run add_example vpn
  [ "$status" -eq 1 ]
  [[ $output == *"already exists and looks real"* ]]
}

@test "add_example: re-uses a bait from an earlier install" {
  mkdir -p "$T/home/vpn"; echo old >"$T/home/vpn/office-wg0.conf"
  PREV_BAITS=" $T/home/vpn/office-wg0.conf "
  add_example vpn
  [ "${BAITS[*]}" = "$T/home/vpn/office-wg0.conf" ]
  [ ${#PAIRS[@]} -eq 0 ]
}

@test "add_example: refuses unknown or escaping names" {
  for ex in nope ../install.sh /etc . ""; do
    run add_example "$ex"
    [ "$status" -eq 1 ] || { echo "accepted '$ex'"; return 1; }
    [[ $output == *"no such example"* ]]
  done
}

@test "add_file: relative to home, tidied, absolute kept" {
  add_file notes.txt
  add_file ./a/../b.txt
  add_file "$T/abs.txt"
  [ "${BAITS[*]}" = "$T/home/notes.txt $T/home/b.txt $T/abs.txt" ]
  [ "${PAIRS[0]}" = "$ROOT/examples/password.txt" ]
}

@test "add_file: a symlinked file is refused, not resolved" {
  touch "$T/target"; ln -s "$T/target" "$T/home/link"
  run add_file link
  [ "$status" -eq 1 ]
  [[ $output == *"goes through a symlink"* ]]
}

@test "collect_baits: examples then files; nothing at all is refused" {
  EXAMPLES=(password.txt); FILES=(x.txt)
  collect_baits
  [ "${BAITS[*]}" = "$T/home/password.txt $T/home/x.txt" ]
  EXAMPLES=(); FILES=(); BAITS=()
  run collect_baits
  [ "$status" -eq 1 ]
  [[ $output == *"no bait files"* ]]
}

@test "load_previous: canonical, space-padded lists from the installed config" {
  mkdir -p "$T/etc" "$T/real"; ln -s "$T/real" "$T/link"
  printf 'BAIT_FILE=%s/link/a %s/b\nBAIT_CREATED=%s/b\n' "$T" "$T" "$T" >"$CONF_PATH"
  echo "BAIT_FILE=$T/legacy" >"$LEGACY_CONF"
  load_previous
  [ "$PREV_BAITS" = " $T/real/a $T/b $T/legacy  " ]
  [ "$PREV_CREATED" = " $T/b  " ]
}

# ------------------------------------------------------------- refuse_collisions
collisions_setup() {
  SYSTEM_UNIT_DIRS=("$T/sys")
  mkdir -p "$T/sys" "$T/etc"
  UNIT_FILE=$T/etc/svc.service
  HANDLER_PATH=$T/etc/handler
}

@test "refuse_collisions: nothing there is fine" {
  collisions_setup
  refuse_collisions
}

@test "refuse_collisions: a distribution unit of that name" {
  collisions_setup
  touch "$T/sys/svc.service"
  run refuse_collisions
  [ "$status" -eq 1 ]
  [[ $output == *"is a real unit"* ]]
}

@test "refuse_collisions: someone else's unit, handler, rules or config" {
  collisions_setup
  echo 'ExecStart=/usr/bin/other' >"$UNIT_FILE"
  run refuse_collisions
  [ "$status" -eq 1 ]
  [[ $output == *"change SERVICE_NAME"* ]]
  rm "$UNIT_FILE"
  echo real >"$HANDLER_PATH"
  run refuse_collisions
  [ "$status" -eq 1 ]
  [[ $output == *"change HANDLER_PATH"* ]]
  rm "$HANDLER_PATH"
  echo '-w /x -k other' >"$RULES_FILE"
  run refuse_collisions
  [ "$status" -eq 1 ]
  [[ $output == *"change RULES_NAME"* ]]
  rm "$RULES_FILE"
  echo 'something=else' >"$CONF_PATH"
  run refuse_collisions
  [ "$status" -eq 1 ]
  [[ $output == *"change CONF_PATH"* ]]
}

@test "refuse_collisions: our own earlier install (or the legacy one) is fine" {
  collisions_setup
  cp "$ROOT/honeypot-handler.py" "$HANDLER_PATH"
  echo "ExecStart=$LEGACY_HANDLER" >"$UNIT_FILE"
  echo "-w /x -p wa -k $AUDIT_KEY" >"$RULES_FILE"
  echo "AUDIT_KEY=$AUDIT_KEY" >"$CONF_PATH"
  refuse_collisions
}

# ------------------------------------------------------------- syscalls, rules
@test "check_python: 3.7 or newer passes, older or broken is fatal" {
  fake python3 'exit 0'
  check_python
  fake python3 '[[ $2 == *print* ]] && echo 3.6; [[ $2 == *print* ]]'
  run check_python
  [ "$status" -eq 1 ]
  [[ $output == *"python3 is 3.6"* ]]
  fake python3 'exit 127'
  run check_python
  [ "$status" -eq 1 ]
  [[ $output == *"doesn't run"* ]]
}

@test "check_python: the real python3 passes" {
  check_python
}

@test "install_deps: refuses NixOS before installing anything" {
  NIXOS_MARK=$T/NIXOS
  touch "$NIXOS_MARK"
  run install_deps
  [ "$status" -eq 1 ]
  [[ $output == *"NixOS isn't supported"* ]]
}

@test "probe_syscalls: keeps only what ausyscall knows, per arch" {
  fake ausyscall '[[ $1 == b64 && ( $2 == openat || $2 == openat2 ) ]]'
  probe_syscalls
  [ "${SC[b64]}" = " -S openat -S openat2" ]
  [ "${SC[b32]}" = "" ]
}

@test "probe_syscalls: none known is fatal" {
  fake ausyscall 'exit 1'
  run probe_syscalls
  [ "$status" -eq 1 ]
  [[ $output == *"can't resolve the open syscalls"* ]]
}

@test "rules_text: a watch plus one open rule per known arch, per bait" {
  BAITS=(/h/a /h/b); SC[b64]=" -S open -S openat"; SC[b32]=""
  [ "$(rules_text)" = "$(cat <<EOF
-w /h/a -p wa -k k1
-a always,exit -F arch=b64 -S open -S openat -F path=/h/a -k k1
-w /h/b -p wa -k k1
-a always,exit -F arch=b64 -S open -S openat -F path=/h/b -k k1
EOF
)" ]
}

LOADED_NEW='-w /h/a -p wa -k k1
-a always,exit -F arch=b64 -S open,openat -F path=/h/a -F key=k1'
LOADED_OLD='-a always,exit -F path=/h/a -F perm=wa -F key=k1
-a always,exit -F arch=b64 -S openat -F path=/h/a -F key=k1'
ENABLED='enabled 1
pid 42'

@test "verify_rules: accepts both auditctl -l formats" {
  BAITS=(/h/a)
  verify_rules "$LOADED_NEW" "$ENABLED"
  verify_rules "$LOADED_OLD" "$ENABLED"
}

@test "verify_rules: a missing watch or open rule is fatal" {
  BAITS=(/h/a)
  run verify_rules "$(grep -v -- -S <<<"$LOADED_NEW")" "$ENABLED"
  [ "$status" -eq 1 ]
  [[ $output == *"open rule for /h/a"* ]]
  run verify_rules "$(grep -- -S <<<"$LOADED_NEW")" "$ENABLED"
  [ "$status" -eq 1 ]
  [[ $output == *"write watch for /h/a"* ]]
}

@test "verify_rules: rules for another path or key don't count" {
  BAITS=(/h/a)
  run verify_rules "${LOADED_NEW//\/h\/a/\/h\/a.bak}" "$ENABLED"
  [ "$status" -eq 1 ]
  run verify_rules "${LOADED_NEW//k1/k10}" "$ENABLED"
  [ "$status" -eq 1 ]
}

@test "verify_rules: auditing disabled or silenced is fatal" {
  BAITS=(/h/a)
  run verify_rules "$LOADED_NEW" "enabled 0"
  [ "$status" -eq 1 ]
  [[ $output == *"auditing is disabled"* ]]
  run verify_rules "$LOADED_NEW"$'\n-a never,task' "$ENABLED"
  [ "$status" -eq 1 ]
  [[ $output == *"never,task"* ]]
  # filtered never,task rules (e.g. for one program) are fine
  verify_rules "$LOADED_NEW"$'\n-a never,task -F exe=/usr/bin/x' "$ENABLED"
}

@test "preflight_audit: refuses a rules file or loaded rule that silences auditing" {
  AUDIT_RULES_DIR=$T/rules.d; mkdir -p "$AUDIT_RULES_DIR"
  printf -- '-D\n-a exit,never -F arch=b64 -S adjtimex\n' >"$AUDIT_RULES_DIR/audit.rules"
  preflight_audit "$LOADED_NEW"
  echo '-a task,never' >>"$AUDIT_RULES_DIR/audit.rules"
  run preflight_audit "$LOADED_NEW"
  [ "$status" -eq 1 ]
  [[ $output == *"$AUDIT_RULES_DIR/audit.rules has a '-a task,never' rule"* ]]
  rm "$AUDIT_RULES_DIR/audit.rules"
  run preflight_audit "$LOADED_NEW"$'\n-a never,task'
  [ "$status" -eq 1 ]
  [[ $output == *"is loaded"* ]]
}

@test "preflight_audit: a commented-out or filtered rule is fine" {
  AUDIT_RULES_DIR=$T/rules.d; mkdir -p "$AUDIT_RULES_DIR"
  printf -- '# -a task,never\n-a never,task -F exe=/usr/bin/x\n' >"$AUDIT_RULES_DIR/audit.rules"
  preflight_audit ""
}

@test "unseen_baits: both ausearch name formats" {
  BAITS=(/h/a /h/b /h/c)
  run unseen_baits 'type=PATH msg=x item=0 name=/h/a inode=1
type=PATH msg=x item=0 name="/h/b" inode=2'
  [ "$output" = /h/c ]
}

@test "unit_text: runs the handler and is recognised as ours" {
  HANDLER_PATH=/usr/lib/x/helper SERVICE_DESCRIPTION="Some Helper"
  unit_text >"$T/u"
  grep -qx "Description=Some Helper" "$T/u"
  unit_is_ours "$T/u" /usr/lib/x/helper
}

# ------------------------------------------------------------- baits on disk
@test "create_baits: renders, owns, backdates; existing folders keep their date" {
  touch -d "2020-01-02" "$T/home"
  before=$(mtime "$T/home")
  BAITS=(); add_example vpn; add_example password.txt
  create_baits >/dev/null
  for f in "$T/home/vpn/office-wg0.conf" "$T/home/password.txt"; do
    [ -s "$f" ]
    [ "$(stat -c '%a %U' "$f")" = "600 $TARGET_USER" ]
    is_old "$f"
    not grep -q '@@' "$f"
  done
  [ "$(stat -c %a "$T/home/vpn")" = 700 ]
  is_old "$T/home/vpn"
  [ "$(mtime "$T/home")" = "$before" ]
  [ "$RENDERED" = yes ]
}

@test "create_baits: an existing -f file is left exactly as it was" {
  echo mine >"$T/home/notes.txt"
  touch -d "2021-03-04" "$T/home/notes.txt"
  before=$(mtime "$T/home/notes.txt")
  add_file notes.txt
  create_baits >/dev/null
  [ "$(cat "$T/home/notes.txt")" = mine ]
  [ "$(mtime "$T/home/notes.txt")" = "$before" ]
}

@test "create_baits: notes earlier baits that are no longer watched" {
  touch "$T/home/old-bait"
  PREV_BAITS=" $T/home/old-bait "
  add_file new.txt
  run create_baits
  [[ $output == *"note: $T/home/old-bait is no longer watched"* ]]
}

# ------------------------------------------------------------- on_failure
@test "on_failure: success does nothing" {
  WAS_ACTIVE=yes
  on_failure
  [ ! -e "$T/calls" ]
}

@test "on_failure: before commit, removes what this run created, restores dates" {
  echo mine >"$T/home/notes.txt"
  touch -d "2020-01-02" "$T/home"
  before=$(mtime "$T/home")
  add_file notes.txt; add_example .kube
  create_baits >/dev/null
  ( ( exit 3 ) || on_failure 2>/dev/null )   # subshell: on_failure turns off -e
  [ ! -e "$T/home/.kube" ]
  [ "$(cat "$T/home/notes.txt")" = mine ]
  [ "$(mtime "$T/home")" = "$before" ]
}

@test "on_failure: after commit, the baits stay" {
  add_example password.txt
  create_baits >/dev/null
  COMMITTED=yes
  ( ( exit 3 ) || on_failure 2>/dev/null )   # subshell: on_failure turns off -e
  [ -e "$T/home/password.txt" ]
}

@test "on_failure: reloads our rules file (even half-loaded), restarts the service" {
  echo "-w /x -p wa -k $AUDIT_KEY" >"$RULES_FILE"
  fake auditctl "[[ \$1 == -l ]] && echo '-w /x -p wa -k $AUDIT_KEY'; true"
  WAS_ACTIVE=yes
  sleep() { :; }
  ( ( exit 3 ) || on_failure 2>/dev/null )   # subshell: on_failure turns off -e
  grep -qx "auditctl -D -k $AUDIT_KEY" "$T/calls"
  grep -qx "auditctl -R $RULES_FILE" "$T/calls"
  grep -qx "systemctl start $SERVICE_NAME" "$T/calls"
}

@test "on_failure: never loads someone else's file, no restart if it wasn't running" {
  echo "-w /y -p wa -k someone-else" >"$LEGACY_RULES"
  ( ( exit 3 ) || on_failure 2>/dev/null )   # subshell: on_failure turns off -e
  not grep -q -- "-R" "$T/calls"
  not grep -q systemctl "$T/calls"
}

@test "load_rules: a partial load is retried with our rules alone" {
  add_example password.txt
  probe_syscalls
  fake augenrules "exit 1"
  # first listing: the open rule is missing; after the reload, everything is there
  fake auditctl "if [[ \$1 == -l ]]; then if grep -q -- '-R' '$T/calls'; then cat '$RULES_FILE'; else grep -v -- -S '$RULES_FILE'; fi; fi; true"
  sleep() { :; }
  load_rules >/dev/null
  grep -qx "auditctl -D -k $AUDIT_KEY" "$T/calls"
  [ "$(grep -c -- "-R $RULES_FILE" "$T/calls")" -eq 1 ]
}

@test "reload_rules: retries until every rule of the file is loaded" {
  printf -- '-w /x -p wa -k k1\n-a always,exit -S openat -F path=/x -k k1\n' >"$RULES_FILE"
  # the watch only "loads" on the second -R
  fake auditctl "if [[ \$1 == -l ]]; then n=\$(grep -c -- '-R' '$T/calls'); cat '$RULES_FILE' | head -n \$n; fi; true"
  sleep() { :; }
  reload_rules "$RULES_FILE" k1
  [ "$(grep -c -- "-R $RULES_FILE" "$T/calls")" -eq 2 ]
  [ "$(grep -c -- "-D -k k1" "$T/calls")" -eq 2 ]
}

@test "reload_rules: gives up after 3 tries" {
  echo '-w /x -p wa -k k1' >"$RULES_FILE"
  sleep() { :; }
  run reload_rules "$RULES_FILE" k1
  [ "$status" -eq 1 ]
  [ "$(grep -c -- "-R $RULES_FILE" "$T/calls")" -eq 3 ]
}

@test "load_rules: a complete load isn't touched" {
  add_example password.txt
  probe_syscalls
  fake auditctl "[[ \$1 == -l ]] && cat '$RULES_FILE'; true"
  load_rules >/dev/null
  not grep -q -- "-R" "$T/calls"
  not grep -q -- "-D" "$T/calls"
}

# ------------------------------------------------------------- config
@test "install_config: an existing config keeps its settings, names and baits re-synced" {
  mkdir -p "$T/etc"
  printf 'AUDIT_KEY=old\nNTFY_URL=https://mine\nBAIT_FILE=/old\n' >"$CONF_PATH"
  BAITS=(/h/a /h/b); CREATED=(/h/a)
  HANDLER_PATH=/x/h SERVICE_DESCRIPTION=d REPORT_DIR=/var/lib/x RULES_NAME=r NFT_TABLE=t
  install_config >/dev/null
  [ "$(conf_get "$CONF_PATH" NTFY_URL)" = https://mine ]
  [ "$(conf_get "$CONF_PATH" AUDIT_KEY)" = k1 ]
  [ "$(conf_get "$CONF_PATH" BAIT_FILE)" = "/h/a /h/b" ]
  [ "$(conf_get "$CONF_PATH" BAIT_CREATED)" = /h/a ]
  [ "$(stat -c %a "$CONF_PATH")" = 600 ]
  [ "$COMMITTED" = yes ]
}

# ------------------------------------------------------------- main
@test "main: sourcing runs nothing; running needs root" {
  [ ! -e "$T/calls" ]
  [ "$EUID" -ne 0 ] || skip "running as root"
  run bash "$ROOT/install.sh" -u nobody
  [ "$status" -eq 1 ]
  [[ $output == *"run with sudo"* ]]
}
