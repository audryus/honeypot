#!/usr/bin/env bats
# Unit tests for common.sh. No root needed: everything happens in a temp dir,
# and system tools (systemctl, auditctl, nft) are fake scripts on PATH.

setup() {
  T=$(mktemp -d)
  ROOT=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  # shellcheck source=../../common.sh
  . "$ROOT/common.sh"
  HERE=$T   # load_names reads $HERE/honeypot.conf(.example)
  NIXOS_MARK=$T/NIXOS   # absent: not NixOS (tests create it when they mean NixOS)
  FAKEBIN=$T/bin
  mkdir -p "$FAKEBIN"
  for cmd in systemctl auditctl nft; do
    printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\n' "$cmd" "$T" >"$FAKEBIN/$cmd"
    chmod +x "$FAKEBIN/$cmd"
  done
  PATH="$FAKEBIN:$PATH"
}

teardown() {
  rm -rf "$T"
}

# `! cmd` and `[ a ] && [ b ]` never fail a bats test (set -e ignores both),
# so negative checks use `not cmd` and checks are one per line.
not() { if "$@"; then echo "unexpectedly succeeded: $*"; return 1; fi; }

# ------------------------------------------------------------- conf_get
@test "conf_get: plain value" {
  printf 'A=1\nB=two words\n' >"$T/c"
  [ "$(conf_get "$T/c" B)" = "two words" ]
}

@test "conf_get: last occurrence wins" {
  printf 'A=1\nA=2\n' >"$T/c"
  [ "$(conf_get "$T/c" A)" = 2 ]
}

@test "conf_get: strips quotes and surrounding blanks" {
  printf 'A = "x y" \nB='"'"'z'"'"'\n' >"$T/c"
  [ "$(conf_get "$T/c" A)" = "x y" ]
  [ "$(conf_get "$T/c" B)" = z ]
}

@test "conf_get: keeps = inside the value" {
  echo 'URL=https://h/x?a=b' >"$T/c"
  [ "$(conf_get "$T/c" URL)" = "https://h/x?a=b" ]
}

@test "conf_get: ignores comments and longer keys" {
  printf '# A=commented\nAB=other\n' >"$T/c"
  [ "$(conf_get "$T/c" A dflt)" = dflt ]
}

@test "conf_get: default for empty value or missing file" {
  echo 'A=' >"$T/c"
  [ "$(conf_get "$T/c" A dflt)" = dflt ]
  [ "$(conf_get "$T/missing" A dflt)" = dflt ]
  [ "$(conf_get "$T/missing" A)" = "" ]
}

# ------------------------------------------------------------- conf_set
@test "conf_set: replaces in place" {
  printf 'A=1\nB=2\nC=3\n' >"$T/c"
  conf_set "$T/c" B new
  [ "$(cat "$T/c")" = "$(printf 'A=1\nB=new\nC=3')" ]
}

@test "conf_set: appends a missing key" {
  echo 'A=1' >"$T/c"
  conf_set "$T/c" Z 9
  [ "$(cat "$T/c")" = "$(printf 'A=1\nZ=9')" ]
}

@test "conf_set: leaves comments and longer keys alone" {
  printf '# A=doc\nAB=x\n' >"$T/c"
  conf_set "$T/c" A v
  [ "$(cat "$T/c")" = "$(printf '# A=doc\nAB=x\nA=v')" ]
}

@test "conf_set: values with / & | \\ are written literally" {
  echo 'A=1' >"$T/c"
  conf_set "$T/c" A 'a/b&c|d\e'
  [ "$(conf_get "$T/c" A)" = 'a/b&c|d\e' ]
}

@test "conf_set: keeps the file's permissions" {
  echo 'A=1' >"$T/c"
  chmod 600 "$T/c"
  conf_set "$T/c" A 2
  [ "$(stat -c %a "$T/c")" = 600 ]
}

# ------------------------------------------------------------- load_names
@test "load_names: defaults when the config sets nothing" {
  : >"$T/honeypot.conf"
  load_names
  [ "$SRC_CONF" = "$T/honeypot.conf" ]
  [ "$SERVICE_NAME" = polkit-agent-helper ]
  [ "$AUDIT_KEY" = pk-auth ]
  [ "$UNIT_FILE" = /etc/systemd/system/polkit-agent-helper.service ]
  [ "$RULES_FILE" = /etc/audit/rules.d/50-polkit.rules ]
}

@test "load_names: reads the config" {
  printf 'SERVICE_NAME=foo-agent\nRULES_NAME=10-foo\nNFT_TABLE=t1\n' >"$T/honeypot.conf"
  load_names
  [ "$UNIT_FILE" = /etc/systemd/system/foo-agent.service ]
  [ "$RULES_FILE" = /etc/audit/rules.d/10-foo.rules ]
  [ "$NFT_TABLE" = t1 ]
}

@test "load_names: NixOS puts the unit in the control folder, rules stay root-only" {
  : >"$T/honeypot.conf"
  touch "$NIXOS_MARK"
  load_names
  [ "$UNIT_DIR" = /etc/systemd/system.control ]
  [ "$UNIT_FILE" = /etc/systemd/system.control/polkit-agent-helper.service ]
  [ "$RULES_FILE" = /etc/audit/rules.d/50-polkit.rules ]
}

@test "load_names: falls back to the .example" {
  echo 'AUDIT_KEY=from-example' >"$T/honeypot.conf.example"
  load_names
  [ "$SRC_CONF" = "$T/honeypot.conf.example" ]
  [ "$AUDIT_KEY" = from-example ]
}

@test "load_names: no config at all" {
  run load_names
  [ "$status" -eq 1 ]
  [[ $output == *"no honeypot.conf"* ]]
}

@test "load_names: the shipped example is valid" {
  cp "$ROOT/honeypot.conf.example" "$T/"
  load_names
}

bad_name() { # KEY VALUE expected-message
  printf '%s=%s\n' "$1" "$2" >"$T/honeypot.conf"
  run load_names
  [ "$status" -eq 1 ] || { echo "accepted $1=$2"; return 1; }
  [[ $output == *"$3"* ]] || { echo "wrong message: $output"; return 1; }
}

@test "load_names: refuses bad names" {
  bad_name SERVICE_NAME 'a b' SERVICE_NAME
  bad_name SERVICE_NAME 'x;rm' SERVICE_NAME
  bad_name SERVICE_DESCRIPTION 'a$b' SERVICE_DESCRIPTION
  bad_name RULES_NAME '../x' RULES_NAME
  bad_name AUDIT_KEY 'a"b' AUDIT_KEY
  bad_name AUDIT_KEY "$(printf 'k%.0s' {1..32})" AUDIT_KEY
  bad_name NFT_TABLE 1abc NFT_TABLE
  bad_name NFT_TABLE a-b NFT_TABLE
  bad_name HANDLER_PATH relative/path HANDLER_PATH
  bad_name CONF_PATH '/etc/x y' CONF_PATH
  bad_name REPORT_DIR /var/lib/../etc REPORT_DIR
  bad_name REPORT_DIR /var/lib "too broad"
  bad_name REPORT_DIR /home "too broad"
}

@test "load_names: accepts a 31-char audit key" {
  printf 'AUDIT_KEY=%s\n' "$(printf 'k%.0s' {1..31})" >"$T/honeypot.conf"
  load_names
}

# ------------------------------------------------------------- no_symlink
@test "no_symlink: real paths, existing or not" {
  mkdir -p "$T/real/dir"
  no_symlink "$T/real/dir"
  no_symlink "$T/real/dir/not-yet/file"
}

@test "no_symlink: refuses a path through a symlink" {
  mkdir -p "$T/real"
  ln -s "$T/real" "$T/link"
  not no_symlink "$T/link/file"
  not no_symlink "$T/link"
}

@test "no_symlink: refuses a symlinked file and relative or unnormalised paths" {
  touch "$T/target"
  ln -s "$T/target" "$T/file"
  not no_symlink "$T/file"
  not no_symlink relative/file
  not no_symlink "$T/a/../b"
}

# ------------------------------------------------------------- is it ours?
@test "unit_is_ours: exact ExecStart line only" {
  printf '[Service]\nExecStart=/usr/lib/x/helper\n' >"$T/u"
  unit_is_ours "$T/u" /usr/lib/x/helper
  not unit_is_ours "$T/u" /usr/lib/x/help
  not unit_is_ours "$T/missing" /usr/lib/x/helper
}

@test "handler_is_ours: recognises the real handler" {
  handler_is_ours "$ROOT/honeypot-handler.py"
  not handler_is_ours "$ROOT/render-bait.py"
}

@test "rules_is_ours: key must end the line" {
  echo '-w /x -p wa -k pk-auth' >"$T/r"
  rules_is_ours "$T/r" pk-auth
  echo '-w /x -p wa -k pk-auth2' >"$T/r"
  not rules_is_ours "$T/r" pk-auth
}

@test "conf_is_ours: needs an AUDIT_KEY line" {
  echo 'AUDIT_KEY=x' >"$T/c"
  conf_is_ours "$T/c"
  echo '# AUDIT_KEY=x' >"$T/c"
  not conf_is_ours "$T/c"
}

# ------------------------------------------------------------- remove_reports
@test "remove_reports: only report files and the state, then the empty dir" {
  mkdir "$T/r"
  touch "$T/r/20260101-000000-42.log" "$T/r/state" "$T/r/state.tmp"
  remove_reports "$T/r"
  [ ! -e "$T/r" ]
}

@test "remove_reports: keeps anything else (never rm -rf)" {
  mkdir -p "$T/r/sub"
  touch "$T/r/20260101-000000-42.log" "$T/r/notes.txt" "$T/r/sub/20260101-000000-1.log"
  remove_reports "$T/r"
  [ ! -e "$T/r/20260101-000000-42.log" ]
  [ -e "$T/r/notes.txt" ]
  [ -e "$T/r/sub/20260101-000000-1.log" ]
}

@test "remove_reports: missing dir is fine" {
  remove_reports "$T/none"
}

# ------------------------------------------------------------- remove_install
@test "remove_install: removes our files, unloads the key, drops the table" {
  printf 'ExecStart=%s\n' "$T/h" >"$T/u.service"
  cp "$ROOT/honeypot-handler.py" "$T/h"
  echo '-w /x -p wa -k k1' >"$T/r"
  remove_install "$T/u.service" "$T/h" "$T/r" k1 tbl
  [ ! -e "$T/u.service" ]
  [ ! -e "$T/h" ]
  [ ! -e "$T/r" ]
  grep -qx 'systemctl stop u.service' "$T/calls"
  grep -qx 'systemctl disable u.service' "$T/calls"
  grep -qx 'auditctl -D -k k1' "$T/calls"
  grep -qx 'nft delete table inet tbl' "$T/calls"
}

@test "remove_install: drops the .wants links made by hand (NixOS), keeps others" {
  printf 'ExecStart=%s\n' "$T/h" >"$T/u.service"
  mkdir -p "$T/multi-user.target.wants" "$T/audit-rules-nixos.service.wants"
  ln -s ../u.service "$T/multi-user.target.wants/u.service"
  ln -s ../u.service "$T/audit-rules-nixos.service.wants/u.service"
  ln -s ../other.service "$T/multi-user.target.wants/other.service"
  remove_install "$T/u.service" "$T/h" "$T/r" k1 tbl
  [ ! -e "$T/u.service" ]
  [ ! -L "$T/multi-user.target.wants/u.service" ]
  [ -L "$T/multi-user.target.wants/other.service" ]
  [ ! -e "$T/audit-rules-nixos.service.wants" ]   # emptied: removed
}

@test "remove_install: never deletes files that aren't ours" {
  echo 'ExecStart=/usr/bin/real' >"$T/u.service"
  echo 'real program' >"$T/h"
  echo '-w /x -p wa -k someone-else' >"$T/r"
  remove_install "$T/u.service" "$T/h" "$T/r" k1 tbl
  [ -e "$T/u.service" ]
  [ -e "$T/h" ]
  [ -e "$T/r" ]
  not grep -q systemctl "$T/calls"
}

@test "remove_install: nothing installed is fine" {
  remove_install "$T/none.service" "$T/none" "$T/none.rules" k1 tbl
}
