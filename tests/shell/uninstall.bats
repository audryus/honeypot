#!/usr/bin/env bats
# Unit tests for uninstall.sh's functions. No root needed: uninstall.sh is
# sourced (main doesn't run), every path points into a temp dir and the system
# tools are fake scripts on PATH that log their arguments to $T/calls.

setup() {
  T=$(mktemp -d)
  T=$(realpath "$T")
  ROOT=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
  # shellcheck source=../../uninstall.sh
  . "$ROOT/uninstall.sh"
  FAKEBIN=$T/bin
  mkdir -p "$FAKEBIN" "$T/home/alice" "$T/etc" "$T/reports"
  for cmd in systemctl auditctl augenrules nft; do
    printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\n' "$cmd" "$T" >"$FAKEBIN/$cmd"
    chmod +x "$FAKEBIN/$cmd"
  done
  PATH="$FAKEBIN:$PATH"

  HOMES=" $T/home/alice "
  CONF_PATH=$T/etc/agent.conf
  LEGACY_CONF=$T/etc/legacy.conf
  REPORT_DIR=$T/reports
  LEGACY_REPORTS=$T/legacy-reports
  home_dirs() { echo "$HOMES"; }   # instead of every home folder in getent passwd
  NIXOS_MARK=$T/NIXOS   # absent: not NixOS
}

teardown() {
  rm -rf "$T"
}

# `! cmd` and `[ a ] && [ b ]` never fail a bats test (set -e ignores both),
# so negative checks use `not cmd` and checks are one per line.
not() { if "$@"; then echo "unexpectedly succeeded: $*"; return 1; fi; }

bait() { mkdir -p "$(dirname "$1")"; echo bait >"$1"; }

# ------------------------------------------------------------- parse_args
@test "parse_args: nothing or --purge" {
  parse_args
  [ "$PURGE" = no ]
  parse_args --purge
  [ "$PURGE" = yes ]
}

@test "parse_args: anything else shows usage" {
  run parse_args --force
  [ "$status" -eq 1 ]
  [[ $output == *"uninstall.sh [--purge]"* ]]
  run parse_args --purge extra
  [ "$status" -eq 1 ]
}

# ------------------------------------------------------------- purge_bait
@test "purge_bait: deletes a created bait and the folders it emptied, not the home" {
  bait "$T/home/alice/.aws/sub/credentials"
  run purge_bait "$T/home/alice/.aws/sub/credentials" "$T/home/alice/.aws/sub/credentials" "$HOMES"
  [[ $output == "deleted bait $T/home/alice/.aws/sub/credentials" ]]
  [ ! -e "$T/home/alice/.aws" ]
  [ -d "$T/home/alice" ]
}

@test "purge_bait: a folder with other files in it stays" {
  bait "$T/home/alice/.aws/credentials"
  echo real >"$T/home/alice/.aws/other"
  purge_bait "$T/home/alice/.aws/credentials" "$T/home/alice/.aws/credentials" "$HOMES" >/dev/null
  [ ! -e "$T/home/alice/.aws/credentials" ]
  [ -e "$T/home/alice/.aws/other" ]
}

@test "purge_bait: a bait the installer didn't create is kept" {
  bait "$T/home/alice/notes.txt"
  run purge_bait "$T/home/alice/notes.txt" "$T/home/alice/other" "$HOMES"
  [ -e "$T/home/alice/notes.txt" ]
  [[ $output == "kept $T/home/alice/notes.txt"* ]]
}

@test "purge_bait: 'created' must match the whole path" {
  bait "$T/home/alice/a"
  purge_bait "$T/home/alice/a" "$T/home/alice/a.bak $T/home/alice/aa" "$HOMES" >/dev/null
  [ -e "$T/home/alice/a" ]
}

@test "purge_bait: never follows a symlink swapped in on the way" {
  mkdir -p "$T/system"; echo important >"$T/system/credentials"
  ln -s "$T/system" "$T/home/alice/.aws"
  run purge_bait "$T/home/alice/.aws/credentials" "$T/home/alice/.aws/credentials" "$HOMES"
  [[ $output == SKIPPED* ]]
  [ "$(cat "$T/system/credentials")" = important ]
}

@test "purge_bait: a relative path is skipped" {
  run purge_bait "rel/x" "rel/x" "$HOMES"
  [[ $output == SKIPPED* ]]
}

@test "purge_bait: a bait that's already gone is fine" {
  purge_bait "$T/home/alice/gone" "$T/home/alice/gone" "$HOMES" >/dev/null
  [ -d "$T/home/alice" ]
}

# ------------------------------------------------------------- purge
@test "purge: config, reports and created baits go; the user's own files stay" {
  bait "$T/home/alice/password.txt"
  bait "$T/home/alice/vpn/wg0.conf"
  echo mine >"$T/home/alice/notes.txt"
  printf 'AUDIT_KEY=k\nBAIT_FILE=%s\nBAIT_CREATED=%s\n' \
    "$T/home/alice/password.txt $T/home/alice/vpn/wg0.conf $T/home/alice/notes.txt" \
    "$T/home/alice/password.txt $T/home/alice/vpn/wg0.conf" >"$CONF_PATH"
  touch "$REPORT_DIR/20260101-000000-1.log" "$REPORT_DIR/state"
  purge >/dev/null
  [ ! -e "$CONF_PATH" ]
  [ ! -e "$REPORT_DIR" ]
  [ ! -e "$T/home/alice/password.txt" ]
  [ ! -e "$T/home/alice/vpn" ]
  [ "$(cat "$T/home/alice/notes.txt")" = mine ]
}

@test "purge: a config without BAIT_CREATED (old install) deletes no bait" {
  bait "$T/home/alice/password.txt"
  printf 'AUDIT_KEY=k\nBAIT_FILE=%s\n' "$T/home/alice/password.txt" >"$CONF_PATH"
  run purge
  [ -e "$T/home/alice/password.txt" ]
  [[ $output == *"kept $T/home/alice/password.txt"* ]]
}

@test "purge: falls back to the legacy config's bait list (kept: no BAIT_CREATED)" {
  bait "$T/home/alice/old.txt"
  printf 'AUDIT_KEY=honeypot\nBAIT_FILE=%s\n' "$T/home/alice/old.txt" >"$LEGACY_CONF"
  run purge
  [ ! -e "$LEGACY_CONF" ]
  [[ $output == *"kept $T/home/alice/old.txt"* ]]
}

@test "purge: a file at CONF_PATH that isn't ours is left alone" {
  echo 'something=else' >"$CONF_PATH"
  purge >/dev/null
  [ -e "$CONF_PATH" ]
}

@test "purge: a bait list can't glob" {
  bait "$T/home/alice/a1"
  printf 'AUDIT_KEY=k\nBAIT_FILE=%s\nBAIT_CREATED=%s\n' "$T/home/alice/a*" "$T/home/alice/a*" >"$CONF_PATH"
  purge >/dev/null
  [ -e "$T/home/alice/a1" ]
}

# ------------------------------------------------------------- remove_service, main
@test "remove_service: removes current and legacy installs, reloads" {
  SERVICE_NAME=svc UNIT_FILE=$T/svc.service HANDLER_PATH=$T/h RULES_FILE=$T/r AUDIT_KEY=k1 NFT_TABLE=t1
  echo "ExecStart=$T/h" >"$UNIT_FILE"
  cp "$ROOT/honeypot-handler.py" "$T/h"
  echo '-w /x -p wa -k k1' >"$T/r"
  remove_service
  [ ! -e "$UNIT_FILE" ]
  [ ! -e "$T/h" ]
  [ ! -e "$T/r" ]
  grep -qx 'auditctl -D -k k1' "$T/calls"
  grep -qx "auditctl -D -k $LEGACY_KEY" "$T/calls"
  grep -qx 'nft delete table inet t1' "$T/calls"
  grep -qx 'systemctl daemon-reload' "$T/calls"
  grep -qx 'augenrules --load' "$T/calls"
}

@test "remove_service: never runs augenrules on NixOS" {
  SERVICE_NAME=svc UNIT_FILE=$T/svc.service HANDLER_PATH=$T/h RULES_FILE=$T/r AUDIT_KEY=k1 NFT_TABLE=t1
  touch "$NIXOS_MARK"
  remove_service
  grep -qx 'auditctl -D -k k1' "$T/calls"
  not grep -q augenrules "$T/calls"
}

@test "main: sourcing runs nothing; running needs root" {
  [ ! -e "$T/calls" ]
  [ "$EUID" -ne 0 ] || skip "running as root"
  run bash "$ROOT/uninstall.sh" --purge
  [ "$status" -eq 1 ]
  [[ $output == *"run with sudo"* ]]
}
