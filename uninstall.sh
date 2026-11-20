#!/usr/bin/env bash
# Remove the tripwire. Keeps baits, config and reports unless --purge (baits: only the ones the installer created).
#   sudo ./uninstall.sh [--purge]
# Uses the names from ./honeypot.conf (or the .example) next to this script, so
# run it BEFORE changing names there. Old "honeypot"-named installs are removed too.
#
# Structure: one function per step, run by main() at the bottom. The file can
# be sourced without running anything (tests/shell/uninstall.bats).

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "$HERE/common.sh"

PURGE=no

usage() { sed -n '2,5p' "$HERE/uninstall.sh"; exit 1; }

parse_args() {
  case ${1:-} in
    "") ;;
    --purge) PURGE=yes ;;
    *) usage ;;
  esac
  [[ $# -le 1 ]] || usage
}

remove_service() {
  remove_install "$UNIT_FILE" "$HANDLER_PATH" "$RULES_FILE" "$AUDIT_KEY" "$NFT_TABLE"
  remove_install "/etc/systemd/system/$LEGACY_SERVICE.service" "$LEGACY_HANDLER" "$LEGACY_RULES" "$LEGACY_KEY" "$LEGACY_TABLE"
  systemctl daemon-reload
  augenrules --load >/dev/null 2>&1 || true
}

home_dirs() { # " /home/a /root ... " (canonical): parent folders are never removed past these
  echo " $(getent passwd | cut -d: -f6 | while IFS= read -r h; do [[ -n $h ]] && realpath -m -- "$h"; done | tr '\n' ' ') "
}

# Only baits the installer created are ever deleted; an existing file watched
# with -f is the user's own. Configs from before BAIT_CREATED existed don't say
# which is which, so nothing is deleted for them (the files are listed instead).
purge_bait() { # bait created-list homes
  local b=$1 d
  if [[ " $2 " != *" $b "* ]]; then
    [[ -e $b ]] && echo "kept $b (it existed before the install, or the install predates tracking: delete it yourself if it's a bait)"
    return 0
  fi
  # We're root in a user's home, maybe months after the install: if a folder
  # on the way was swapped for a symlink (~/.kube -> /etc/selinux), rm would
  # delete a system file. Never follow one.
  if [[ $b != /* ]] || ! no_symlink "$b"; then
    echo "SKIPPED $b: its path now goes through a symlink (it leads to $(realpath -m -- "$b")). Not following it as root: check and delete it yourself"
    return 0
  fi
  rm -f -- "$b" && echo "deleted bait $b"
  d=$(dirname "$b")  # drop folders the decoy created, if now empty (rmdir never removes non-empty ones)
  while [[ $d != / && $3 != *" $d "* ]] && rmdir -- "$d" 2>/dev/null; do d=$(dirname "$d"); done
  return 0
}

purge() {
  local c b baits created homes list
  baits=$(conf_get "$CONF_PATH" BAIT_FILE)
  [[ -n $baits ]] || baits=$(conf_get "$LEGACY_CONF" BAIT_FILE)
  created=$(conf_get "$CONF_PATH" BAIT_CREATED)
  for c in "$CONF_PATH" "$LEGACY_CONF"; do
    if conf_is_ours "$c"; then rm -f "$c"; fi
  done
  remove_reports "$REPORT_DIR"
  remove_reports "$LEGACY_REPORTS"
  homes=$(home_dirs)
  read -ra list <<<"$baits"   # space-separated list (no glob expansion)
  for b in "${list[@]}"; do purge_bait "$b" "$created" "$homes"; done
}

main() {
  set -uo pipefail   # no -e: removal is best effort, one failing step mustn't skip the rest
  parse_args "$@"
  [[ $EUID -eq 0 ]] || die "run with sudo"
  load_names
  remove_service
  if [[ $PURGE == yes ]]; then
    purge
    echo "removed (purged config, reports and the bait files the installer created)"
  else
    echo "removed (kept $CONF_PATH, $REPORT_DIR/ and the bait files; --purge deletes them)"
  fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
