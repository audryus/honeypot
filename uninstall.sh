#!/usr/bin/env bash
# Remove the tripwire. Keeps baits, config and reports unless --purge (baits: only the ones the installer created).
#   sudo ./uninstall.sh [--purge]
# Uses the names from ./honeypot.conf (or the .example) next to this script, so
# run it BEFORE changing names there. Old "honeypot"-named installs are removed too.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$HERE/common.sh"

[[ $EUID -eq 0 ]] || die "run with sudo"
PURGE=no
case ${1:-} in
  "") ;;
  --purge) PURGE=yes ;;
  *) sed -n '2,5p' "$0"; exit 1 ;;
esac
load_names

BAIT=$(conf_get "$CONF_PATH" BAIT_FILE)
[[ -n $BAIT ]] || BAIT=$(conf_get "$LEGACY_CONF" BAIT_FILE)
# Only baits the installer created are ever deleted; an existing file watched
# with -f is the user's own. Configs from before BAIT_CREATED existed don't say
# which is which, so nothing is deleted for them (the files are listed instead).
CREATED=$(conf_get "$CONF_PATH" BAIT_CREATED)

remove_install "$UNIT_FILE" "$HANDLER_PATH" "$RULES_FILE" "$AUDIT_KEY" "$NFT_TABLE"
remove_install "/etc/systemd/system/$LEGACY_SERVICE.service" "$LEGACY_HANDLER" "$LEGACY_RULES" "$LEGACY_KEY" "$LEGACY_TABLE"
systemctl daemon-reload
augenrules --load >/dev/null 2>&1

if [[ $PURGE == yes ]]; then
  for c in "$CONF_PATH" "$LEGACY_CONF"; do
    conf_is_ours "$c" && rm -f "$c"
  done
  remove_reports "$REPORT_DIR"
  remove_reports "$LEGACY_REPORTS"
  for b in $BAIT; do   # space-separated lists
    if [[ " $CREATED " != *" $b "* ]]; then
      [[ -e $b ]] && echo "kept $b (it existed before the install, or the install predates tracking: delete it yourself if it's a bait)"
      continue
    fi
    rm -f "$b" && echo "deleted bait $b"
    d=$(dirname "$b")  # drop folders the decoy created, if now empty (rmdir never removes non-empty ones)
    while [[ $d != / ]] && rmdir "$d" 2>/dev/null; do d=$(dirname "$d"); done
  done
  echo "removed (purged config, reports and the bait files the installer created)"
else
  echo "removed (kept $CONF_PATH, $REPORT_DIR/ and the bait files; --purge deletes them)"
fi
