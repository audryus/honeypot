#!/usr/bin/env bash
# Remove the tripwire. Keeps the bait file, the config and the reports unless --purge.
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
  for b in $BAIT; do   # space-separated list
    rm -f "$b" && echo "deleted bait $b"
    d=$(dirname "$b")  # drop folders the decoy created, if now empty (rmdir never removes non-empty ones)
    while [[ $d != / ]] && rmdir "$d" 2>/dev/null; do d=$(dirname "$d"); done
  done
  echo "removed (purged config, reports and bait files)"
else
  echo "removed (kept $CONF_PATH, $REPORT_DIR/ and the bait files; --purge deletes them)"
fi
