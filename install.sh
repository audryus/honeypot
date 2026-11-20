#!/usr/bin/env bash
# Bait-file tripwire installer (idempotent: safe to re-run).
#   sudo ./install.sh [-u user] [-e example]... [-f file] [-d date]
# -u  user owning the bait            (default: the one running sudo)
# -e  decoy from examples/ (repeatable), copied into that user's home with fresh
#     random secrets; EVERY file of it is watched.  e.g. -e .aws -e .git-credentials
#     Files that already exist (real ones) are never overwritten: install aborts.
# -f  watch this file instead/as well, absolute or relative to that user's home.
#     Created from examples/password.txt if missing; an existing file is watched
#     as is. If it sits in its own folder, that folder and its files are backdated.
# -d  fake modification date, anything `touch -d` accepts (default: "97 days ago")
# No -e/-f: same as -e password.txt.   List decoys: ls -A examples/
# Settings and on-disk names come from ./honeypot.conf next to this script
# (falls back to honeypot.conf.example). See the STEALTH section in that file.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$HERE/common.sh"

TARGET_USER=${SUDO_USER:-}
EXAMPLES=()
FILE_NAME=""
FAKE_DATE="97 days ago"

while getopts "u:e:f:d:h" o; do
  case $o in
    u) TARGET_USER=$OPTARG ;;
    e) EXAMPLES+=("${OPTARG%/}") ;;
    f) FILE_NAME=$OPTARG ;;
    d) FAKE_DATE=$OPTARG ;;
    *) sed -n '2,14p' "$0"; exit 1 ;;
  esac
done
[[ ${#EXAMPLES[@]} -eq 0 && -z $FILE_NAME ]] && EXAMPLES=(password.txt)

step() { echo -e "\n==> $*"; }

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -n $TARGET_USER ]] || die "cannot detect user, pass -u <user>"
HOME_DIR=$(getent passwd "$TARGET_USER" | cut -d: -f6) || die "unknown user $TARGET_USER"
touch -d "$FAKE_DATE" /dev/null 2>/dev/null || die "invalid date for -d: $FAKE_DATE"

load_names
echo "Using settings from $SRC_CONF"
[[ $SRC_CONF == *.example ]] && echo "  (tip: cp honeypot.conf.example honeypot.conf and pick your own names)"

# --- work out the bait files ------------------------------------------------
# Baits from an earlier run may be re-used (their content is kept); any other
# existing file is someone's real data and is refused.
PREV_BAITS=" $(conf_get "$CONF_PATH" BAIT_FILE) $(conf_get "$LEGACY_CONF" BAIT_FILE) "
BAITS=()   # every file to watch
PAIRS=()   # template -> destination, for files that must be created
add_bait() { # dst [template]
  [[ $1 =~ [[:space:]] ]] && die "bait paths can't contain spaces: $1"
  [[ -d $1 ]] && die "$1 is a directory, not a file"
  BAITS+=("$1")
  if [[ ! -e $1 && -n ${2:-} ]]; then PAIRS+=("$2" "$1"); fi
}
for ex in "${EXAMPLES[@]}"; do
  [[ $ex != *..* && $ex != /* && -e $HERE/examples/$ex ]] || die "no such example: examples/$ex (see: ls -A $HERE/examples)"
  while IFS= read -r -d '' rel; do
    dst="$HOME_DIR/$rel"
    if [[ -e $dst && $PREV_BAITS != *" $dst "* ]]; then
      die "$dst already exists and looks real (not a bait from an earlier install). Not touching it: pick another example or remove that file from examples/$ex"
    fi
    add_bait "$dst" "$HERE/examples/$rel"
  done < <(cd "$HERE/examples" && find "$ex" -type f ! -name README.md -print0 | sort -z)
done
if [[ -n $FILE_NAME ]]; then
  case $FILE_NAME in
    /*) BAIT=$FILE_NAME ;;
    *)  BAIT="$HOME_DIR/$FILE_NAME" ;;
  esac
  BAIT=$(realpath -m "$BAIT")
  add_bait "$BAIT" "$HERE/examples/password.txt"
fi
[[ ${#BAITS[@]} -gt 0 ]] || die "no bait files"

# --- refuse names that would clobber something real -------------------------
for d in /usr/lib/systemd/system /lib/systemd/system /run/systemd/system; do
  [[ -e $d/$SERVICE_NAME.service ]] && die "SERVICE_NAME=$SERVICE_NAME is a real unit ($d), pick another"
done
if [[ -e $UNIT_FILE ]] && ! unit_is_ours "$UNIT_FILE" "$HANDLER_PATH" \
                       && ! unit_is_ours "$UNIT_FILE" "$LEGACY_HANDLER"; then
  die "$UNIT_FILE exists and isn't ours: change SERVICE_NAME"
fi
if [[ -e $HANDLER_PATH ]] && ! handler_is_ours "$HANDLER_PATH"; then
  die "$HANDLER_PATH exists and isn't ours: change HANDLER_PATH"
fi
if [[ -e $RULES_FILE ]] && ! rules_is_ours "$RULES_FILE" "$AUDIT_KEY"; then
  die "$RULES_FILE exists and isn't ours: change RULES_NAME"
fi
if [[ -e $CONF_PATH ]] && ! conf_is_ours "$CONF_PATH"; then
  die "$CONF_PATH exists and isn't ours: change CONF_PATH"
fi

step "Installing dependencies (auditd, nftables, python3)"
if command -v apt-get >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd nftables python3 iproute2 >/dev/null
elif command -v dnf >/dev/null; then
  dnf install -y -q audit nftables python3 iproute
elif command -v pacman >/dev/null; then
  pacman -S --needed --noconfirm audit nftables python iproute2
else
  die "unsupported package manager: install auditd, nftables, python3 manually"
fi
systemctl enable --now auditd >/dev/null 2>&1 || true

# Re-runs: unload the old rules first so preparing the bait doesn't trigger an alert
auditctl -D -k "$AUDIT_KEY" >/dev/null 2>&1 || true
auditctl -D -k "$LEGACY_KEY" >/dev/null 2>&1 || true

step "Creating bait files"
# Everything should look old and forgotten. Note: ctime/birth time (stat) can't
# be faked, only mtime/atime.
declare -A KEEP_MTIME=()   # existing folders we add files to: restore their mtime
NEW_DIRS=()                # folders we create: backdate them
for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
  d=$(dirname "${PAIRS[i]}"); chain=()
  while [[ ! -d $d ]]; do chain=("$d" "${chain[@]}"); d=$(dirname "$d"); done
  [[ -n ${KEEP_MTIME[$d]:-} ]] || KEEP_MTIME[$d]=$(stat -c %Y "$d")
  for c in "${chain[@]}"; do
    install -d -o "$TARGET_USER" -g "$TARGET_USER" -m 700 "$c"
    NEW_DIRS+=("$c")
  done
done
if [[ ${#PAIRS[@]} -gt 0 ]]; then
  python3 -I "$HERE/render-bait.py" "$TARGET_USER" "$(hostname -s)" "${PAIRS[@]}"
fi
for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
  chown "$TARGET_USER:$TARGET_USER" "${PAIRS[i]}"
  echo "created ${PAIRS[i]}"
done
for b in "${BAITS[@]}"; do
  [[ -e $b ]] || die "bait $b missing"
  touch -d "$FAKE_DATE" "$b"
done
for d in "${!KEEP_MTIME[@]}"; do touch -d "@${KEEP_MTIME[$d]}" "$d"; done
for d in "${NEW_DIRS[@]}"; do touch -d "$FAKE_DATE" "$d"; done
# -f in its own folder: make the neighbours look just as old (original behaviour)
if [[ -n $FILE_NAME && $(dirname "$BAIT") != "$HOME_DIR" ]]; then
  find "$(dirname "$BAIT")" -maxdepth 1 -type f -exec touch -d "$FAKE_DATE" {} +
  touch -d "$FAKE_DATE" "$(dirname "$BAIT")"
fi
ls -la "${BAITS[@]}"
for b in $PREV_BAITS; do
  [[ " ${BAITS[*]} " == *" $b "* || ! -e $b ]] || echo "note: $b is no longer watched (delete it if unneeded)"
done

step "Removing old installs that used the obvious original names"
# Keep the user's old config and reports, just move them to the new names.
if [[ $CONF_PATH != "$LEGACY_CONF" && -f $LEGACY_CONF && ! -e $CONF_PATH ]]; then
  mkdir -p "$(dirname "$CONF_PATH")"
  mv "$LEGACY_CONF" "$CONF_PATH" && echo "moved $LEGACY_CONF -> $CONF_PATH"
fi
if [[ $REPORT_DIR != "$LEGACY_REPORTS" && -d $LEGACY_REPORTS ]]; then
  mkdir -p -m 700 "$REPORT_DIR"
  find "$LEGACY_REPORTS" -maxdepth 1 -type f -exec mv -t "$REPORT_DIR" {} +
  rmdir "$LEGACY_REPORTS" 2>/dev/null && echo "moved reports $LEGACY_REPORTS -> $REPORT_DIR"
fi
[[ $SERVICE_NAME != "$LEGACY_SERVICE" ]] && \
  remove_install "/etc/systemd/system/$LEGACY_SERVICE.service" "$LEGACY_HANDLER" "$LEGACY_RULES" "$LEGACY_KEY" "$LEGACY_TABLE"
[[ $HANDLER_PATH != "$LEGACY_HANDLER" && -f $LEGACY_HANDLER ]] && handler_is_ours "$LEGACY_HANDLER" && rm -f "$LEGACY_HANDLER"
echo "ok"

step "Installing handler -> $HANDLER_PATH"
mkdir -p "$(dirname "$HANDLER_PATH")"
# root-only: others can't read the source and learn what it is
install -m 700 -o root -g root "$HERE/honeypot-handler.py" "$HANDLER_PATH"
sed -i "s|^CONF_PATH = .*|CONF_PATH = os.environ.get(\"HONEYPOT_CONF\", \"$CONF_PATH\")|" "$HANDLER_PATH"

step "Installing config -> $CONF_PATH"
mkdir -p "$(dirname "$CONF_PATH")"
if [[ -f $CONF_PATH ]]; then
  echo "exists, keeping your settings (only names and BAIT_FILE are updated)"
else
  install -m 600 -o root -g root "$SRC_CONF" "$CONF_PATH"
fi
for k in "${NAME_KEYS[@]}"; do conf_set "$CONF_PATH" "$k" "${!k}"; done
conf_set "$CONF_PATH" BAIT_FILE "${BAITS[*]}"
chmod 600 "$CONF_PATH"

step "Installing service -> $UNIT_FILE"
cat >"$UNIT_FILE" <<EOF
[Unit]
Description=$SERVICE_DESCRIPTION
After=auditd.service network-online.target
Wants=auditd.service network-online.target

[Service]
ExecStart=$HANDLER_PATH
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

step "Loading audit rules -> $RULES_FILE"
# Not `-p r`: its read class includes getxattr/listxattr, which `ls -l` calls on
# every file. Instead watch the open syscalls themselves (names vary per arch).
declare -A SC=()
for arch in b64 b32; do
  SC[$arch]=""
  for s in open openat openat2 open_by_handle_at; do
    ausyscall "$arch" "$s" --exact >/dev/null 2>&1 && SC[$arch]+=" -S $s"
  done
done
{
  for b in "${BAITS[@]}"; do
    echo "-w $b -p wa -k $AUDIT_KEY"
    for arch in b64 b32; do
      [[ -n ${SC[$arch]} ]] && echo "-a always,exit -F arch=$arch${SC[$arch]} -F path=$b -k $AUDIT_KEY"
    done
  done
  true
} >"$RULES_FILE"
chmod 640 "$RULES_FILE"
cat "$RULES_FILE"
augenrules --load >/dev/null 2>&1 || auditctl -c -R "$RULES_FILE" >/dev/null || true
auditctl -l | grep -- "-k $AUDIT_KEY" || die "audit rule not loaded"

step "Starting service $SERVICE_NAME"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
systemctl restart "$SERVICE_NAME"
sleep 1
systemctl is-active "$SERVICE_NAME"

step "Test notification"
"$HANDLER_PATH" --test || echo "(configure a channel in $CONF_PATH, then: sudo $HANDLER_PATH --test)"

cat <<EOF

Done. Watching ${#BAITS[@]} bait file(s):
$(printf '  %s\n' "${BAITS[@]}")

Now delete this repository copy from the machine: it gives the trap away.
  service: $SERVICE_NAME            logs: journalctl -u $SERVICE_NAME -f
  config:  $CONF_PATH (no restart needed)
  reports: $REPORT_DIR/
  bans:    sudo $HANDLER_PATH --bans     unban: sudo $HANDLER_PATH --unban <ip>
EOF
