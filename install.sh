#!/usr/bin/env bash
# Bait-file tripwire installer (idempotent: safe to re-run).
#   sudo ./install.sh [-u user] [-e example]... [-f file]... [-d date]
# -u  user owning the bait            (default: the one running sudo)
# -e  decoy from examples/ (repeatable), copied into that user's home with fresh
#     random secrets; EVERY file of it is watched.  e.g. -e .aws -e .git-credentials
#     Files that already exist (real ones) are never overwritten: install aborts.
# -f  watch this file (repeatable), absolute or relative to that user's home.
#     Created from examples/password.txt if missing; an existing file is watched
#     as is (content and dates untouched). Paths through a symlink are refused.
# -d  fake modification date for the files and folders this run creates,
#     anything `date -d` accepts (default: "97 days ago")
# No -e/-f: same as -e password.txt.   List decoys: ls -A examples/
# Settings and on-disk names come from ./honeypot.conf next to this script
# (falls back to honeypot.conf.example). See the STEALTH section in that file.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$HERE/common.sh"

TARGET_USER=${SUDO_USER:-}
EXAMPLES=()
FILES=()
FAKE_DATE="97 days ago"

while getopts "u:e:f:d:h" o; do
  case $o in
    u) TARGET_USER=$OPTARG ;;
    e) ex=${OPTARG%/}; EXAMPLES+=("${ex#./}") ;;
    f) FILES+=("$OPTARG") ;;
    d) FAKE_DATE=$OPTARG ;;
    *) sed -n '2,15p' "$0"; exit 1 ;;
  esac
done
[[ ${#EXAMPLES[@]} -eq 0 && ${#FILES[@]} -eq 0 ]] && EXAMPLES=(password.txt)

step() { echo -e "\n==> $*"; }

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -n $TARGET_USER ]] || die "cannot detect user, pass -u <user>"
HOME_DIR=$(getent passwd "$TARGET_USER" | cut -d: -f6) || die "unknown user $TARGET_USER"
# Canonical form (e.g. /home -> /var/home), so the symlink check below is exact
HOME_DIR=$(realpath -e "$HOME_DIR" 2>/dev/null) || die "home folder of $TARGET_USER doesn't exist"
TARGET_GROUP=$(id -gn "$TARGET_USER") || die "no primary group for $TARGET_USER"
date -d "$FAKE_DATE" >/dev/null 2>&1 || die "invalid date for -d: $FAKE_DATE"
# Short hostname for the templates. Not `hostname -s`: that command is missing
# on minimal installs (e.g. Arch) and an empty value renders obviously fake baits.
HOST_SHORT=$(uname -n); HOST_SHORT=${HOST_SHORT%%.*}
[[ -n $HOST_SHORT ]] || die "cannot determine the hostname"

load_names
echo "Using settings from $SRC_CONF"
[[ $SRC_CONF == *.example ]] && echo "  (tip: cp honeypot.conf.example honeypot.conf and pick your own names)"

# --- work out the bait files ------------------------------------------------
# Baits from an earlier run may be re-used (their content is kept); any other
# existing file is someone's real data and is refused.
# Paths are compared in canonical form (an older install may have recorded them
# through a symlinked /home).
canon_list() { local p a; read -ra a <<<"$1"; for p in "${a[@]}"; do realpath -m -- "$p"; done | tr '\n' ' '; }
PREV_BAITS=" $(canon_list "$(conf_get "$CONF_PATH" BAIT_FILE) $(conf_get "$LEGACY_CONF" BAIT_FILE)") "
# Baits an earlier run created (vs. existing files watched with -f): only those
# are deleted by `uninstall.sh --purge`.
PREV_CREATED=" $(canon_list "$(conf_get "$CONF_PATH" BAIT_CREATED)") "
BAITS=()   # every file to watch
PAIRS=()   # template -> destination, for files that must be created
CREATED=() # baits created by an install (this one or an earlier one)
add_bait() { # dst(absolute, normalised) template
  # Lists are space separated and expanded unquoted by older tools: no blanks or globs
  [[ $1 =~ [[:space:]*?[] ]] && die "bait paths can't contain spaces or * ? [ : $1"
  [[ -d $1 ]] && die "$1 is a directory, not a file"
  # We run as root inside a user's home: never follow a symlink planted there
  # (e.g. ~/.aws -> /etc/profile.d would make root create a file there and
  # hand it to the user).
  no_symlink "$1" || die "$1 goes through a symlink (it leads to $(realpath -m -- "$1")), refusing. If that's really the file you mean, pass its real path with -f"
  [[ " ${BAITS[*]} " == *" $1 "* ]] && return 0   # same path given twice
  BAITS+=("$1")
  if [[ ! -e $1 ]]; then
    PAIRS+=("$2" "$1"); CREATED+=("$1")
  elif [[ $PREV_CREATED == *" $1 "* ]]; then
    # Only a file an install provably created may ever be purged. An existing
    # file (e.g. a real one watched with -f earlier, even if a decoy now has
    # the same path) is never marked as created.
    CREATED+=("$1")
  fi
}
for ex in "${EXAMPLES[@]}"; do
  [[ -n $ex && $ex != . && $ex != *..* && $ex != /* && -e $HERE/examples/$ex ]] || die "no such example: examples/$ex (see: ls -A $HERE/examples)"
  while IFS= read -r -d '' rel; do
    dst="$HOME_DIR/$rel"
    if [[ -e $dst && $PREV_BAITS != *" $dst "* ]]; then
      die "$dst already exists and looks real (not a bait from an earlier install). Not touching it: pick another example or remove that file from examples/$ex"
    fi
    add_bait "$dst" "$HERE/examples/$rel"
  done < <(cd "$HERE/examples" && find "$ex" -type f ! -name README.md -print0 | sort -z)
done
for f in "${FILES[@]}"; do
  case $f in
    /*) b=$f ;;
    *)  b="$HOME_DIR/$f" ;;
  esac
  # -s: tidy up . and .. but DON'T resolve symlinks, so add_bait can refuse them
  add_bait "$(realpath -m -s -- "$b")" "$HERE/examples/password.txt"
done
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

# Not `-p r`: its read class includes getxattr/listxattr, which `ls -l` calls on
# every file. Instead watch the open syscalls themselves (names vary per arch).
# Probed now so a box where this can't work fails before anything is created.
declare -A SC=()
for arch in b64 b32; do
  SC[$arch]=""
  for s in open openat openat2 open_by_handle_at; do
    ausyscall "$arch" "$s" --exact >/dev/null 2>&1 && SC[$arch]+=" -S $s"
  done
done
[[ -n ${SC[b64]}${SC[b32]} ]] || die "ausyscall can't resolve the open syscalls: reads of the bait would go unnoticed"

# Re-runs: unload the old rules first so preparing the bait doesn't trigger an alert
auditctl -D -k "$AUDIT_KEY" >/dev/null 2>&1 || true
auditctl -D -k "$LEGACY_KEY" >/dev/null 2>&1 || true
# From here on the trap is disarmed. If anything below fails:
#  - before the config records the new baits: delete the files and folders
#    this run created (else a re-run refuses them as "real" files, and a
#    leftover folder would keep today's date and look freshly made);
#  - always: reload whatever rules file is on disk so the previous install
#    keeps watching.
declare -A KEEP_MTIME=()   # existing folders we add files to: restore their mtime
NEW_DIRS=()                # folders we create: backdate them
RENDERED=no                # render-bait.py wrote every file in PAIRS
COMMITTED=no               # the installed config lists the new baits
on_failure() {
  local rc=$? f k i
  [[ $rc -ne 0 ]] || return 0
  set +e   # best effort: one failing step must not skip the rest (rule reload!)
  if [[ $COMMITTED == no ]]; then
    if [[ $RENDERED == yes ]]; then
      for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
        no_symlink "${PAIRS[i]}" && rm -f -- "${PAIRS[i]}"
      done
    fi
    for ((i = ${#NEW_DIRS[@]} - 1; i >= 0; i--)); do rmdir -- "${NEW_DIRS[i]}" 2>/dev/null; done
    for d in "${!KEEP_MTIME[@]}"; do touch -h -d "@${KEEP_MTIME[$d]}" "$d" 2>/dev/null; done
    [[ ${#PAIRS[@]} -eq 0 ]] || echo "install failed: removed the bait files and folders this run created" >&2
  fi
  for f in "$RULES_FILE:$AUDIT_KEY" "$LEGACY_RULES:$LEGACY_KEY"; do
    k=${f##*:}; f=${f%:*}
    [[ -f $f ]] && rules_is_ours "$f" "$k" || continue
    auditctl -l 2>/dev/null | grep -q -- "-k $k\$" && continue
    auditctl -c -R "$f" >/dev/null 2>&1 && echo "install failed: reloaded the previous audit rules from $f" >&2
  done
}
trap on_failure EXIT

step "Creating bait files"
# Everything new should look old and forgotten: files and folders this run
# creates get FAKE_DATE, folders that already existed keep their own date, and
# existing baits (earlier runs, -f files) are left alone. Note: ctime/birth time
# (stat) can't be faked, only mtime/atime.
for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
  d=$(dirname "${PAIRS[i]}"); chain=()
  while [[ ! -d $d ]]; do chain=("$d" "${chain[@]}"); d=$(dirname "$d"); done
  [[ -n ${KEEP_MTIME[$d]:-} ]] || KEEP_MTIME[$d]=$(stat -c %Y "$d")
  for c in "${chain[@]}"; do
    install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 700 "$c"
    NEW_DIRS+=("$c")
  done
done
if [[ ${#PAIRS[@]} -gt 0 ]]; then
  python3 -I "$HERE/render-bait.py" "$TARGET_USER" "$HOST_SHORT" "${PAIRS[@]}"
  RENDERED=yes
fi
for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
  chown -h "$TARGET_USER:$TARGET_GROUP" "${PAIRS[i]}"
  touch -h -d "$FAKE_DATE" "${PAIRS[i]}"
  echo "created ${PAIRS[i]}"
done
for b in "${BAITS[@]}"; do [[ -e $b ]] || die "bait $b missing"; done
for d in "${!KEEP_MTIME[@]}"; do touch -h -d "@${KEEP_MTIME[$d]}" "$d"; done
for d in "${NEW_DIRS[@]}"; do touch -h -d "$FAKE_DATE" "$d"; done
ls -la "${BAITS[@]}"
read -ra prev <<<"$PREV_BAITS"
for b in "${prev[@]}"; do
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
  echo "exists, keeping your settings (only the names and the bait lists are updated)"
else
  install -m 600 -o root -g root "$SRC_CONF" "$CONF_PATH"
fi
for k in "${NAME_KEYS[@]}"; do conf_set "$CONF_PATH" "$k" "${!k}"; done
conf_set "$CONF_PATH" BAIT_FILE "${BAITS[*]}"
conf_set "$CONF_PATH" BAIT_CREATED "${CREATED[*]}"
chmod 600 "$CONF_PATH"
COMMITTED=yes   # the new baits are on record: a later failure keeps them

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
# Per bait: a write/attribute watch, plus the open syscalls probed above (SC)
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

# This is the only moment someone is watching: once the repo is deleted, a
# trap that never fires goes unnoticed for good. So verify it can fire.
LOADED=$(auditctl -l 2>/dev/null)
rules_for() { # loaded rules with our key on exactly this path
  { grep -F -e "-w $1 " -e "path=$1 " <<<"$LOADED" | grep -E -- "(-k |key=)$AUDIT_KEY\$"; } || true
}
for b in "${BAITS[@]}"; do
  r=$(rules_for "$b")
  # a watch prints as "-w PATH -p wa -k KEY" (or with path=/perm= fields)
  grep -qE -- '(-p |perm=)[a-z]*w' <<<"$r" \
    || die "the write watch for $b didn't load (see: auditctl -l)"
  grep -qE -- '-S [^ ]*open' <<<"$r" \
    || die "the open rule for $b didn't load (see: auditctl -l): reading it would go unnoticed"
done
[[ $(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2}') != 0 ]] \
  || die "kernel auditing is disabled (auditctl -s: enabled 0, or audit=0 on the kernel command line): no event would ever fire"
if grep -qxE -- '-a (never,task|task,never)' <<<"$LOADED"; then   # unfiltered = every task
  die "a 'never,task' audit rule is loaded (often /etc/audit/rules.d/audit.rules): it silences all syscall auditing, so the bait could never fire. Remove it, then re-run"
fi
echo "verified: every bait has its open and write rules loaded"

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
