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
#
# Structure: one function per step, run in order by main() at the bottom. The
# file can be sourced without running anything (tests/shell/install.bats).

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
. "$HERE/common.sh"

# Where distributions ship their own units: a SERVICE_NAME found there is real.
SYSTEM_UNIT_DIRS=(/usr/lib/systemd/system /lib/systemd/system /run/systemd/system)
AUDIT_RULES_DIR=/etc/audit/rules.d
NIXOS_MARK=/etc/NIXOS
# An unfiltered "never,task" rule turns off syscall auditing for every process
NEVER_TASK_RE='^[[:space:]]*-a[[:space:]]+(never,task|task,never)[[:space:]]*$'

TARGET_USER=${SUDO_USER:-}
EXAMPLES=()
FILES=()
FAKE_DATE="97 days ago"

BAITS=()   # every file to watch
PAIRS=()   # template -> destination, for files that must be created
CREATED=() # baits created by an install (this one or an earlier one)
PREV_BAITS=" "
PREV_CREATED=" "
declare -gA SC=()          # arch -> " -S open -S openat ..." (what ausyscall knows)

# Failure-cleanup state (see on_failure)
declare -gA KEEP_MTIME=()   # existing folders we add files to: restore their mtime
NEW_DIRS=()                # folders we create: backdate them
RENDERED=no                # render-bait.py wrote every file in PAIRS
COMMITTED=no               # the installed config lists the new baits
WAS_ACTIVE=no              # we stopped a running service

step() { echo -e "\n==> $*"; }
usage() { sed -n '2,15p' "$HERE/install.sh"; exit 1; }

# ------------------------------------------------------------- options, user
parse_args() {
  local o ex OPTIND=1
  while getopts "u:e:f:d:h" o; do
    case $o in
      u) TARGET_USER=$OPTARG ;;
      e) ex=${OPTARG%/}; EXAMPLES+=("${ex#./}") ;;
      f) FILES+=("$OPTARG") ;;
      d) FAKE_DATE=$OPTARG ;;
      *) usage ;;
    esac
  done
  [[ $OPTIND -gt $# ]] || { echo "unexpected argument: ${!OPTIND}" >&2; usage; }
  if [[ ${#EXAMPLES[@]} -eq 0 && ${#FILES[@]} -eq 0 ]]; then EXAMPLES=(password.txt); fi
}

resolve_user() {
  [[ -n $TARGET_USER ]] || die "cannot detect user, pass -u <user>"
  HOME_DIR=$(getent passwd "$TARGET_USER" | cut -d: -f6) || die "unknown user $TARGET_USER"
  [[ -n $HOME_DIR ]] || die "unknown user $TARGET_USER"
  # Canonical form (e.g. /home -> /var/home), so the symlink check is exact
  HOME_DIR=$(realpath -e "$HOME_DIR" 2>/dev/null) || die "home folder of $TARGET_USER doesn't exist"
  TARGET_GROUP=$(id -gn "$TARGET_USER") || die "no primary group for $TARGET_USER"
  date -d "$FAKE_DATE" >/dev/null 2>&1 || die "invalid date for -d: $FAKE_DATE"
  # Short hostname for the templates. Not `hostname -s`: that command is missing
  # on minimal installs (e.g. Arch) and an empty value renders obviously fake baits.
  HOST_SHORT=$(uname -n); HOST_SHORT=${HOST_SHORT%%.*}
  [[ -n $HOST_SHORT ]] || die "cannot determine the hostname"
}

# ------------------------------------------------------------- bait list
# Baits from an earlier run may be re-used (their content is kept); any other
# existing file is someone's real data and is refused.
# Paths are compared in canonical form (an older install may have recorded them
# through a symlinked /home).
canon_list() { local p a; read -ra a <<<"$1"; for p in "${a[@]}"; do realpath -m -- "$p"; done | tr '\n' ' '; }

load_previous() {
  PREV_BAITS=" $(canon_list "$(conf_get "$CONF_PATH" BAIT_FILE) $(conf_get "$LEGACY_CONF" BAIT_FILE)") "
  # Baits an earlier run created (vs. existing files watched with -f): only
  # those are deleted by `uninstall.sh --purge`.
  PREV_CREATED=" $(canon_list "$(conf_get "$CONF_PATH" BAIT_CREATED)") "
}

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

add_example() { # name under examples/
  local ex=$1 rel dst
  [[ -n $ex && $ex != . && $ex != *..* && $ex != /* && -e $HERE/examples/$ex ]] || die "no such example: examples/$ex (see: ls -A $HERE/examples)"
  while IFS= read -r -d '' rel; do
    dst="$HOME_DIR/$rel"
    if [[ -e $dst && $PREV_BAITS != *" $dst "* ]]; then
      die "$dst already exists and looks real (not a bait from an earlier install). Not touching it: pick another example or remove that file from examples/$ex"
    fi
    add_bait "$dst" "$HERE/examples/$rel"
  done < <(cd "$HERE/examples" && find "$ex" -type f ! -name README.md -print0 | sort -z)
}

add_file() { # -f argument
  local b
  case $1 in
    /*) b=$1 ;;
    *)  b="$HOME_DIR/$1" ;;
  esac
  # -s: tidy up . and .. but DON'T resolve symlinks, so add_bait can refuse them
  add_bait "$(realpath -m -s -- "$b")" "$HERE/examples/password.txt"
}

collect_baits() {
  local x
  for x in "${EXAMPLES[@]}"; do add_example "$x"; done
  for x in "${FILES[@]}"; do add_file "$x"; done
  [[ ${#BAITS[@]} -gt 0 ]] || die "no bait files"
}

# ------------------------------------------------------------- name collisions
refuse_collisions() {
  local d
  for d in "${SYSTEM_UNIT_DIRS[@]}"; do
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
}

# ------------------------------------------------------------- dependencies
install_deps() {
  step "Installing dependencies (auditd, nftables, python3)"
  # NixOS builds /etc/systemd/system and the audit rules from configuration.nix
  # (read-only): a unit or rules file written here would be gone or refused.
  [[ ! -e $NIXOS_MARK ]] || die "NixOS isn't supported: its systemd units and audit rules come from configuration.nix, so this installer can't set them"
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
}

# The handler and render-bait.py use subprocess.run(capture_output=, text=):
# 3.7+. Checked before anything is created (RHEL 8's python3 is 3.6).
check_python() {
  local v
  v=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null) \
    || die "python3 doesn't run: install Python 3.7 or newer"
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 7))' \
    || die "python3 is $v: the handler needs Python 3.7 or newer"
}

# Not `-p r`: its read class includes getxattr/listxattr, which `ls -l` calls on
# every file. Instead watch the open syscalls themselves (names vary per arch).
# Probed before anything is created, so a box where this can't work fails early.
probe_syscalls() {
  local arch s
  for arch in b64 b32; do
    SC[$arch]=""
    for s in open openat openat2 open_by_handle_at; do
      if ausyscall "$arch" "$s" --exact >/dev/null 2>&1; then SC[$arch]+=" -S $s"; fi
    done
  done
  [[ -n ${SC[b64]}${SC[b32]} ]] || die "ausyscall can't resolve the open syscalls: reads of the bait would go unnoticed"
}

# Some distributions ship a rule that turns off syscall auditing for every
# process (Fedora: "-a task,never" in /etc/audit/rules.d/audit.rules), so the
# bait could never fire. Checked before anything is created; verify_rules
# checks again once our rules are loaded.
preflight_audit() { # auditctl -l output
  local f
  f=$(grep -lxE -- "$NEVER_TASK_RE" "$AUDIT_RULES_DIR"/*.rules 2>/dev/null | head -n1 || true)
  [[ -z $f ]] || die "$f has a '-a task,never' rule: it turns off syscall auditing for every process, so the bait could never fire. Comment that line out, unload it (auditctl -d task,never), then re-run"
  if grep -qxE -- "$NEVER_TASK_RE" <<<"$1"; then
    die "a '-a never,task' audit rule is loaded (auditctl -l): it turns off syscall auditing for every process, so the bait could never fire. Unload it (auditctl -d task,never or -d never,task), remove it where it comes from (grep -r never /etc/audit), then re-run"
  fi
}

# ------------------------------------------------------------- failure cleanup
# From disarm() on, the trap is unarmed. If anything after that fails:
#  - before the config records the new baits: delete the files and folders
#    this run created (else a re-run refuses them as "real" files, and a
#    leftover folder would keep today's date and look freshly made);
#  - always: reload whatever rules file is on disk so the previous install
#    keeps watching, and restart the service if we stopped it.
on_failure() {
  local rc=$? f k i d
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
    # always reload, even if some rules are loaded: a partial load (one rule
    # refused) would leave the trap half-armed
    reload_rules "$f" "$k" && echo "install failed: reloaded the audit rules from $f" >&2
  done
  if [[ $WAS_ACTIVE == yes ]]; then
    systemctl daemon-reload; systemctl start "$SERVICE_NAME" && echo "install failed: restarted $SERVICE_NAME" >&2
  fi
  return 0
}

# Re-runs: stop the running service first (its health checks would report the
# brief disarm, and the end-to-end test opens every bait), then unload the old
# rules so preparing the baits doesn't trigger an alert.
disarm() {
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"; WAS_ACTIVE=yes
  fi
  auditctl -D -k "$AUDIT_KEY" >/dev/null 2>&1 || true
  auditctl -D -k "$LEGACY_KEY" >/dev/null 2>&1 || true
}

# ------------------------------------------------------------- baits on disk
# Everything new should look old and forgotten: files and folders this run
# creates get FAKE_DATE, folders that already existed keep their own date, and
# existing baits (earlier runs, -f files) are left alone. Note: ctime/birth time
# (stat) can't be faked, only mtime/atime.
make_dirs() {
  local i d c chain
  for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
    d=$(dirname "${PAIRS[i]}"); chain=()
    while [[ ! -d $d ]]; do chain=("$d" "${chain[@]}"); d=$(dirname "$d"); done
    [[ -n ${KEEP_MTIME[$d]:-} ]] || KEEP_MTIME[$d]=$(stat -c %Y "$d")
    for c in "${chain[@]}"; do
      install -d -o "$TARGET_USER" -g "$TARGET_GROUP" -m 700 "$c"
      NEW_DIRS+=("$c")
    done
  done
}

render_baits() {
  local i
  [[ ${#PAIRS[@]} -gt 0 ]] || return 0
  python3 -I "$HERE/render-bait.py" "$TARGET_USER" "$HOST_SHORT" "${PAIRS[@]}"
  RENDERED=yes
  for ((i = 1; i < ${#PAIRS[@]}; i += 2)); do
    chown -h "$TARGET_USER:$TARGET_GROUP" "${PAIRS[i]}"
    touch -h -d "$FAKE_DATE" "${PAIRS[i]}"
    echo "created ${PAIRS[i]}"
  done
}

date_dirs() {
  local d
  for d in "${!KEEP_MTIME[@]}"; do touch -h -d "@${KEEP_MTIME[$d]}" "$d"; done
  for d in "${NEW_DIRS[@]}"; do touch -h -d "$FAKE_DATE" "$d"; done
}

note_dropped() { # earlier baits this run no longer watches
  local b prev
  read -ra prev <<<"$PREV_BAITS"
  for b in "${prev[@]}"; do
    [[ " ${BAITS[*]} " == *" $b "* || ! -e $b ]] || echo "note: $b is no longer watched (delete it if unneeded)"
  done
}

create_baits() {
  local b
  step "Creating bait files"
  make_dirs
  render_baits
  for b in "${BAITS[@]}"; do [[ -e $b ]] || die "bait $b missing"; done
  date_dirs
  ls -la "${BAITS[@]}"
  note_dropped
}

# ------------------------------------------------------------- legacy names
# Keep the user's old config and reports, just move them to the new names.
migrate_legacy() {
  step "Removing old installs that used the obvious original names"
  if [[ $CONF_PATH != "$LEGACY_CONF" && -f $LEGACY_CONF && ! -e $CONF_PATH ]]; then
    mkdir -p "$(dirname "$CONF_PATH")"
    mv "$LEGACY_CONF" "$CONF_PATH" && echo "moved $LEGACY_CONF -> $CONF_PATH"
  fi
  if [[ $REPORT_DIR != "$LEGACY_REPORTS" && -d $LEGACY_REPORTS ]]; then
    install -d -m 700 "$REPORT_DIR"   # parents keep default perms
    find "$LEGACY_REPORTS" -maxdepth 1 -type f -exec mv -t "$REPORT_DIR" {} +
    rmdir "$LEGACY_REPORTS" 2>/dev/null && echo "moved reports $LEGACY_REPORTS -> $REPORT_DIR"
  fi
  if [[ $SERVICE_NAME != "$LEGACY_SERVICE" ]]; then
    remove_install "/etc/systemd/system/$LEGACY_SERVICE.service" "$LEGACY_HANDLER" "$LEGACY_RULES" "$LEGACY_KEY" "$LEGACY_TABLE"
  fi
  if [[ $HANDLER_PATH != "$LEGACY_HANDLER" && -f $LEGACY_HANDLER ]] && handler_is_ours "$LEGACY_HANDLER"; then
    rm -f "$LEGACY_HANDLER"
  fi
  echo "ok"
}

# ------------------------------------------------------------- handler, config, unit
install_handler() {
  step "Installing handler -> $HANDLER_PATH"
  mkdir -p "$(dirname "$HANDLER_PATH")"
  # root-only: others can't read the source and learn what it is
  install -m 700 -o root -g root "$HERE/honeypot-handler.py" "$HANDLER_PATH"
  sed -i "s|^CONF_PATH = .*|CONF_PATH = os.environ.get(\"HONEYPOT_CONF\", \"$CONF_PATH\")|" "$HANDLER_PATH"
}

install_config() {
  local k
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
}

unit_text() {
  cat <<EOF
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
}

install_unit() {
  step "Installing service -> $UNIT_FILE"
  unit_text >"$UNIT_FILE"
}

# ------------------------------------------------------------- audit rules
rules_text() { # per bait: a write/attribute watch, plus the open syscalls probed (SC)
  local b arch
  for b in "${BAITS[@]}"; do
    echo "-w $b -p wa -k $AUDIT_KEY"
    for arch in b64 b32; do
      if [[ -n ${SC[$arch]} ]]; then
        echo "-a always,exit -F arch=$arch${SC[$arch]} -F path=$b -k $AUDIT_KEY"
      fi
    done
  done
}

load_rules() {
  step "Loading audit rules -> $RULES_FILE"
  rules_text >"$RULES_FILE"
  chmod 640 "$RULES_FILE"
  cat "$RULES_FILE"
  augenrules --load >/dev/null 2>&1 || true
  # augenrules stops at the first rule the kernel refuses (seen on Arch): reload ours alone
  rules_complete "$(auditctl -l 2>/dev/null)" || reload_rules "$RULES_FILE" "$AUDIT_KEY" || true
  auditctl -l | grep -- "-k $AUDIT_KEY" || die "audit rule not loaded"
}

# The kernel can refuse a watch re-added right after it was deleted (its old
# inotify mark is freed asynchronously): pause after deleting, check, retry.
reload_rules() { # rules-file key: 0 once every rule of the file with that key is loaded
  local try want
  want=$(grep -cE -- "(-k |key=)$2\$" "$1" || true)
  for try in 1 2 3; do
    auditctl -D -k "$2" >/dev/null 2>&1
    sleep "$try"
    auditctl -R "$1" >/dev/null 2>&1   # exactly "-R file": auditctl ignores -R with any other option (-c)
    (( $(auditctl -l 2>/dev/null | grep -cE -- "(-k |key=)$2\$") >= want )) && return 0
  done
  return 1
}

rules_complete() { # auditctl -l output: does every bait have its write watch and open rule?
  local b r
  for b in "${BAITS[@]}"; do
    r=$(rules_for "$1" "$b")
    grep -qE -- '(-p |perm=)[a-z]*w' <<<"$r" || return 1
    grep -qE -- '-S [^ ]*open' <<<"$r" || return 1
  done
}

rules_for() { # loaded-rules path: loaded rules with our key on exactly this path
  { grep -F -e "-w $2 " -e "path=$2 " <<<"$1" | grep -E -- "(-k |key=)$AUDIT_KEY\$"; } || true
}

# This is the only moment someone is watching: once the repo is deleted, a
# trap that never fires goes unnoticed for good. So verify it can fire.
verify_rules() { # auditctl -l output, auditctl -s output
  local b r
  for b in "${BAITS[@]}"; do
    r=$(rules_for "$1" "$b")
    # a watch prints as "-w PATH -p wa -k KEY" (or with path=/perm= fields)
    grep -qE -- '(-p |perm=)[a-z]*w' <<<"$r" \
      || die "the write watch for $b didn't load (see: auditctl -l)"
    grep -qE -- '-S [^ ]*open' <<<"$r" \
      || die "the open rule for $b didn't load (see: auditctl -l): reading it would go unnoticed"
  done
  [[ $(awk '$1 == "enabled" {print $2}' <<<"$2") != 0 ]] \
    || die "kernel auditing is disabled (auditctl -s: enabled 0, or audit=0 on the kernel command line): no event would ever fire"
  if grep -qxE -- "$NEVER_TASK_RE" <<<"$1"; then
    die "a 'never,task' audit rule is loaded (often /etc/audit/rules.d/audit.rules): it silences all syscall auditing, so the bait could never fire. Remove it, then re-run"
  fi
  echo "verified: every bait has its open and write rules loaded"
}

# ------------------------------------------------------------- end-to-end test
# Proves the whole chain the handler relies on: the kernel logs an open of each
# bait, auditd writes it, and AUDIT_LOG (what the handler follows) holds the
# exact line it filters for (type=SYSCALL + key="<AUDIT_KEY>"). The service is
# started only afterwards and reads from the log's end, so these test events
# never raise an alert.
open_baits() { # prints the pid that opened them
  python3 -I - "${BAITS[@]}" <<'PY'
import os, sys
for b in sys.argv[1:]:
    try:  # O_NOATIME (allowed for root): the bait's access time stays as it was
        fd = os.open(b, os.O_RDONLY | os.O_NOATIME)
    except PermissionError:  # some filesystems (NFS) refuse the flag
        fd = os.open(b, os.O_RDONLY)
    os.close(fd)
print(os.getpid())
PY
}

unseen_baits() { # ausearch PATH records -> baits missing from them
  local b
  for b in "${BAITS[@]}"; do
    grep -qF -e "name=$b " -e "name=\"$b\" " <<<"$1" || echo "$b"
  done
}

e2e_test() {
  local log pid seen missing n
  step "End-to-end test: opening each bait once (service stopped: nothing is contained)"
  log=$(conf_get "$CONF_PATH" AUDIT_LOG /var/log/audit/audit.log)
  [[ -f $log ]] || die "AUDIT_LOG=$log doesn't exist: set it in $CONF_PATH to auditd.conf's log_file"
  pid=$(open_baits) || die "end-to-end test: could not open the bait files"
  # --input-logs: else ausearch reads stdin when it isn't a terminal (CI, ssh, cron)
  for _ in $(seq 20); do   # auditd writes asynchronously: give it up to ~10s
    seen=$(ausearch --input-logs -k "$AUDIT_KEY" -p "$pid" -ts recent -i 2>/dev/null | grep '^type=PATH' || true)
    missing=$(unseen_baits "$seen")
    [[ -z $missing ]] && break
    sleep 0.5
  done
  [[ -z $missing ]] || die "end-to-end test: opening these baits was NOT logged by auditd: ${missing//$'\n'/ } (the rules look loaded; check auditd: systemctl status auditd, auditctl -s)"
  n=$(tail -n 100000 "$log" | grep -F 'type=SYSCALL' | grep -F " pid=$pid " | grep -cF "key=\"$AUDIT_KEY\"" || true)
  [[ $n -ge ${#BAITS[@]} ]] || die "end-to-end test: auditd logged the opens, but not into AUDIT_LOG=$log, which the handler follows. Set AUDIT_LOG in $CONF_PATH to auditd.conf's log_file"
  echo "ok: all ${#BAITS[@]} bait open(s) reached $log as the handler expects"
}

# ------------------------------------------------------------- start, report
start_service() {
  step "Starting service $SERVICE_NAME"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  systemctl restart "$SERVICE_NAME"
  sleep 1
  systemctl is-active "$SERVICE_NAME"
  "$HANDLER_PATH" --health || die "the handler's own health check fails (see above)"
  step "Test notification"
  "$HANDLER_PATH" --test || echo "(configure a channel in $CONF_PATH, then: sudo $HANDLER_PATH --test)"
}

summary() {
  cat <<EOF

Done. Watching ${#BAITS[@]} bait file(s):
$(printf '  %s\n' "${BAITS[@]}")

Now delete this repository copy from the machine: it gives the trap away.
  service: $SERVICE_NAME            logs: journalctl -u $SERVICE_NAME -f
  config:  $CONF_PATH (no restart needed)
  reports: $REPORT_DIR/
  bans:    sudo $HANDLER_PATH --bans     unban: sudo $HANDLER_PATH --unban <ip>
  health:  sudo $HANDLER_PATH --health   (also checked every 15 min: you get an alert if the trap goes blind)
  heartbeat: a "still watching" message every $(conf_get "$CONF_PATH" HEARTBEAT_DAYS 7) day(s) (HEARTBEAT_DAYS, 0 = off);
           no heartbeat = something is wrong. HEARTBEAT_URL adds an outside dead-man's switch.
EOF
}

main() {
  set -euo pipefail
  parse_args "$@"
  [[ $EUID -eq 0 ]] || die "run with sudo"
  resolve_user
  load_names
  echo "Using settings from $SRC_CONF"
  if [[ $SRC_CONF == *.example ]]; then echo "  (tip: cp honeypot.conf.example honeypot.conf and pick your own names)"; fi
  load_previous
  collect_baits
  refuse_collisions
  install_deps
  check_python
  probe_syscalls
  preflight_audit "$(auditctl -l 2>/dev/null)"
  trap on_failure EXIT
  disarm
  create_baits
  migrate_legacy
  install_handler
  install_config
  install_unit
  load_rules
  verify_rules "$(auditctl -l 2>/dev/null)" "$(auditctl -s 2>/dev/null)"
  e2e_test
  start_service
  summary
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
