# Shared by install.sh and uninstall.sh (sourced, not executed).
# Reads the STEALTH names from ./honeypot.conf (or the .example) next to the scripts.

die() { echo "ERROR: $*" >&2; exit 1; }

# conf_get FILE KEY [DEFAULT]  -> value of the last KEY=... line, quotes stripped
conf_get() {
  local v
  v=$(sed -n "s/^[[:space:]]*$2[[:space:]]*=//p" "$1" 2>/dev/null | tail -n1)
  v=${v#"${v%%[![:space:]]*}"}; v=${v%"${v##*[![:space:]]}"}
  if [[ $v =~ ^\"(.*)\"$ || $v =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
  printf '%s' "${v:-${3:-}}"
}

# conf_set FILE KEY VALUE  -> replace KEY=... in place (keeps perms) or append it
conf_set() {
  local tmp
  tmp=$(mktemp)
  K=$2 V=$3 awk '
    index($0, ENVIRON["K"] "=") == 1 { print ENVIRON["K"] "=" ENVIRON["V"]; done = 1; next }
    { print }
    END { if (!done) print ENVIRON["K"] "=" ENVIRON["V"] }' "$1" >"$tmp"
  cat "$tmp" >"$1"
  rm -f "$tmp"
}

NAME_KEYS=(SERVICE_NAME SERVICE_DESCRIPTION HANDLER_PATH CONF_PATH REPORT_DIR RULES_NAME AUDIT_KEY NFT_TABLE)

# Names used before they became configurable; migrated / cleaned up automatically.
LEGACY_SERVICE=honeypot
LEGACY_HANDLER=/usr/local/sbin/honeypot-handler
LEGACY_CONF=/etc/honeypot.conf
LEGACY_REPORTS=/var/log/honeypot
LEGACY_RULES=/etc/audit/rules.d/honeypot.rules
LEGACY_KEY=honeypot
LEGACY_TABLE=honeypot

# A line only the handler contains: used to recognise our own installed copy.
HANDLER_MARKER='watches the auditd log for access to a bait file'

load_names() {
  SRC_CONF="$HERE/honeypot.conf"
  [[ -f $SRC_CONF ]] || SRC_CONF="$HERE/honeypot.conf.example"
  [[ -f $SRC_CONF ]] || die "no honeypot.conf or honeypot.conf.example next to $0"

  SERVICE_NAME=$(conf_get "$SRC_CONF" SERVICE_NAME polkit-agent-helper)
  SERVICE_DESCRIPTION=$(conf_get "$SRC_CONF" SERVICE_DESCRIPTION "Authorization Agent Helper")
  HANDLER_PATH=$(conf_get "$SRC_CONF" HANDLER_PATH /usr/lib/polkit-1/polkit-agent-helper)
  CONF_PATH=$(conf_get "$SRC_CONF" CONF_PATH /etc/polkit-1/agent-helper.conf)
  REPORT_DIR=$(conf_get "$SRC_CONF" REPORT_DIR /var/lib/polkit-1/agent-cache)
  RULES_NAME=$(conf_get "$SRC_CONF" RULES_NAME 50-polkit)
  AUDIT_KEY=$(conf_get "$SRC_CONF" AUDIT_KEY pk-auth)
  NFT_TABLE=$(conf_get "$SRC_CONF" NFT_TABLE raw_filter)

  local path_re='^/[A-Za-z0-9._/-]+$'
  [[ $SERVICE_NAME =~ ^[A-Za-z0-9._-]+$ ]] || die "SERVICE_NAME: letters, digits, . _ - only"
  [[ $SERVICE_DESCRIPTION =~ ^[A-Za-z0-9\ ._()/-]+$ ]] || die "SERVICE_DESCRIPTION: letters, digits, spaces, . _ ( ) / - only"
  [[ $RULES_NAME =~ ^[A-Za-z0-9._-]+$ ]] || die "RULES_NAME: letters, digits, . _ - only"
  [[ $AUDIT_KEY =~ ^[A-Za-z0-9._-]{1,31}$ ]] || die "AUDIT_KEY: 1-31 chars, letters, digits, . _ -"
  [[ $NFT_TABLE =~ ^[A-Za-z][A-Za-z0-9_]*$ ]] || die "NFT_TABLE: letters, digits, _ (start with a letter)"
  local k
  for k in HANDLER_PATH CONF_PATH REPORT_DIR; do
    [[ ${!k} =~ $path_re && ${!k} != *..* ]] || die "$k must be an absolute path of letters, digits, . _ - /"
  done
  case $REPORT_DIR in
    / | /etc | /usr | /var | /var/lib | /var/log | /var/cache | /tmp | /root | /home) die "REPORT_DIR=$REPORT_DIR is too broad, use a dedicated folder" ;;
  esac

  UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"
  RULES_FILE="/etc/audit/rules.d/$RULES_NAME.rules"
}

# True if PATH (absolute, normalised) reaches its target without following a
# symlink. We run as root inside users' homes: a symlink planted there (e.g.
# ~/.aws -> /etc) must never make us create, chown or delete a system file.
no_symlink() { [[ $(realpath -m -- "$1") == "$1" ]]; }

# --- "is this ours?" checks, so we never touch a real system file ----------
unit_is_ours()    { grep -qxF "ExecStart=$2" "$1" 2>/dev/null; }      # unit handler
handler_is_ours() { grep -qF "$HANDLER_MARKER" "$1" 2>/dev/null; }
rules_is_ours()   { grep -qE -- "-k $2\$" "$1" 2>/dev/null; }          # file key
conf_is_ours()    { grep -q '^AUDIT_KEY=' "$1" 2>/dev/null; }

# Remove one installed copy (service + handler + rules + audit key + nft table)
remove_install() { # unit handler rules key table
  if [[ -f $1 ]] && unit_is_ours "$1" "$2"; then
    systemctl disable --now "$(basename "$1")" >/dev/null 2>&1 || true
    rm -f "$1"
  fi
  if [[ -f $2 ]] && handler_is_ours "$2"; then rm -f "$2"; fi
  if [[ -f $3 ]] && rules_is_ours "$3" "$4"; then rm -f "$3"; fi
  auditctl -D -k "$4" >/dev/null 2>&1 || true
  nft delete table inet "$5" 2>/dev/null || true
}

# Delete report files only (never rm -rf a folder the user may have pointed at a real dir)
remove_reports() {
  [[ -d $1 ]] || return 0
  find "$1" -maxdepth 1 -type f -name '[0-9]*-[0-9]*.log' -delete
  rm -f -- "$1/state" "$1/state.tmp"   # the handler's heartbeat state (STATE_FILE)
  rmdir "$1" 2>/dev/null || true
}
