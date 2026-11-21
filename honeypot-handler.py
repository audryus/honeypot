#!/usr/bin/env python3
"""
honeypot-handler: watches the auditd log for access to a bait file, then
  1. contains the intruder (terminates the login session / kills the process,
     bans the source IP in nftables and drops its open sockets)
  2. gathers everything it can about who did it
  3. sends a notification (ntfy / Telegram / Discord / generic webhook)

Runs as root from a systemd unit. Stdlib only. Every on-disk name (unit, this
file's path, config path, report dir, nft table, audit key) is chosen in the
config's "stealth" section and applied by install.sh, which also bakes the
config path into CONF_PATH below. Journal output is kept deliberately neutral;
details go to the report files only.

CLI (installed under whatever HANDLER_PATH is set to):
  <handler>              run the watcher (what systemd does)
  <handler> --test       send a test notification
  <handler> --health     check the trap can fire (rules loaded, auditd up...)
  <handler> --bans       list currently banned IPs
  <handler> --unban IP   remove an IP from the ban list
"""
import ipaddress
import json
import os
import pwd
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime

# install.sh rewrites this line with the configured CONF_PATH (keep it on one line)
CONF_PATH = os.environ.get("HONEYPOT_CONF", "/etc/polkit-1/agent-helper.conf")
UNSET = ("4294967295", "-1", "", "unset")
SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "busybox", "tcsh", "csh"}

DEFAULTS = {
    "BAIT_FILE": "",
    "HOST_LABEL": "",            # name shown in alerts (default: hostname)
    "AUDIT_LOG": "/var/log/audit/audit.log",
    # stealth names read at runtime (the rest of that section is install-only)
    "AUDIT_KEY": "pk-auth",
    "NFT_TABLE": "raw_filter",
    "REPORT_DIR": "/var/lib/polkit-1/agent-cache",
    "RULES_NAME": "50-polkit",   # NixOS: the handler loads the rules file itself
    # containment
    "KILL_SESSION": "yes",
    "BAN_IP": "yes",
    "BAN_TIMEOUT": "1h",
    "BAN_SAFE_IPS": "",          # never banned (session is still killed)
    # noise control
    "IGNORE_AUIDS": "",          # login uids to skip entirely
    "DEBOUNCE_SECONDS": "30",
    # enrichment
    "IP_LOOKUP": "yes",          # ipinfo.io lookup for public IPs only
    # notification channels (any combination)
    "NTFY_URL": "",              # e.g. https://ntfy.sh/my-secret-topic
    "NTFY_TOKEN": "",
    "TELEGRAM_BOT_TOKEN": "",
    "TELEGRAM_CHAT_ID": "",
    "DISCORD_WEBHOOK": "",
    "WEBHOOK_URL": "",           # generic JSON POST
    # liveness (install and forget: say so when the trap can't fire any more)
    "HEARTBEAT_DAYS": "7",       # "still watching" message every N days (0 = off)
    "HEARTBEAT_URL": "",         # dead-man's switch pinged while healthy
}
PROC = "/proc"
HEALTH_EVERY = 900               # seconds between health checks / pings
START_DELAY = 120                # first health check after start (let auditd settle)
RECHECK_AFTER = 60               # a problem must still be there this much later
WATCHER_STALE = 300              # audit log loop silent this long = stuck
AUSEARCH_DELAY = 0.7             # let auditd flush the rest of an event
POLL = 0.2                       # audit log polling interval
STATE_FILE = "state"             # in REPORT_DIR: when the last heartbeat went out
REPORT_RE = re.compile(r"^\d{8}-\d{6}-\d+\.log$")
RULES_DIR = "/etc/audit/rules.d"
# NixOS loads only its own audit rules (and deletes all rules when it reloads
# them): there the handler loads ours at start (see ensure_rules).
NIXOS_MARK = "/etc/NIXOS"
RULES_RETRIES = 3
LEASE_FILES = ("/etc/pihole/dhcp.leases", "/var/lib/misc/dnsmasq.leases")

_last_seen = {}
_lock = threading.Lock()
_tick = [time.time()]            # last turn of the audit log loop (stuck watcher check)


# ---------------------------------------------------------------- config
def unquote(v):
    """Strip one pair of matching quotes."""
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def parse_conf_line(line):
    """(key, value) from a KEY=value line, None for comments and blanks."""
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    k, v = line.split("=", 1)
    return k.strip(), unquote(v.strip())


def parse_conf(text):
    """Config text over DEFAULTS (the last occurrence of a key wins)."""
    cfg = dict(DEFAULTS)
    for line in text.splitlines():
        kv = parse_conf_line(line)
        if kv:
            cfg[kv[0]] = kv[1]
    return cfg


def load_conf(path=None):
    """Re-read on every event, so runtime keys need no restart."""
    try:
        with open(path or CONF_PATH) as f:
            return parse_conf(f.read())
    except FileNotFoundError:
        return dict(DEFAULTS)


def host(cfg):
    return cfg.get("HOST_LABEL") or socket.gethostname()


def baits(cfg):
    return cfg["BAIT_FILE"].split()


def yes(v):
    return str(v).strip().lower() in ("1", "yes", "true", "on")


def seconds(cfg, key):
    """A numeric setting; a typo falls back to the default instead of raising
    (an exception here would drop the alert)."""
    try:
        return float(cfg[key])
    except (TypeError, ValueError):
        return float(DEFAULTS[key])


def ban_timeout(cfg):
    v = cfg["BAN_TIMEOUT"].strip()
    return v if re.fullmatch(r"(\d+[smhd])+", v) else DEFAULTS["BAN_TIMEOUT"]


# ---------------------------------------------------------------- helpers
def norm_ip(s):
    """Canonical IP string ('[::ffff:1.2.3.4]' -> '1.2.3.4'), or None."""
    try:
        a = ipaddress.ip_address(str(s).strip().strip("[]"))
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def log(*a):
    print(*a, flush=True)


def run(cmd, timeout=5, input=None):
    """(returncode, stdout, stderr); never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def count_lines(text):
    return sum(1 for l in text.splitlines() if l.strip())


def parse_kv(text):
    """KEY=value lines (loginctl show-session) to a dict."""
    return dict(l.split("=", 1) for l in text.splitlines() if "=" in l)


def all_ok(results):
    return bool(results) and all(": ok" in r for r in results)


def any_ok(results):
    return any(": ok" in r for r in results)


def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------- audit records
FIELD_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')
STAMP_RE = re.compile(r"msg=audit\(([\d.]+):(\d+)\)")


def audit_fields(raw):
    """key=value / key="value" pairs of one audit record."""
    return {m.group(1): m.group(3) if m.group(3) is not None else m.group(2)
            for m in FIELD_RE.finditer(raw)}


def parse_audit(line):
    raw = line.split("\x1d", 1)[0]  # drop ENRICHED part
    d = audit_fields(raw)
    m = STAMP_RE.search(raw)
    if m:
        d["_ts"], d["_serial"] = m.group(1), m.group(2)
    return d


def is_trigger(line, needle):
    """A SYSCALL record carrying our audit key (one per access)."""
    return "type=SYSCALL" in line and needle in line


def username(uid):
    if uid in UNSET or uid is None:
        return "unset"
    try:
        return f"{pwd.getpwuid(int(uid)).pw_name} ({uid})"
    except Exception:  # noqa: BLE001
        return str(uid)


# ---------------------------------------------------------------- /proc
def parse_stat(text):
    """(comm, ppid) from /proc/PID/stat; comm may contain spaces and parens."""
    comm = text[text.index("(") + 1 : text.rindex(")")]
    ppid = int(text[text.rindex(")") + 2 :].split()[1])
    return comm, ppid


def parse_cmdline(raw):
    return raw.replace(b"\0", b" ").decode(errors="replace").strip()


def ssh_from_environ(raw):
    """SSH_CONNECTION from /proc/PID/environ (attacker-controlled: report only)."""
    found = ""
    for e in raw.split(b"\0"):
        if e.startswith(b"SSH_CONNECTION="):
            found = e.split(b"=", 1)[1].decode(errors="replace")
    return found


def container_from_cgroup(text):
    m = re.search(r"(?:docker|libpod)[-/]([0-9a-f]{12,64})", text)
    return m.group(1)[:12] if m else ""


def proc_info(pid):
    base = f"{PROC}/{pid}"
    stat = read_bytes(f"{base}/stat")
    if stat is None:
        return None
    try:
        comm, ppid = parse_stat(stat.decode(errors="replace"))
        info = {"pid": int(pid), "ppid": ppid, "comm": comm}
    except (ValueError, IndexError):
        return None
    info["cmdline"] = parse_cmdline(read_bytes(f"{base}/cmdline") or b"")
    ssh = ssh_from_environ(read_bytes(f"{base}/environ") or b"")
    if ssh:
        info["ssh"] = ssh
    container = container_from_cgroup((read_bytes(f"{base}/cgroup") or b"").decode(errors="replace"))
    if container:
        info["container"] = container
    return info


def proc_chain(pid):
    """The process and its ancestors, nearest first."""
    try:
        p = int(pid)
    except (TypeError, ValueError):
        return []
    out, seen = [], set()
    while p > 0 and p not in seen and len(out) < 40:
        seen.add(p)
        i = proc_info(p)
        if not i:
            break
        out.append(i)
        p = i["ppid"]
    return out


def is_conn_sshd(p):
    """A per-connection sshd (the listener's parent is init)."""
    return p["comm"].startswith("sshd") and p["ppid"] != 1


def sshd_pids(procs):
    return [p["pid"] for p in procs if is_conn_sshd(p)]


def first_container(procs):
    return next((p["container"] for p in procs if p.get("container")), "")


# ---------------------------------------------------------------- containment
def nft_ruleset(table):
    """Ban table: sets checked at prerouting/raw, so a ban blocks everything."""
    return f"""table inet {table} {{
  set banned4 {{ type ipv4_addr; flags timeout; }}
  set banned6 {{ type ipv6_addr; flags timeout; }}
  chain prerouting {{
    type filter hook prerouting priority raw; policy accept;
    ip saddr @banned4 drop
    ip6 saddr @banned6 drop
  }}
}}
"""


def ensure_nft(cfg):
    table = cfg["NFT_TABLE"]
    if run(["nft", "list", "table", "inet", table])[0] == 0:
        return
    rc, _, err = run(["nft", "-f", "-"], input=nft_ruleset(table))
    if rc != 0:
        log(f"WARN: could not create nft table: {err}")


def ip_set(ip):
    return "banned4" if ipaddress.ip_address(ip).version == 4 else "banned6"


def ban_target(ip, cfg):
    """(normalised ip, None) to ban it, or (ip, reason) not to."""
    n = norm_ip(ip)
    if not n:
        return ip, "not an IP address"
    safe = {norm_ip(x) for x in cfg["BAN_SAFE_IPS"].split()}
    if ipaddress.ip_address(n).is_loopback or n in safe:
        return n, "loopback / BAN_SAFE_IPS"
    return n, None


def drop_sockets(ip, actions):
    n = count_lines(run(["ss", "-K", "-H", "dst", ip])[1])
    if n:
        actions.append(f"killed {n} open socket(s) from {ip}")


def ban_ip(ip, cfg, actions):
    ip, why_not = ban_target(ip, cfg)
    if why_not:
        actions.append(f"NOT banned {ip} ({why_not})")
        return
    ensure_nft(cfg)
    timeout = ban_timeout(cfg)
    rc, _, err = run(["nft", "add", "element", "inet", cfg["NFT_TABLE"], ip_set(ip),
                      f"{{ {ip} timeout {timeout} }}"])
    actions.append(f"banned {ip} for {timeout}" if rc == 0 else f"ban {ip} failed: {err}")
    drop_sockets(ip, actions)


def kill(pid, sig, actions, why):
    if pid <= 1 or pid == os.getpid():
        return
    try:
        os.kill(pid, sig)
        actions.append(f"killed pid {pid} ({why})")
    except ProcessLookupError:
        pass
    except Exception as e:  # noqa: BLE001
        actions.append(f"kill {pid} failed: {e}")


def terminate_session(ses, actions):
    """True if logind ended the login session."""
    if ses in UNSET:
        return False
    rc, _, err = run(["loginctl", "terminate-session", ses])
    if rc == 0:
        actions.append(f"terminated login session {ses}")
        return True
    actions.append(f"terminate-session {ses} failed: {err or rc}")
    return False


def sshd_connection(procs):
    """What to kill to drop the SSH connection: from the process up to the
    topmost per-connection sshd (never the listener). [] if not over SSH."""
    for i, p in enumerate(procs):
        if is_conn_sshd(p):
            top = i
            while top + 1 < len(procs) and is_conn_sshd(procs[top + 1]):
                top += 1
            return procs[: top + 1]
    return []


def kill_process_and_shell(ev, actions):
    """No session (daemon / web shell / container): only the process and its
    shell parent; never walk further up (the parent could be a service)."""
    kill(int(ev.get("pid", 0)), signal.SIGKILL, actions, ev.get("comm", "?"))
    parent = proc_info(ev.get("ppid", 0))
    if parent and parent["comm"] in SHELLS:
        kill(parent["pid"], signal.SIGKILL, actions, f"parent shell {parent['comm']}")


def contain(ev, procs, actions):
    if terminate_session(ev.get("ses", ""), actions):
        return
    chain = sshd_connection(procs)
    for q in chain:
        kill(q["pid"], signal.SIGKILL, actions, q["comm"])
    if not chain:
        kill_process_and_shell(ev, actions)


# ---------------------------------------------------------------- source of the intrusion
def session_info(ses):
    if ses in UNSET:
        return {}
    rc, out, _ = run(["loginctl", "show-session", ses, "-p", "Name", "-p", "RemoteHost",
                      "-p", "Service", "-p", "TTY", "-p", "Timestamp", "-p", "Leader", "-p", "Type"])
    return parse_kv(out) if rc == 0 else {}


def ss_peer(ss_out, pid):
    """(ip, port) of PID's TCP peer in `ss -tnpH state established` output
    (no State column there: the peer is the 4th field), or None."""
    for l in ss_out.splitlines():
        if f"pid={pid}," in l:
            ip, _, port = l.split()[3].rpartition(":")
            return norm_ip(ip) or ip.strip("[]"), port
    return None


def claimed_connection(procs):
    return next((p["ssh"] for p in procs if p.get("ssh")), "")


def find_remote(procs, sess):
    """Source (ip, port, claimed). Only sources the intruder can't forge are
    trusted: the kernel's view of the sshd process's TCP peer, then logind's
    RemoteHost (set by sshd through PAM). SSH_CONNECTION comes from the process
    environment, which the intruder controls (`export SSH_CONNECTION="<your
    router> 1 2 22"` would get the wrong IP banned), so it is only returned as
    `claimed`, for the report."""
    claimed = claimed_connection(procs)
    pids = sshd_pids(procs)
    if pids:
        out = run(["ss", "-tnpH", "state", "established"])[1]
        for pid in pids:
            peer = ss_peer(out, pid)
            if peer:
                return peer[0], peer[1], claimed
    if sess.get("RemoteHost"):
        return norm_ip(sess["RemoteHost"]) or sess["RemoteHost"], "", claimed
    return "", "", claimed


# ---------------------------------------------------------------- enrichment
def rdns(ip):
    rc, out, _ = run(["getent", "hosts", ip], timeout=3)
    return " ".join(out.split()[1:]) if rc == 0 and out else ""


def parse_lladdr(neigh_out):
    m = re.search(r"lladdr (\S+)", neigh_out)
    return m.group(1) if m else ""


def mac_of(ip):
    return parse_lladdr(run(["ip", "neigh", "show", ip])[1])


def dhcp_lease(lines, ip):
    """'hostname (mac ...)' for IP in dnsmasq-style lease lines (last one wins)."""
    found = ""
    for l in lines:
        p = l.split()
        if len(p) >= 4 and p[2] == ip:
            found = f"{p[3]} (mac {p[1]})"
    return found


def dhcp_of(ip):
    found = ""
    for lf in LEASE_FILES:
        try:
            with open(lf) as f:
                found = dhcp_lease(f, ip) or found
        except OSError:
            pass
    return found


def format_geo(j):
    return ", ".join(str(j[k]) for k in ("city", "region", "country", "org") if j.get(k))


def geo_of(ip, cfg):
    """ipinfo.io, public IPs only."""
    try:
        if not (ipaddress.ip_address(ip).is_global and yes(cfg["IP_LOOKUP"])):
            return ""
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=4) as r:
            return format_geo(json.load(r))
    except Exception:  # noqa: BLE001
        return ""


def sshd_log(ip):
    out = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "-3d", "--no-pager",
               "-o", "cat", "-g", f"(Accepted|Failed).* from {re.escape(ip)} "], timeout=6)[1]
    return out.splitlines()[-3:] if out else []


def ip_details(ip, cfg):
    d = {"rdns": rdns(ip), "mac": mac_of(ip), "dhcp": dhcp_of(ip),
         "geo": geo_of(ip, cfg), "sshlog": sshd_log(ip)}
    return {k: v for k, v in d.items() if v}


AUSEARCH_FIELDS = (("proctitle", r"proctitle=(.*)$"), ("cwd", r"type=CWD .*cwd=(\S+)"),
                   ("syscall", r"syscall=(\S+)"), ("exit", r" exit=(\S+)"))


def path_record(line):
    return dict(re.findall(r"\b(name|inode|dev)=(\S+)", line))


def parse_ausearch(out):
    """proctitle, cwd, syscall, exit and PATH records from `ausearch -i`."""
    d = {}
    for key, rx in AUSEARCH_FIELDS:
        m = re.search(rx, out, re.M)
        if m:
            d[key] = m.group(1).strip()
    d["paths"] = [path_record(l) for l in out.splitlines() if l.startswith("type=PATH")]
    d["raw"] = out
    return d


def ausearch(serial):
    time.sleep(AUSEARCH_DELAY)
    # -ts recent: serial numbers restart at every boot, so without a time bound
    # an older event with the same serial would be picked up. --input-logs:
    # without it ausearch reads stdin instead of the logs when stdin is a pipe
    return parse_ausearch(run(["ausearch", "--input-logs", "-a", serial, "-ts", "recent", "-i"], timeout=6)[1])


# ---------------------------------------------------------------- which bait
def dev_str(st_dev):
    """st_dev as audit prints it (major:minor in hex)."""
    return f"{os.major(st_dev):02x}:{os.minor(st_dev):02x}"


def bait_ids(paths):
    """{(inode, dev): bait}; stat() doesn't open the file, so it can't trigger."""
    ids = {}
    for b in paths:
        try:
            st = os.stat(b)
            ids[(str(st.st_ino), dev_str(st.st_dev))] = b
        except OSError:
            pass
    return ids


def match_inode(ids, paths):
    for p in paths:
        hit = ids.get((p.get("inode"), p.get("dev")))
        if hit:
            return hit
        # btrfs: stat() reports a per-subvolume dev, audit the superblock's one
        same = [b for (ino, _), b in ids.items() if ino == p.get("inode")]
        if len(same) == 1:
            return same[0]
    return None


def bait_by_name(paths, name, cwd):
    """The bait a (maybe relative) PATH name points to, or None."""
    if not name or name == "(null)":
        return None
    full = os.path.normpath(os.path.join(cwd, name)) if cwd and not name.startswith("/") else name
    if full in paths:
        return full
    cands = [b for b in paths if b.endswith("/" + os.path.normpath(name))]
    if len(cands) == 1:
        return cands[0]
    return f"one of: {' '.join(cands)}" if cands else None


def match_name(bait_paths, records, cwd):
    for p in records:
        hit = bait_by_name(bait_paths, p.get("name", "").strip('"'), cwd)
        if hit:
            return hit
    return None


def default_bait(paths):
    if len(paths) == 1:
        return paths[0]
    return f"one of: {' '.join(paths)}" if paths else "?"


def which_bait(bait_paths, records, cwd=""):
    """Which of the (possibly many) bait files was touched, from the PATH records.
    By inode first (a relative name like "config" can't tell ~/.aws/config from
    ~/.kube/config), then by name (e.g. the bait was replaced since)."""
    return (match_inode(bait_ids(bait_paths), records)
            or match_name(bait_paths, records, cwd)
            or default_bait(bait_paths))


# ---------------------------------------------------------------- notify
def http(url, data, headers, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def ntfy_request(cfg, title, body, priority, tags):
    h = {"Title": title.encode("ascii", "ignore").decode(), "Priority": priority, "Tags": tags}
    if cfg["NTFY_TOKEN"]:
        h["Authorization"] = f"Bearer {cfg['NTFY_TOKEN']}"
    return cfg["NTFY_URL"], body.encode(), h


def telegram_request(cfg, title, body):
    data = urllib.parse.urlencode({"chat_id": cfg["TELEGRAM_CHAT_ID"],
                                   "text": f"{title}\n\n{body}"[:4000]}).encode()
    return (f"https://api.telegram.org/bot{cfg['TELEGRAM_BOT_TOKEN']}/sendMessage", data,
            {"Content-Type": "application/x-www-form-urlencoded"})


def discord_request(cfg, title, body):
    data = json.dumps({"content": f"**{title}**\n```\n{body[:1850]}\n```"}).encode()
    return cfg["DISCORD_WEBHOOK"], data, {"Content-Type": "application/json"}


def webhook_request(cfg, title, body, event):
    data = json.dumps({"title": title, "message": body, "event": event or {}}).encode()
    return cfg["WEBHOOK_URL"], data, {"Content-Type": "application/json"}


def channels(cfg, title, body, event, priority, tags):
    """(name, url, data, headers) for every configured channel."""
    out = []
    if cfg["NTFY_URL"]:
        out.append(("ntfy", *ntfy_request(cfg, title, body, priority, tags)))
    if cfg["TELEGRAM_BOT_TOKEN"] and cfg["TELEGRAM_CHAT_ID"]:
        out.append(("telegram", *telegram_request(cfg, title, body)))
    if cfg["DISCORD_WEBHOOK"]:
        out.append(("discord", *discord_request(cfg, title, body)))
    if cfg["WEBHOOK_URL"]:
        out.append(("webhook", *webhook_request(cfg, title, body, event)))
    return out


def send(name, url, data, headers):
    try:
        http(url, data, headers)
        return f"{name}: ok"
    except Exception as e:  # noqa: BLE001
        return f"{name}: FAILED {e}"


def notify(cfg, title, body, event=None, priority="urgent", tags="rotating_light,skull"):
    """One 'name: ok' / 'name: FAILED ...' line per channel."""
    results = [send(*c) for c in channels(cfg, title, body, event, priority, tags)]
    return results or ["no notification channel configured"]


# ---------------------------------------------------------------- health
def bait_problems(paths):
    if not paths:
        return ["no bait files configured (BAIT_FILE is empty)"]
    return [f"bait file is gone: {b}" for b in paths if not os.path.lexists(b)]


def parse_audit_status(out):
    """`auditctl -s` lines ('enabled 1', 'pid 812'...) to a dict."""
    st = {}
    for l in out.splitlines():
        parts = l.split(None, 1)
        if len(parts) == 2:
            st[parts[0]] = parts[1]
    return st


def status_problems(st):
    p = []
    if st.get("enabled") == "0":
        p.append("kernel auditing is disabled (auditctl -s: enabled 0)")
    if st.get("pid", "0") == "0":
        p.append("auditd is not running: nothing reaches the audit log")
    return p


def auditd_problems():
    rc, out, err = run(["auditctl", "-s"])
    if rc != 0:
        return [f"auditctl -s failed: {err or rc}"]
    return status_problems(parse_audit_status(out))


def key_rules(rules_out, key):
    """Loaded rules carrying KEY (`-k KEY` or `key=KEY`, by auditctl version)."""
    rx = re.compile(r"(-k |key=)" + re.escape(key) + r"$")
    return [l for l in rules_out.splitlines() if rx.search(l)]


def rules_for(rules, bait):
    return [l for l in rules if f"-w {bait} " in l or f"path={bait} " in l]


def bait_rule_problems(rules, bait):
    mine = rules_for(rules, bait)
    p = []
    if not any(re.search(r"-S \S*open", l) for l in mine):
        p.append(f"audit rule for opening {bait} is not loaded")
    if not any(re.search(r"(-p |perm=)[a-z]*w", l) for l in mine):
        p.append(f"audit watch for writing {bait} is not loaded")
    return p


def rule_problems(rules_out, key, paths):
    rules = key_rules(rules_out, key)
    return [p for b in paths for p in bait_rule_problems(rules, b)]


def loaded_rule_problems(cfg, paths):
    rc, out, err = run(["auditctl", "-l"])
    if rc != 0:
        return [f"auditctl -l failed: {err or rc}"]
    return rule_problems(out, cfg["AUDIT_KEY"], paths)


def rules_file(cfg):
    return os.path.join(RULES_DIR, cfg["RULES_NAME"] + ".rules")


def ensure_rules(cfg):
    """Load our rules file if any bait's rules are missing; True once all are
    loaded. The kernel can refuse a watch re-added right after it was deleted,
    so delete, pause, load, check, retry (like install.sh's reload_rules).
    `auditctl -R FILE` exactly: auditctl loads nothing if given another option."""
    paths = baits(cfg)
    if not paths or not loaded_rule_problems(cfg, paths):
        return True
    path = rules_file(cfg)
    if not os.path.isfile(path):
        return False
    for attempt in range(1, RULES_RETRIES + 1):
        run(["auditctl", "-D", "-k", cfg["AUDIT_KEY"]])
        time.sleep(attempt)
        run(["auditctl", "-R", path])
        if not loaded_rule_problems(cfg, paths):
            return True
    return False


def log_problems(path):
    return [] if os.path.exists(path) else [f"audit log {path} does not exist (AUDIT_LOG)"]


def watcher_problems(now, tick):
    return ["the audit log watcher is stuck"] if now - tick > WATCHER_STALE else []


def health(cfg, check_watcher=False):
    """Problems that would keep the trap from ever firing. Never opens a bait
    (stat/lexists don't trigger the audit rules)."""
    paths = baits(cfg)
    problems = (bait_problems(paths) + auditd_problems()
                + loaded_rule_problems(cfg, paths) + log_problems(cfg["AUDIT_LOG"]))
    if check_watcher:
        problems += watcher_problems(time.time(), _tick[0])
    return problems


# ---------------------------------------------------------------- liveness
def read_state(cfg):
    try:
        with open(os.path.join(cfg["REPORT_DIR"], STATE_FILE)) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def write_state(cfg, st):
    os.makedirs(cfg["REPORT_DIR"], mode=0o700, exist_ok=True)
    path = os.path.join(cfg["REPORT_DIR"], STATE_FILE)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f)
    os.replace(path + ".tmp", path)


def reports_since(cfg, since):
    try:
        with os.scandir(cfg["REPORT_DIR"]) as it:
            return sum(1 for e in it if REPORT_RE.match(e.name) and e.stat().st_mtime > since)
    except OSError:
        return 0


def checked_problems():
    """(cfg, problems); a problem must survive a re-check (auditd restart,
    package upgrade...) to count."""
    cfg = load_conf()
    problems = health(cfg, check_watcher=True)
    if problems:
        time.sleep(RECHECK_AFTER)
        cfg = load_conf()
        problems = health(cfg, check_watcher=True)
    return cfg, problems


def report_change(cfg, problems, reported):
    """Alert on new problems and on recovery; returns what is now reported."""
    if set(problems) - reported:
        notify(cfg, f"Honeypot PROBLEM on {host(cfg)}",
               "The tripwire may be blind:\n- " + "\n- ".join(problems)
               + "\n\nOn the machine: sudo <handler> --health", tags="warning")
    elif reported and not problems:
        notify(cfg, f"Honeypot recovered on {host(cfg)}", "All checks pass again.",
               priority="default", tags="white_check_mark")
    return set(problems)


def ping(url):
    """Dead-man's switch: an outside service alerts when these stop."""
    try:
        urllib.request.urlopen(url, timeout=10).close()
    except Exception:  # noqa: BLE001
        pass


def heartbeat_due(st, now, days):
    """'start' (first run: only record the time, the install's test message was
    the first sign of life), 'send', or None."""
    if days <= 0:
        return None
    last = st.get("heartbeat")
    if not isinstance(last, (int, float)):
        return "start"
    return "send" if now - last >= days * 86400 else None


def heartbeat_body(cfg, problems, alerts, days):
    checks = "all OK" if not problems else "PROBLEMS: " + "; ".join(problems)
    return (f"Still watching on {host(cfg)}.\n"
            f"Bait files: {len(baits(cfg))}\n"
            f"Checks:     {checks}\n"
            f"Alerts since the last heartbeat: {alerts}\n"
            f"Next heartbeat in {days:g} day(s).")


def heartbeat(cfg, problems, now):
    days = seconds(cfg, "HEARTBEAT_DAYS")
    st = read_state(cfg)
    due = heartbeat_due(st, now, days)
    if due == "send":
        body = heartbeat_body(cfg, problems, reports_since(cfg, st["heartbeat"]), days)
        r = notify(cfg, f"Honeypot heartbeat from {host(cfg)}", body,
                   priority="low", tags="green_heart")
        if not any_ok(r):
            return  # retried at the next check
    if due:
        st["heartbeat"] = now
        write_state(cfg, st)


def liveness_tick(reported):
    cfg, problems = checked_problems()
    reported = report_change(cfg, problems, reported)
    if not problems and cfg["HEARTBEAT_URL"]:
        ping(cfg["HEARTBEAT_URL"])
    heartbeat(cfg, problems, time.time())
    return reported


def liveness_loop():
    """Install and forget: nobody looks at this box, so it must speak up by
    itself. Immediate alert when the trap goes blind (and when it recovers),
    a periodic "still watching" message, and a dead-man's-switch ping that an
    outside service turns into an alert if it stops (box down, channel broken)."""
    time.sleep(START_DELAY)
    reported = set()
    while True:
        try:
            reported = liveness_tick(reported)
        except Exception as e:  # noqa: BLE001
            log(f"check failed ({type(e).__name__})")
        time.sleep(HEALTH_EVERY)


# ---------------------------------------------------------------- report
def ignored(ev, cfg):
    return ev.get("auid") in cfg["IGNORE_AUIDS"].split()


def debounce_key(ev):
    """Per login session, or per process when there is none."""
    ses = ev.get("ses", "")
    return ses if ses not in UNSET else f"pid{ev.get('pid', '0')}"


def debounced(key, window, now=None):
    """True if KEY already fired less than WINDOW seconds ago (else records it)."""
    with _lock:
        now = time.time() if now is None else now
        if now - _last_seen.get(key, 0) < window:
            return True
        _last_seen[key] = now
        return False


def snapshot(ev):
    """Everything containment destroys: take it first."""
    procs = proc_chain(ev.get("pid", "0")) or proc_chain(ev.get("ppid", 0))
    sess = session_info(ev.get("ses", ""))
    ip, port, claimed = find_remote(procs, sess)
    return {"procs": procs, "sess": sess, "ip": ip, "port": port, "claimed": claimed,
            "others": run(["who"])[1]}


def respond(ev, snap, cfg):
    actions = []
    if yes(cfg["KILL_SESSION"]):
        contain(ev, snap["procs"], actions)
    if snap["ip"] and yes(cfg["BAN_IP"]):
        ban_ip(snap["ip"], cfg, actions)
    return actions or ["none (monitor only)"]


def event_time(ev):
    return datetime.fromtimestamp(float(ev.get("_ts", time.time()))).strftime("%Y-%m-%d %H:%M:%S")


def result_line(ev, au):
    outcome = "OPENED" if ev.get("success") == "yes" else "attempt DENIED"
    return (f"Result:   {outcome} ({au.get('syscall', ev.get('syscall', '?'))},"
            f" exit {au.get('exit', ev.get('exit', '?'))})")


def event_lines(ev, au, opened, when):
    return [
        f"File:     {opened}",
        f"When:     {when}",
        result_line(ev, au),
        f"Command:  {au.get('proctitle') or ev.get('comm', '?')}",
        f"Cwd:      {au.get('cwd', '?')}",
        f"Process:  {ev.get('comm', '?')} [{ev.get('exe', '?')}] pid {ev.get('pid', '0')}"
        f" ppid {ev.get('ppid', '?')}",
        f"User:     uid {username(ev.get('uid'))}, euid {username(ev.get('euid'))}",
        f"Login as: {username(ev.get('auid'))}  (session {ev.get('ses', '') or '?'},"
        f" tty {ev.get('tty', '?')})",
    ]


def session_line(sess):
    return f"Session:  {sess.get('Service', '?')} {sess.get('Type', '')} since {sess.get('Timestamp', '?')}"


def ip_lines(ip, port, ipd):
    if not ip:
        return ["Source:   no network session found (local / service / container)"]
    L = [f"Source:   {ip}{':' + port if port else ''}"]
    for k, label in (("rdns", "rDNS"), ("mac", "MAC"), ("dhcp", "DHCP"), ("geo", "Geo")):
        if ipd.get(k):
            L.append(f"  {label + ':':6}  {ipd[k]}")
    L += [f"  sshd:   {s}" for s in ipd.get("sshlog", [])]
    return L


def claimed_lines(claimed, ip):
    """SSH_CONNECTION that disagrees with the trusted source: forged, or the
    chain to sshd was broken (setsid, tmux...). Report only."""
    claimed_ip = norm_ip(claimed.split()[0]) if claimed.split() else None
    if claimed and claimed_ip != ip:
        return [f"  Env claims SSH_CONNECTION={claimed}  (not trusted, not banned)"]
    return []


def tree_line(procs):
    return "Tree:     " + " <- ".join(f"{p['comm']}({p['pid']})" for p in procs[:8])


def report_body(ev, snap, au, ipd, actions, opened, when):
    L = event_lines(ev, au, opened, when)
    if snap["sess"]:
        L.append(session_line(snap["sess"]))
    L += ip_lines(snap["ip"], snap["port"], ipd)
    L += claimed_lines(snap["claimed"], snap["ip"])
    container = first_container(snap["procs"])
    if container:
        L.append(f"Container: {container}  (docker ps | grep {container})")
    if snap["procs"]:
        L.append(tree_line(snap["procs"]))
    L.append("Actions:  " + "; ".join(actions))
    if snap["others"]:
        L.append("Logged in now:\n  " + snap["others"].replace("\n", "\n  "))
    return "\n".join(L)


def event_json(ev, snap, ipd, actions):
    return {"audit": ev, "session": snap["sess"], "ip": snap["ip"],
            "ssh_connection_claimed": snap["claimed"], "ip_details": ipd, "actions": actions,
            "processes": snap["procs"], "container": first_container(snap["procs"])}


def report_name(pid, now):
    return f"{now:%Y%m%d-%H%M%S}-{pid}.log"


def write_report(cfg, name, text):
    """Root-only file in REPORT_DIR (the details never go to the journal)."""
    os.makedirs(cfg["REPORT_DIR"], mode=0o700, exist_ok=True)
    path = os.path.join(cfg["REPORT_DIR"], name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)
    return path


def report_text(title, body, results, au, procs):
    return (f"{title}\n\n{body}\n\nNotify: {results}\n\n--- ausearch ---\n{au.get('raw', '')}\n"
            f"\n--- processes ---\n{json.dumps(procs, indent=2)}\n")


# ---------------------------------------------------------------- main handler
def handle(line, state=None):
    state = {} if state is None else state
    cfg = load_conf()
    ev = parse_audit(line)
    if ignored(ev, cfg) or debounced(debounce_key(ev), seconds(cfg, "DEBOUNCE_SECONDS")):
        return
    snap = snapshot(ev)                     # before anything gets killed
    actions = respond(ev, snap, cfg)
    au = ausearch(ev.get("_serial", "0"))
    ipd = ip_details(snap["ip"], cfg) if snap["ip"] else {}
    opened = which_bait(baits(cfg), au.get("paths", []), au.get("cwd", ""))
    body = report_body(ev, snap, au, ipd, actions, opened, event_time(ev))
    title = f"Honeypot triggered on {host(cfg)}"
    results = notify(cfg, title, body, event_json(ev, snap, ipd, actions))
    state["notified"] = True
    rpt = write_report(cfg, report_name(ev.get("pid", "0"), datetime.now()),
                       report_text(title, body, results, au, snap["procs"]))
    # The journal may be readable by non-root admins (adm/wheel): keep it bland.
    log(f"request {ev.get('_serial', '?')} handled"
        f" ({'delivered' if all_ok(results) else 'delivery failed'}): {rpt}")


def fallback_body(ev, err, key):
    return (f"A bait file was accessed, but building the full report failed: {err!r}\n"
            f"Containment may not have run.\n"
            f"Process: {ev.get('comm', '?')} [{ev.get('exe', '?')}] pid {ev.get('pid', '?')}"
            f" ppid {ev.get('ppid', '?')}\n"
            f"User: uid {ev.get('uid', '?')}, login uid {ev.get('auid', '?')},"
            f" session {ev.get('ses', '?')}\n"
            f"Details: sudo ausearch -k {key} -ts recent -i")


def fallback_alert(line, err):
    try:
        cfg = load_conf()
    except Exception:  # noqa: BLE001
        cfg = dict(DEFAULTS)
    ev = parse_audit(line)
    notify(cfg, f"Honeypot triggered on {host(cfg)}",
           fallback_body(ev, err, cfg.get("AUDIT_KEY", "?")), {"audit": ev, "error": repr(err)})


def _safe_handle(line):
    """Nobody reads this box's logs (install and forget): if building the full
    report fails, a short alert must still go out. The journal stays bland
    (exception type only); the details go to the notification channels."""
    state = {}
    try:
        handle(line, state)
    except Exception as e:  # noqa: BLE001
        log(f"request failed ({type(e).__name__})")
        if state.get("notified"):
            return
        try:
            fallback_alert(line, e)
        except Exception as e2:  # noqa: BLE001
            log(f"request failed ({type(e2).__name__})")


# ---------------------------------------------------------------- audit log
def open_log(path, at_end):
    """(file, inode); at_end skips what's already there, like tail -n0."""
    f = open(path, "rb")
    if at_end:
        f.seek(0, os.SEEK_END)
    return f, os.fstat(f.fileno()).st_ino


def rotated(path, ino, pos):
    """The log was replaced (rotation) or truncated under us."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_ino != ino or st.st_size < pos


def follow(path):
    """Yield new lines appended to path, surviving log rotation. Done in-process
    (instead of `tail -F`) so no tell-tale child process shows up in ps."""
    # Binary mode: tell() is then an exact byte offset (in text mode it is an
    # opaque cookie, which could fake a "truncated" log and replay old events).
    f, ino, buf, first = None, None, b"", True
    while True:
        _tick[0] = time.time()
        if f is None:
            try:
                f, ino = open_log(path, first)
            except OSError:
                time.sleep(1)
                continue
            first, buf = False, b""
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith(b"\n"):
                yield buf.decode(errors="replace")
                buf = b""
            continue
        time.sleep(POLL)
        if rotated(path, ino, f.tell()):
            f.close()
            f = None


def watch():
    cfg = load_conf()
    if os.path.exists(NIXOS_MARK) and not ensure_rules(cfg):
        log("check failed (rules)")   # the liveness loop alerts if it lasts
    ensure_nft(cfg)
    needle = f'key="{cfg["AUDIT_KEY"]}"'
    threading.Thread(target=liveness_loop, daemon=True).start()
    log("agent started")
    for line in follow(cfg["AUDIT_LOG"]):
        if is_trigger(line, needle):
            threading.Thread(target=_safe_handle, args=(line,), daemon=True).start()


# ---------------------------------------------------------------- CLI
def cmd_test():
    cfg = load_conf()
    r = notify(cfg, f"Honeypot test from {host(cfg)}",
               f"Test notification. Bait file: {cfg['BAIT_FILE'] or '?'}\nIf you got this, alerts work.")
    print("\n".join(r))
    return 0 if all_ok(r) else 1


def cmd_health():
    problems = health(load_conf())
    print("\n".join(problems) if problems else "ok: every check passes")
    return 1 if problems else 0


def cmd_bans():
    cfg = load_conf()
    for s in ("banned4", "banned6"):
        print(run(["nft", "list", "set", "inet", cfg["NFT_TABLE"], s])[1])
    return 0


def cmd_unban(arg):
    cfg = load_conf()
    ip = norm_ip(arg)
    if not ip:
        print(f"not an IP address: {arg}", file=sys.stderr)
        return 1
    rc, _, err = run(["nft", "delete", "element", "inet", cfg["NFT_TABLE"], ip_set(ip), f"{{ {ip} }}"])
    print("unbanned" if rc == 0 else err)
    return 0


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if not a:
        watch()
        return 0
    if a == ["--test"]:
        return cmd_test()
    if a == ["--health"]:
        return cmd_health()
    if a == ["--bans"]:
        return cmd_bans()
    if len(a) == 2 and a[0] == "--unban":
        return cmd_unban(a[1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
