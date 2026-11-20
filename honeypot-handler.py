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
}



def host(cfg):
    return cfg.get("HOST_LABEL") or socket.gethostname()

_last_seen = {}
_lock = threading.Lock()


# ---------------------------------------------------------------- helpers
def load_conf():
    cfg = dict(DEFAULTS)
    try:
        with open(CONF_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                cfg[k.strip()] = v
    except FileNotFoundError:
        pass
    return cfg


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
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


FIELD_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def parse_audit(line):
    raw = line.split("\x1d", 1)[0]  # drop ENRICHED part
    d = {}
    for m in FIELD_RE.finditer(raw):
        d[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(2)
    m = re.search(r"msg=audit\(([\d.]+):(\d+)\)", raw)
    if m:
        d["_ts"], d["_serial"] = m.group(1), m.group(2)
    return d


def username(uid):
    if uid in UNSET or uid is None:
        return "unset"
    try:
        return f"{pwd.getpwuid(int(uid)).pw_name} ({uid})"
    except Exception:  # noqa: BLE001
        return str(uid)


# ---------------------------------------------------------------- /proc
def proc_info(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
        comm = s[s.index("(") + 1 : s.rindex(")")]
        ppid = int(s[s.rindex(")") + 2 :].split()[1])
    except Exception:  # noqa: BLE001
        return None
    info = {"pid": int(pid), "ppid": ppid, "comm": comm, "cmdline": ""}
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            info["cmdline"] = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
    except Exception:  # noqa: BLE001
        pass
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            for e in f.read().split(b"\0"):
                if e.startswith(b"SSH_CONNECTION="):
                    info["ssh"] = e.split(b"=", 1)[1].decode(errors="replace")
    except Exception:  # noqa: BLE001
        pass
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            m = re.search(r"(?:docker|libpod)[-/]([0-9a-f]{12,64})", f.read())
            if m:
                info["container"] = m.group(1)[:12]
    except Exception:  # noqa: BLE001
        pass
    return info


def proc_chain(pid):
    out, seen, p = [], set(), int(pid)
    while p > 0 and p not in seen and len(out) < 40:
        seen.add(p)
        i = proc_info(p)
        if not i:
            break
        out.append(i)
        p = i["ppid"]
    return out


# ---------------------------------------------------------------- containment
def ensure_nft(cfg):
    table = cfg["NFT_TABLE"]
    if run(["nft", "list", "table", "inet", table])[0] == 0:
        return
    rules = f"""table inet {table} {{
  set banned4 {{ type ipv4_addr; flags timeout; }}
  set banned6 {{ type ipv6_addr; flags timeout; }}
  chain prerouting {{
    type filter hook prerouting priority raw; policy accept;
    ip saddr @banned4 drop
    ip6 saddr @banned6 drop
  }}
}}
"""
    rc, _, err = run(["nft", "-f", "-"], input=rules)
    if rc != 0:
        log(f"WARN: could not create nft table: {err}")


def ban_ip(ip, cfg, actions):
    n = norm_ip(ip)
    if not n:
        actions.append(f"NOT banned {ip} (not an IP address)")
        return
    ip, addr = n, ipaddress.ip_address(n)
    safe = {norm_ip(x) for x in cfg["BAN_SAFE_IPS"].split()}
    if addr.is_loopback or ip in safe:
        actions.append(f"NOT banned {ip} (loopback / BAN_SAFE_IPS)")
        return
    ensure_nft(cfg)
    s = "banned4" if addr.version == 4 else "banned6"
    timeout = ban_timeout(cfg)
    rc, _, err = run(["nft", "add", "element", "inet", cfg["NFT_TABLE"], s,
                      f"{{ {ip} timeout {timeout} }}"])
    actions.append(f"banned {ip} for {timeout}" if rc == 0 else f"ban {ip} failed: {err}")
    rc, out, _ = run(["ss", "-K", "-H", "dst", ip])
    n = len([l for l in out.splitlines() if l.strip()])
    if n:
        actions.append(f"killed {n} open socket(s) from {ip}")


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


def contain(ev, procs, cfg, actions):
    ses = ev.get("ses", "")
    if ses not in UNSET:
        rc, _, err = run(["loginctl", "terminate-session", ses])
        if rc == 0:
            actions.append(f"terminated login session {ses}")
            return
        actions.append(f"terminate-session {ses} failed: {err or rc}")

    # fallback 1: kill the SSH connection the process belongs to
    for i, p in enumerate(procs):
        if p["comm"].startswith("sshd") and p["ppid"] != 1:
            top = i
            while top + 1 < len(procs) and procs[top + 1]["comm"].startswith("sshd") \
                    and procs[top + 1]["ppid"] != 1:
                top += 1
            for q in procs[: top + 1]:
                kill(q["pid"], signal.SIGKILL, actions, q["comm"])
            return

    # fallback 2: no session (daemon / web shell / container) -> only the
    # process itself and its shell parent; never walk further up (could be a service)
    kill(int(ev["pid"]), signal.SIGKILL, actions, ev.get("comm", "?"))
    parent = proc_info(ev.get("ppid", 0))
    if parent and parent["comm"] in SHELLS:
        kill(parent["pid"], signal.SIGKILL, actions, f"parent shell {parent['comm']}")


# ---------------------------------------------------------------- enrichment
def session_info(ses):
    if ses in UNSET:
        return {}
    rc, out, _ = run(["loginctl", "show-session", ses, "-p", "Name", "-p", "RemoteHost",
                      "-p", "Service", "-p", "TTY", "-p", "Timestamp", "-p", "Leader", "-p", "Type"])
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l) if rc == 0 else {}


def find_remote(procs, sess):
    """Source (ip, port, claimed). Only sources the intruder can't forge are
    trusted: the kernel's view of the sshd process's TCP peer, then logind's
    RemoteHost (set by sshd through PAM). SSH_CONNECTION comes from the process
    environment, which the intruder controls (`export SSH_CONNECTION="<your
    router> 1 2 22"` would get the wrong IP banned), so it is only returned as
    `claimed`, for the report."""
    claimed = next((p["ssh"] for p in procs if p.get("ssh")), "")
    sshds = [p["pid"] for p in procs if p["comm"].startswith("sshd") and p["ppid"] != 1]
    if sshds:
        out = run(["ss", "-tnpH", "state", "established"])[1]
        for pid in sshds:
            for l in out.splitlines():
                if f"pid={pid}," in l:
                    ip, _, port = l.split()[3].rpartition(":")
                    return norm_ip(ip) or ip.strip("[]"), port, claimed
    if sess.get("RemoteHost"):
        return norm_ip(sess["RemoteHost"]) or sess["RemoteHost"], "", claimed
    return "", "", claimed


def ip_details(ip, cfg):
    d = {}
    rc, out, _ = run(["getent", "hosts", ip], timeout=3)
    if rc == 0 and out:
        d["rdns"] = " ".join(out.split()[1:])
    rc, out, _ = run(["ip", "neigh", "show", ip])
    m = re.search(r"lladdr (\S+)", out)
    if m:
        d["mac"] = m.group(1)
    for lf in ("/etc/pihole/dhcp.leases", "/var/lib/misc/dnsmasq.leases"):
        try:
            with open(lf) as f:
                for l in f:
                    p = l.split()
                    if len(p) >= 4 and p[2] == ip:
                        d["dhcp"] = f"{p[3]} (mac {p[1]})"
        except Exception:  # noqa: BLE001
            pass
    try:
        if ipaddress.ip_address(ip).is_global and yes(cfg["IP_LOOKUP"]):
            with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=4) as r:
                j = json.load(r)
            d["geo"] = ", ".join(str(j[k]) for k in ("city", "region", "country", "org") if j.get(k))
    except Exception:  # noqa: BLE001
        pass
    rc, out, _ = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "-3d", "--no-pager",
                      "-o", "cat", "-g", f"(Accepted|Failed).* from {re.escape(ip)} "], timeout=6)
    if out:
        d["sshlog"] = out.splitlines()[-3:]
    return d


def ausearch(serial):
    time.sleep(0.7)  # let auditd flush the rest of the event
    # -ts recent: serial numbers restart at every boot, so without a time bound
    # an older event with the same serial would be picked up
    rc, out, _ = run(["ausearch", "-a", serial, "-ts", "recent", "-i"], timeout=6)
    d = {}
    for key, rx in (("proctitle", r"proctitle=(.*)$"), ("cwd", r"type=CWD .*cwd=(\S+)"),
                    ("syscall", r"syscall=(\S+)"), ("exit", r" exit=(\S+)")):
        m = re.search(rx, out, re.M)
        if m:
            d[key] = m.group(1).strip()
    d["paths"] = [dict(re.findall(r"\b(name|inode|dev)=(\S+)", l))
                  for l in out.splitlines() if l.startswith("type=PATH")]
    d["raw"] = out
    return d


# ---------------------------------------------------------------- notify
def http(url, data, headers, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def notify(cfg, title, body, event=None):
    results = []

    def attempt(name, fn):
        try:
            fn()
            results.append(f"{name}: ok")
        except Exception as e:  # noqa: BLE001
            results.append(f"{name}: FAILED {e}")

    if cfg["NTFY_URL"]:
        h = {"Title": title.encode("ascii", "ignore").decode(), "Priority": "urgent",
             "Tags": "rotating_light,skull"}
        if cfg["NTFY_TOKEN"]:
            h["Authorization"] = f"Bearer {cfg['NTFY_TOKEN']}"
        attempt("ntfy", lambda: http(cfg["NTFY_URL"], body.encode(), h))
    if cfg["TELEGRAM_BOT_TOKEN"] and cfg["TELEGRAM_CHAT_ID"]:
        data = urllib.parse.urlencode({"chat_id": cfg["TELEGRAM_CHAT_ID"],
                                       "text": f"{title}\n\n{body}"[:4000]}).encode()
        attempt("telegram", lambda: http(
            f"https://api.telegram.org/bot{cfg['TELEGRAM_BOT_TOKEN']}/sendMessage", data,
            {"Content-Type": "application/x-www-form-urlencoded"}))
    if cfg["DISCORD_WEBHOOK"]:
        data = json.dumps({"content": f"**{title}**\n```\n{body[:1850]}\n```"}).encode()
        attempt("discord", lambda: http(cfg["DISCORD_WEBHOOK"], data,
                                        {"Content-Type": "application/json"}))
    if cfg["WEBHOOK_URL"]:
        data = json.dumps({"title": title, "message": body, "event": event or {}}).encode()
        attempt("webhook", lambda: http(cfg["WEBHOOK_URL"], data,
                                        {"Content-Type": "application/json"}))
    if not results:
        results.append("no notification channel configured")
    return results


# ---------------------------------------------------------------- main handler
def handle(line):
    cfg = load_conf()
    ev = parse_audit(line)
    pid = ev.get("pid", "0")
    if ev.get("auid") in cfg["IGNORE_AUIDS"].split():
        return
    ses = ev.get("ses", "")
    dkey = ses if ses not in UNSET else f"pid{pid}"
    with _lock:
        now = time.time()
        if now - _last_seen.get(dkey, 0) < seconds(cfg, "DEBOUNCE_SECONDS"):
            return
        _last_seen[dkey] = now

    # snapshot fast, before anything gets killed
    procs = proc_chain(pid) or proc_chain(ev.get("ppid", 0))
    sess = session_info(ses)
    ip, port, claimed = find_remote(procs, sess)
    others = run(["who"])[1]

    actions = []
    if yes(cfg["KILL_SESSION"]):
        contain(ev, procs, cfg, actions)
    if ip and yes(cfg["BAN_IP"]):
        ban_ip(ip, cfg, actions)
    if not actions:
        actions.append("none (monitor only)")

    au = ausearch(ev.get("_serial", "0"))
    ipd = ip_details(ip, cfg) if ip else {}
    when = datetime.fromtimestamp(float(ev.get("_ts", time.time()))).strftime("%Y-%m-%d %H:%M:%S")
    container = next((p["container"] for p in procs if p.get("container")), "")
    opened = which_bait(cfg["BAIT_FILE"].split(), au.get("paths", []), au.get("cwd", ""))

    L = [
        f"File:     {opened}",
        f"When:     {when}",
        f"Result:   {'OPENED' if ev.get('success') == 'yes' else 'attempt DENIED'}"
        f" ({au.get('syscall', ev.get('syscall', '?'))}, exit {au.get('exit', ev.get('exit', '?'))})",
        f"Command:  {au.get('proctitle') or ev.get('comm', '?')}",
        f"Cwd:      {au.get('cwd', '?')}",
        f"Process:  {ev.get('comm', '?')} [{ev.get('exe', '?')}] pid {pid} ppid {ev.get('ppid', '?')}",
        f"User:     uid {username(ev.get('uid'))}, euid {username(ev.get('euid'))}",
        f"Login as: {username(ev.get('auid'))}  (session {ses or '?'}, tty {ev.get('tty', '?')})",
    ]
    if sess:
        L.append(f"Session:  {sess.get('Service', '?')} {sess.get('Type', '')} since {sess.get('Timestamp', '?')}")
    claimed_ip = norm_ip(claimed.split()[0]) if claimed.split() else None
    if ip:
        L.append(f"Source:   {ip}{':' + port if port else ''}")
        for k, label in (("rdns", "rDNS"), ("mac", "MAC"), ("dhcp", "DHCP"), ("geo", "Geo")):
            if ipd.get(k):
                L.append(f"  {label + ':':6}  {ipd[k]}")
        for s in ipd.get("sshlog", []):
            L.append(f"  sshd:   {s}")
    else:
        L.append("Source:   no network session found (local / service / container)")
    if claimed and claimed_ip != ip:
        # forged, or the chain to sshd was broken (setsid, tmux...): report only
        L.append(f"  Env claims SSH_CONNECTION={claimed}  (not trusted, not banned)")
    if container:
        L.append(f"Container: {container}  (docker ps | grep {container})")
    if procs:
        L.append("Tree:     " + " <- ".join(f"{p['comm']}({p['pid']})" for p in procs[:8]))
    L.append("Actions:  " + "; ".join(actions))
    if others:
        L.append("Logged in now:\n  " + others.replace("\n", "\n  "))
    body = "\n".join(L)
    title = f"Honeypot triggered on {host(cfg)}"

    event = {"audit": ev, "session": sess, "ip": ip, "ssh_connection_claimed": claimed,
             "ip_details": ipd, "actions": actions,
             "processes": procs, "container": container}
    results = notify(cfg, title, body, event)

    os.makedirs(cfg["REPORT_DIR"], mode=0o700, exist_ok=True)
    rpt = os.path.join(cfg["REPORT_DIR"], f"{datetime.now():%Y%m%d-%H%M%S}-{pid}.log")
    with open(rpt, "w") as f:
        f.write(f"{title}\n\n{body}\n\nNotify: {results}\n\n--- ausearch ---\n{au.get('raw', '')}\n"
                f"\n--- processes ---\n{json.dumps(procs, indent=2)}\n")
    os.chmod(rpt, 0o600)
    # The journal may be readable by non-root admins (adm/wheel): keep it bland.
    ok = all(": ok" in r for r in results)
    log(f"request {ev.get('_serial', '?')} handled ({'delivered' if ok else 'delivery failed'}): {rpt}")


def which_bait(baits, paths, cwd=""):
    """Which of the (possibly many) bait files was touched, from the PATH records.
    By inode first (a relative name like "config" can't tell ~/.aws/config from
    ~/.kube/config); stat() doesn't open the file, so it can't trigger."""
    ids = {}
    for b in baits:
        try:
            st = os.stat(b)
            ids[(str(st.st_ino), f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}")] = b
        except OSError:
            pass
    for p in paths:
        hit = ids.get((p.get("inode"), p.get("dev")))
        if hit:
            return hit
        # btrfs: stat() reports a per-subvolume dev, audit the superblock's one
        same = [b for (ino, _), b in ids.items() if ino == p.get("inode")]
        if len(same) == 1:
            return same[0]
    for p in paths:  # fall back to names (e.g. the bait was replaced since)
        n = p.get("name", "").strip('"')
        if not n or n == "(null)":
            continue
        full = os.path.normpath(os.path.join(cwd, n)) if cwd and not n.startswith("/") else n
        if full in baits:
            return full
        cands = [b for b in baits if b.endswith("/" + os.path.normpath(n))]
        if len(cands) == 1:
            return cands[0]
        if cands:
            return f"one of: {' '.join(cands)}"
    if len(baits) == 1:
        return baits[0]
    return f"one of: {' '.join(baits)}" if baits else "?"


def follow(path):
    """Yield new lines appended to path, surviving log rotation. Done in-process
    (instead of `tail -F`) so no tell-tale child process shows up in ps."""
    # Binary mode: tell() is then an exact byte offset (in text mode it is an
    # opaque cookie, which could fake a "truncated" log and replay old events).
    f, ino, buf, first = None, None, b"", True
    while True:
        if f is None:
            try:
                f = open(path, "rb")
                ino = os.fstat(f.fileno()).st_ino
                if first:
                    f.seek(0, os.SEEK_END)  # only new events, like tail -n0
                first, buf = False, b""
            except OSError:
                time.sleep(1)
                continue
        chunk = f.readline()
        if chunk:
            buf += chunk
            if buf.endswith(b"\n"):
                yield buf.decode(errors="replace")
                buf = b""
            continue
        time.sleep(0.2)
        try:
            st = os.stat(path)
            if st.st_ino != ino or st.st_size < f.tell():  # rotated or truncated
                f.close()
                f = None
        except OSError:
            pass


def watch():
    cfg = load_conf()
    ensure_nft(cfg)
    needle = f'key="{cfg["AUDIT_KEY"]}"'
    log("agent started")
    for line in follow(cfg["AUDIT_LOG"]):
        if "type=SYSCALL" in line and needle in line:
            threading.Thread(target=_safe_handle, args=(line,), daemon=True).start()


def _safe_handle(line):
    try:
        handle(line)
    except Exception as e:  # noqa: BLE001
        log(f"ERROR: {e!r}")


def main():
    a = sys.argv[1:]
    if not a:
        watch()
    elif a[0] == "--test":
        cfg = load_conf()
        r = notify(cfg, f"Honeypot test from {host(cfg)}",
                   f"Test notification. Bait file: {cfg['BAIT_FILE'] or '?'}\nIf you got this, alerts work.")
        print("\n".join(r))
        sys.exit(0 if all(": ok" in x for x in r) else 1)
    elif a[0] == "--bans":
        cfg = load_conf()
        for s in ("banned4", "banned6"):
            print(run(["nft", "list", "set", "inet", cfg["NFT_TABLE"], s])[1])
    elif a[0] == "--unban" and len(a) == 2:
        cfg = load_conf()
        ip = norm_ip(a[1])
        if not ip:
            sys.exit(f"not an IP address: {a[1]}")
        s = "banned4" if ipaddress.ip_address(ip).version == 4 else "banned6"
        rc, _, err = run(["nft", "delete", "element", "inet", cfg["NFT_TABLE"], s, f"{{ {ip} }}"])
        print("unbanned" if rc == 0 else err)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
