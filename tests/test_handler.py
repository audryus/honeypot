"""Tests for honeypot-handler.py. Nothing here runs a real command, kills a
process, touches nftables or the network: setUp fakes run(), os.kill, http and
urlopen for every test (an unexpected command just fails, like a missing tool)."""
import io
import json
import os
import queue
import signal
import tempfile
import threading
import time
import unittest
from datetime import datetime
from unittest import mock

from load import load

h = load("honeypot-handler.py", "honeypot_handler")

KEY = "pk-auth"
SYSCALL = ('type=SYSCALL msg=audit(1763632800.123:4711): arch=c000003e syscall=257 success=yes '
           'exit=3 a0=ffffff9c ppid=100 pid=200 auid=1000 uid=1000 euid=1000 ses=3 tty=pts0 '
           'comm="cat" exe="/usr/bin/cat" subj=unconfined key="pk-auth"'
           '\x1dARCH=x86_64 SYSCALL=openat AUID="alice" UID="alice"')


class FakeRun:
    """Stand-in for h.run: answers by command prefix, records every call."""

    def __init__(self):
        self.answers = []   # (prefix list, (rc, out, err))
        self.calls = []

    def on(self, prefix, rc=0, out="", err=""):
        self.answers.insert(0, (prefix, (rc, out, err)))

    def __call__(self, cmd, timeout=5, input=None):
        self.calls.append((cmd, input))
        for prefix, answer in self.answers:
            if cmd[: len(prefix)] == prefix:
                return answer
        return 1, "", "not faked"

    def ran(self, *prefix):
        return [c for c, _ in self.calls if c[: len(prefix)] == list(prefix)]


class Base(unittest.TestCase):
    def setUp(self):
        self.run = FakeRun()
        self.kills = []
        self.sent = []
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        patches = [
            mock.patch.object(h, "run", self.run),
            mock.patch.object(h.os, "kill", lambda pid, sig: self.kills.append((pid, sig))),
            mock.patch.object(h, "http", self.fake_http),
            mock.patch.object(h.urllib.request, "urlopen", side_effect=OSError("no network")),
            mock.patch.object(h, "log", lambda *a: None),
            mock.patch.object(h, "_last_seen", {}),
            mock.patch.object(h, "AUSEARCH_DELAY", 0),
            mock.patch.object(h, "RECHECK_AFTER", 0),
            mock.patch.object(h, "POLL", 0.01),
            mock.patch.object(h, "PROC", os.path.join(self.d, "proc")),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def fake_http(self, url, data, headers, timeout=8):
        self.sent.append((url, data, headers))
        return 200

    def cfg(self, **kw):
        c = dict(h.DEFAULTS)
        c["REPORT_DIR"] = os.path.join(self.d, "reports")
        c.update({k: str(v) for k, v in kw.items()})
        return c

    def file(self, name, content=""):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def fake_proc(self, pid, ppid, comm, cmdline="", environ=b"", cgroup=""):
        base = os.path.join(self.d, "proc", str(pid))
        os.makedirs(base, exist_ok=True)
        with open(f"{base}/stat", "w") as f:
            f.write(f"{pid} ({comm}) S {ppid} 1 1 0 -1")
        with open(f"{base}/cmdline", "wb") as f:
            f.write(cmdline.replace(" ", "\0").encode())
        with open(f"{base}/environ", "wb") as f:
            f.write(environ)
        with open(f"{base}/cgroup", "w") as f:
            f.write(cgroup)


# ---------------------------------------------------------------- config
class Config(Base):
    def test_unquote(self):
        self.assertEqual(h.unquote('"a b"'), "a b")
        self.assertEqual(h.unquote("'x'"), "x")
        self.assertEqual(h.unquote("\"mismatch'"), "\"mismatch'")
        self.assertEqual(h.unquote('"'), '"')

    def test_parse_conf_line(self):
        self.assertIsNone(h.parse_conf_line("   "))
        self.assertIsNone(h.parse_conf_line("# KEY=v"))
        self.assertIsNone(h.parse_conf_line("no equals"))
        self.assertEqual(h.parse_conf_line("  K = \"v=1\"  "), ("K", "v=1"))

    def test_parse_conf_over_defaults(self):
        c = h.parse_conf("BAN_IP=no\nBAN_IP=yes\n# NTFY_URL=x\nNEW=1")
        self.assertEqual(c["BAN_IP"], "yes")
        self.assertEqual(c["NTFY_URL"], "")
        self.assertEqual(c["NEW"], "1")
        self.assertEqual(c["AUDIT_KEY"], h.DEFAULTS["AUDIT_KEY"])

    def test_load_conf(self):
        self.assertEqual(h.load_conf(self.file("c", "HOST_LABEL=nas"))["HOST_LABEL"], "nas")
        self.assertEqual(h.load_conf(os.path.join(self.d, "missing")), h.DEFAULTS)

    def test_load_conf_uses_conf_path(self):
        with mock.patch.object(h, "CONF_PATH", self.file("c", "HOST_LABEL=x")):
            self.assertEqual(h.load_conf()["HOST_LABEL"], "x")

    def test_conf_path_line_is_sed_friendly(self):
        # install.sh: sed "s|^CONF_PATH = .*|...|" must hit exactly one line
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "honeypot-handler.py")) as f:
            lines = [l for l in f if l.startswith("CONF_PATH = ")]
        self.assertEqual(len(lines), 1)
        self.assertIn('os.environ.get("HONEYPOT_CONF", ', lines[0])

    def test_runtime_keys_in_example_have_defaults(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "honeypot.conf.example")) as f:
            keys = {kv[0] for kv in map(h.parse_conf_line, f) if kv}
        install_only = {"SERVICE_NAME", "SERVICE_DESCRIPTION", "HANDLER_PATH", "CONF_PATH",
                        "RULES_NAME", "BAIT_CREATED"}
        self.assertEqual(keys - install_only - set(h.DEFAULTS), set())

    def test_host(self):
        self.assertEqual(h.host({"HOST_LABEL": "box"}), "box")
        with mock.patch.object(h.socket, "gethostname", return_value="real"):
            self.assertEqual(h.host({"HOST_LABEL": ""}), "real")

    def test_baits(self):
        self.assertEqual(h.baits({"BAIT_FILE": " /a  /b "}), ["/a", "/b"])

    def test_yes(self):
        for v in ("1", "yes", "TRUE", " on "):
            self.assertTrue(h.yes(v))
        for v in ("0", "no", "", "nope"):
            self.assertFalse(h.yes(v))

    def test_seconds(self):
        self.assertEqual(h.seconds({"DEBOUNCE_SECONDS": "5"}, "DEBOUNCE_SECONDS"), 5)
        self.assertEqual(h.seconds({"DEBOUNCE_SECONDS": "5s"}, "DEBOUNCE_SECONDS"), 30)

    def test_ban_timeout(self):
        self.assertEqual(h.ban_timeout({"BAN_TIMEOUT": "1d12h"}), "1d12h")
        self.assertEqual(h.ban_timeout({"BAN_TIMEOUT": "forever"}), "1h")


# ---------------------------------------------------------------- helpers
class Helpers(Base):
    def test_norm_ip(self):
        self.assertEqual(h.norm_ip("[::ffff:1.2.3.4]"), "1.2.3.4")
        self.assertEqual(h.norm_ip(" 2001:DB8::1 "), "2001:db8::1")
        self.assertIsNone(h.norm_ip("example.com"))
        self.assertIsNone(h.norm_ip(None))

    def test_count_lines(self):
        self.assertEqual(h.count_lines("a\n\n  \nb\n"), 2)

    def test_parse_kv(self):
        self.assertEqual(h.parse_kv("A=1\nB=x=y\njunk"), {"A": "1", "B": "x=y"})

    def test_all_ok_any_ok(self):
        self.assertTrue(h.all_ok(["ntfy: ok", "discord: ok"]))
        self.assertFalse(h.all_ok(["ntfy: ok", "discord: FAILED x"]))
        self.assertFalse(h.all_ok([]))
        self.assertTrue(h.any_ok(["ntfy: ok", "discord: FAILED x"]))
        self.assertFalse(h.any_ok(["no notification channel configured"]))

    def test_read_bytes(self):
        self.assertEqual(h.read_bytes(self.file("f", "x")), b"x")
        self.assertIsNone(h.read_bytes(os.path.join(self.d, "missing")))

    def test_username(self):
        self.assertEqual(h.username("4294967295"), "unset")
        self.assertEqual(h.username(None), "unset")
        self.assertEqual(h.username("0"), "root (0)")
        self.assertEqual(h.username("987654"), "987654")


class RealRun(unittest.TestCase):
    """The real run(), with harmless commands."""

    def test_output_and_errors(self):
        real = h.run  # not a Base test: nothing is faked here
        self.assertNotIsInstance(real, FakeRun)
        self.assertEqual(real(["sh", "-c", "echo hi; echo err >&2; exit 3"]), (3, "hi", "err"))
        self.assertEqual(real(["cat"], input="in")[1], "in")
        rc, _, err = real(["/nonexistent/command"])
        self.assertEqual(rc, 1)
        self.assertTrue(err)


# ---------------------------------------------------------------- audit records
class Audit(Base):
    def test_parse_audit(self):
        ev = h.parse_audit(SYSCALL)
        self.assertEqual(ev["pid"], "200")
        self.assertEqual(ev["comm"], "cat")
        self.assertEqual(ev["key"], KEY)
        self.assertEqual((ev["_ts"], ev["_serial"]), ("1763632800.123", "4711"))
        self.assertNotIn("AUID", ev)  # the enriched part is dropped

    def test_audit_fields_quoted_with_spaces(self):
        self.assertEqual(h.audit_fields('a=1 b="x y" c=(null)'), {"a": "1", "b": "x y", "c": "(null)"})

    def test_parse_audit_without_stamp(self):
        self.assertNotIn("_serial", h.parse_audit("pid=1"))

    def test_is_trigger(self):
        needle = f'key="{KEY}"'
        self.assertTrue(h.is_trigger(SYSCALL, needle))
        self.assertFalse(h.is_trigger(SYSCALL.replace("SYSCALL", "PATH", 1), needle))
        self.assertFalse(h.is_trigger(SYSCALL, 'key="other"'))


# ---------------------------------------------------------------- /proc
class Proc(Base):
    def test_parse_stat_with_odd_comm(self):
        self.assertEqual(h.parse_stat("42 (my (evil) prog) S 7 1 1"), ("my (evil) prog", 7))

    def test_parse_cmdline(self):
        self.assertEqual(h.parse_cmdline(b"cat\0/x\0"), "cat /x")

    def test_ssh_from_environ(self):
        env = b"A=1\0SSH_CONNECTION=1.2.3.4 5 6.7.8.9 22\0B=2"
        self.assertEqual(h.ssh_from_environ(env), "1.2.3.4 5 6.7.8.9 22")
        self.assertEqual(h.ssh_from_environ(b"A=1"), "")

    def test_container_from_cgroup(self):
        cid = "a" * 64
        self.assertEqual(h.container_from_cgroup(f"0::/system.slice/docker-{cid}.scope"), "a" * 12)
        self.assertEqual(h.container_from_cgroup(f"0::/libpod/{cid}"), "a" * 12)
        self.assertEqual(h.container_from_cgroup("0::/user.slice"), "")

    def test_proc_info(self):
        self.fake_proc(200, 100, "cat", "cat /bait", b"SSH_CONNECTION=1.2.3.4 1 2 22\0",
                       "0::/docker/" + "b" * 64)
        self.assertEqual(h.proc_info(200), {"pid": 200, "ppid": 100, "comm": "cat",
                                            "cmdline": "cat /bait", "ssh": "1.2.3.4 1 2 22",
                                            "container": "b" * 12})

    def test_proc_info_missing_or_garbled(self):
        self.assertIsNone(h.proc_info(999))
        self.file("proc/5/stat", "garbage")
        self.assertIsNone(h.proc_info(5))

    def test_proc_chain(self):
        self.fake_proc(200, 100, "cat")
        self.fake_proc(100, 50, "bash")
        self.fake_proc(50, 1, "sshd")
        self.assertEqual([p["pid"] for p in h.proc_chain("200")], [200, 100, 50])

    def test_proc_chain_loop_and_bad_pid(self):
        self.fake_proc(10, 11, "a")
        self.fake_proc(11, 10, "b")
        self.assertEqual([p["pid"] for p in h.proc_chain(10)], [10, 11])
        self.assertEqual(h.proc_chain("x"), [])
        self.assertEqual(h.proc_chain(None), [])

    def test_sshd_helpers(self):
        procs = [{"pid": 3, "ppid": 2, "comm": "bash"},
                 {"pid": 2, "ppid": 1, "comm": "sshd"},
                 {"pid": 9, "ppid": 8, "comm": "sshd-session"}]
        self.assertFalse(h.is_conn_sshd(procs[1]))  # the listener
        self.assertEqual(h.sshd_pids(procs), [9])

    def test_first_container(self):
        self.assertEqual(h.first_container([{"pid": 1}, {"container": "c1"}, {"container": "c2"}]), "c1")
        self.assertEqual(h.first_container([]), "")


# ---------------------------------------------------------------- containment
class Containment(Base):
    def test_nft_ruleset(self):
        r = h.nft_ruleset("raw_filter")
        self.assertIn("table inet raw_filter {", r)
        self.assertIn("hook prerouting priority raw", r)
        self.assertIn("ip saddr @banned4 drop", r)
        self.assertIn("ip6 saddr @banned6 drop", r)

    def test_ensure_nft_exists(self):
        self.run.on(["nft", "list"], 0)
        h.ensure_nft(self.cfg())
        self.assertEqual(self.run.ran("nft", "-f"), [])

    def test_ensure_nft_creates(self):
        self.run.on(["nft", "list"], 1)
        self.run.on(["nft", "-f"], 0)
        h.ensure_nft(self.cfg(NFT_TABLE="t1"))
        self.assertIn("table inet t1", self.run.calls[-1][1])

    def test_ip_set(self):
        self.assertEqual(h.ip_set("1.2.3.4"), "banned4")
        self.assertEqual(h.ip_set("::1"), "banned6")

    def test_ban_target(self):
        c = self.cfg(BAN_SAFE_IPS="10.0.0.1 [::ffff:10.0.0.2]")
        self.assertEqual(h.ban_target("::ffff:8.8.8.8", c), ("8.8.8.8", None))
        self.assertEqual(h.ban_target("10.0.0.2", c)[1], "loopback / BAN_SAFE_IPS")
        self.assertEqual(h.ban_target("127.0.0.1", c)[1], "loopback / BAN_SAFE_IPS")
        self.assertEqual(h.ban_target("::1", c)[1], "loopback / BAN_SAFE_IPS")
        self.assertEqual(h.ban_target("evil.host", c), ("evil.host", "not an IP address"))

    def test_ban_ip(self):
        self.run.on(["nft"], 0)
        self.run.on(["ss", "-K"], 0, "s1\ns2")
        actions = []
        h.ban_ip("[2001:db8::5]", self.cfg(BAN_TIMEOUT="2h"), actions)
        add = self.run.ran("nft", "add")[0]
        self.assertEqual(add[-2:], ["banned6", "{ 2001:db8::5 timeout 2h }"])
        self.assertEqual(actions, ["banned 2001:db8::5 for 2h", "killed 2 open socket(s) from 2001:db8::5"])

    def test_ban_ip_failure_reported(self):
        self.run.on(["nft", "list"], 0)
        self.run.on(["nft", "add"], 1, err="no table")
        actions = []
        h.ban_ip("8.8.8.8", self.cfg(), actions)
        self.assertEqual(actions, ["ban 8.8.8.8 failed: no table"])

    def test_ban_ip_refused(self):
        actions = []
        h.ban_ip("127.0.0.1", self.cfg(), actions)
        self.assertEqual(actions, ["NOT banned 127.0.0.1 (loopback / BAN_SAFE_IPS)"])
        self.assertEqual(self.run.calls, [])

    def test_kill(self):
        actions = []
        h.kill(1, 9, actions, "init")
        h.kill(os.getpid(), 9, actions, "me")
        self.assertEqual(self.kills, [])
        h.kill(321, 9, actions, "cat")
        self.assertEqual(self.kills, [(321, 9)])
        self.assertEqual(actions, ["killed pid 321 (cat)"])

    def test_kill_gone_or_denied(self):
        actions = []
        with mock.patch.object(h.os, "kill", side_effect=ProcessLookupError):
            h.kill(5, 9, actions, "x")
        with mock.patch.object(h.os, "kill", side_effect=PermissionError("no")):
            h.kill(6, 9, actions, "y")
        self.assertEqual(actions, ["kill 6 failed: no"])

    def test_terminate_session(self):
        actions = []
        self.assertFalse(h.terminate_session("4294967295", actions))
        self.run.on(["loginctl", "terminate-session", "3"], 0)
        self.assertTrue(h.terminate_session("3", actions))
        self.assertFalse(h.terminate_session("4", actions))
        self.assertEqual(actions, ["terminated login session 3", "terminate-session 4 failed: not faked"])

    def test_sshd_connection(self):
        procs = [{"pid": 5, "ppid": 4, "comm": "cat"}, {"pid": 4, "ppid": 3, "comm": "bash"},
                 {"pid": 3, "ppid": 2, "comm": "sshd-session"}, {"pid": 2, "ppid": 1, "comm": "sshd"}]
        self.assertEqual([p["pid"] for p in h.sshd_connection(procs)], [5, 4, 3])
        self.assertEqual(h.sshd_connection(procs[:2]), [])

    def test_sshd_connection_privsep_pair(self):
        procs = [{"pid": 5, "ppid": 4, "comm": "bash"}, {"pid": 4, "ppid": 3, "comm": "sshd"},
                 {"pid": 3, "ppid": 2, "comm": "sshd"}, {"pid": 2, "ppid": 1, "comm": "sshd"}]
        self.assertEqual([p["pid"] for p in h.sshd_connection(procs)], [5, 4, 3])

    def test_kill_process_and_shell(self):
        self.fake_proc(100, 50, "bash")
        actions = []
        h.kill_process_and_shell({"pid": "200", "ppid": "100", "comm": "cat"}, actions)
        self.assertEqual(self.kills, [(200, signal.SIGKILL), (100, signal.SIGKILL)])

    def test_kill_process_spares_non_shell_parent(self):
        self.fake_proc(100, 1, "nginx")
        h.kill_process_and_shell({"pid": "200", "ppid": "100", "comm": "cat"}, [])
        self.assertEqual(self.kills, [(200, signal.SIGKILL)])

    def test_contain_prefers_session(self):
        self.run.on(["loginctl", "terminate-session"], 0)
        actions = []
        h.contain({"ses": "3", "pid": "200"}, [], actions)
        self.assertEqual(self.kills, [])
        self.assertEqual(actions, ["terminated login session 3"])

    def test_contain_falls_back_to_sshd(self):
        procs = [{"pid": 5, "ppid": 4, "comm": "cat"}, {"pid": 4, "ppid": 2, "comm": "sshd"}]
        h.contain({"ses": "3", "pid": "5"}, procs, [])
        self.assertEqual([p for p, _ in self.kills], [5, 4])

    def test_contain_last_resort(self):
        h.contain({"ses": "-1", "pid": "5", "ppid": "0"}, [], [])
        self.assertEqual([p for p, _ in self.kills], [5])


# ---------------------------------------------------------------- source
class Source(Base):
    SS = ("0 0 10.0.0.5:22 203.0.113.9:51234 users:((\"sshd-session\",pid=300,fd=4))\n"
          "0 0 [::ffff:10.0.0.5]:22 [::ffff:198.51.100.7]:4000 users:((\"sshd\",pid=301,fd=4))\n"
          "0 0 [2001:db8::1]:22 [2001:db8::99]:5555 users:((\"sshd\",pid=302,fd=4))")

    def test_session_info(self):
        self.assertEqual(h.session_info("unset"), {})
        self.run.on(["loginctl", "show-session", "3"], 0, "Name=alice\nRemoteHost=1.2.3.4")
        self.assertEqual(h.session_info("3"), {"Name": "alice", "RemoteHost": "1.2.3.4"})
        self.assertEqual(h.session_info("4"), {})

    def test_ss_peer(self):
        self.assertEqual(h.ss_peer(self.SS, 300), ("203.0.113.9", "51234"))
        self.assertEqual(h.ss_peer(self.SS, 301), ("198.51.100.7", "4000"))
        self.assertEqual(h.ss_peer(self.SS, 302), ("2001:db8::99", "5555"))
        self.assertIsNone(h.ss_peer(self.SS, 30))  # pid=30 must not match pid=300

    def test_claimed_connection(self):
        self.assertEqual(h.claimed_connection([{}, {"ssh": "a"}, {"ssh": "b"}]), "a")

    def test_find_remote_trusts_the_socket_not_the_env(self):
        self.run.on(["ss", "-tnpH"], 0, self.SS)
        procs = [{"pid": 5, "ppid": 300, "comm": "bash", "ssh": "192.168.1.1 1 2 22"},
                 {"pid": 300, "ppid": 2, "comm": "sshd-session"}]
        self.assertEqual(h.find_remote(procs, {"RemoteHost": "9.9.9.9"}),
                         ("203.0.113.9", "51234", "192.168.1.1 1 2 22"))

    def test_find_remote_falls_back_to_logind(self):
        self.assertEqual(h.find_remote([], {"RemoteHost": "::ffff:9.9.9.9"}), ("9.9.9.9", "", ""))

    def test_find_remote_never_uses_the_env(self):
        procs = [{"pid": 5, "ppid": 1, "comm": "bash", "ssh": "192.168.1.1 1 2 22"}]
        self.assertEqual(h.find_remote(procs, {}), ("", "", "192.168.1.1 1 2 22"))


# ---------------------------------------------------------------- enrichment
class Enrichment(Base):
    def test_rdns(self):
        self.run.on(["getent", "hosts"], 0, "1.2.3.4  host.example a.example")
        self.assertEqual(h.rdns("1.2.3.4"), "host.example a.example")
        self.run.on(["getent", "hosts"], 2)
        self.assertEqual(h.rdns("1.2.3.4"), "")

    def test_mac(self):
        self.assertEqual(h.parse_lladdr("10.0.0.9 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"),
                         "aa:bb:cc:dd:ee:ff")
        self.assertEqual(h.parse_lladdr("10.0.0.9 dev eth0 FAILED"), "")
        self.run.on(["ip", "neigh"], 0, "x lladdr 11:22:33:44:55:66 STALE")
        self.assertEqual(h.mac_of("10.0.0.9"), "11:22:33:44:55:66")

    def test_dhcp_lease(self):
        lines = ["1700000000 aa:aa 10.0.0.9 laptop 01:aa", "1700000001 bb:bb 10.0.0.10 phone *",
                 "short line", "1700000002 cc:cc 10.0.0.9 laptop2 *"]
        self.assertEqual(h.dhcp_lease(lines, "10.0.0.9"), "laptop2 (mac cc:cc)")
        self.assertEqual(h.dhcp_lease(lines, "10.0.0.1"), "")

    def test_dhcp_of(self):
        f1 = self.file("l1", "1 aa:aa 10.0.0.9 one *\n")
        f2 = self.file("l2", "1 bb:bb 10.0.0.8 two *\n")
        with mock.patch.object(h, "LEASE_FILES", (f1, f2, os.path.join(self.d, "missing"))):
            self.assertEqual(h.dhcp_of("10.0.0.9"), "one (mac aa:aa)")

    def test_format_geo(self):
        self.assertEqual(h.format_geo({"city": "Paris", "country": "FR", "org": "", "x": 1}), "Paris, FR")

    def test_geo_of(self):
        self.assertEqual(h.geo_of("10.0.0.1", self.cfg()), "")       # private: no lookup
        self.assertEqual(h.geo_of("8.8.8.8", self.cfg(IP_LOOKUP="no")), "")
        resp = mock.MagicMock()
        resp.__enter__.return_value = io.BytesIO(b'{"city": "Mountain View", "country": "US"}')
        with mock.patch.object(h.urllib.request, "urlopen", return_value=resp) as u:
            self.assertEqual(h.geo_of("8.8.8.8", self.cfg()), "Mountain View, US")
        self.assertIn("ipinfo.io/8.8.8.8/json", u.call_args[0][0])
        self.assertEqual(h.geo_of("8.8.8.8", self.cfg()), "")        # network down

    def test_sshd_log(self):
        self.run.on(["journalctl"], 0, "a\nb\nc\nd")
        self.assertEqual(h.sshd_log("1.2.3.4"), ["b", "c", "d"])
        self.assertIn(r"from 1\.2\.3\.4 ", self.run.calls[-1][0][-1])

    def test_ip_details_drops_empty(self):
        self.run.on(["getent"], 0, "1.2.3.4 h.example")
        self.assertEqual(h.ip_details("1.2.3.4", self.cfg(IP_LOOKUP="no")), {"rdns": "h.example"})

    AUS = ("----\n"
           "type=PROCTITLE msg=audit(11/20/2026 10:00:00.123:4711) : proctitle=cat /home/a/.aws/config\n"
           "type=PATH msg=audit(x) : item=0 name=/home/a/.aws/config inode=1234 dev=fd:01 mode=file\n"
           "type=PATH msg=audit(x) : item=1 name=(null) inode=99 dev=fd:01\n"
           "type=CWD msg=audit(x) : cwd=/home/a\n"
           "type=SYSCALL msg=audit(x) : arch=x86_64 syscall=openat success=yes exit=3 pid=200")

    def test_parse_ausearch(self):
        d = h.parse_ausearch(self.AUS)
        self.assertEqual(d["proctitle"], "cat /home/a/.aws/config")
        self.assertEqual((d["cwd"], d["syscall"], d["exit"]), ("/home/a", "openat", "3"))
        self.assertEqual(d["paths"][0], {"name": "/home/a/.aws/config", "inode": "1234", "dev": "fd:01"})
        self.assertEqual(len(d["paths"]), 2)
        self.assertEqual(d["raw"], self.AUS)

    def test_parse_ausearch_empty(self):
        self.assertEqual(h.parse_ausearch(""), {"paths": [], "raw": ""})

    def test_ausearch(self):
        self.run.on(["ausearch"], 0, self.AUS)
        self.assertEqual(h.ausearch("4711")["cwd"], "/home/a")
        self.assertEqual(self.run.calls[-1][0], ["ausearch", "--input-logs", "-a", "4711", "-ts", "recent", "-i"])


# ---------------------------------------------------------------- which bait
class WhichBait(Base):
    def setUp(self):
        super().setUp()
        self.aws = self.file("home/.aws/config")
        self.kube = self.file("home/.kube/config")
        self.all = [self.aws, self.kube]

    def rec(self, path, **kw):
        st = os.stat(path)
        return {"inode": str(st.st_ino), "dev": h.dev_str(st.st_dev), **kw}

    def test_dev_str(self):
        self.assertEqual(h.dev_str(os.makedev(0xfd, 1)), "fd:01")
        self.assertEqual(h.dev_str(os.makedev(8, 17)), "08:11")

    def test_bait_ids(self):
        ids = h.bait_ids(self.all + [os.path.join(self.d, "gone")])
        self.assertEqual(sorted(ids.values()), sorted(self.all))

    def test_by_inode(self):
        self.assertEqual(h.which_bait(self.all, [self.rec(self.kube, name="config")]), self.kube)

    def test_by_inode_with_other_dev(self):  # btrfs subvolume
        r = self.rec(self.kube)
        r["dev"] = "00:99"
        self.assertEqual(h.match_inode(h.bait_ids(self.all), [r]), self.kube)

    def test_by_relative_name_and_cwd(self):
        recs = [{"name": "config", "inode": "1", "dev": "00:00"}]
        self.assertEqual(h.which_bait(self.all, recs, os.path.dirname(self.aws)), self.aws)

    def test_by_absolute_name(self):
        self.assertEqual(h.bait_by_name(self.all, self.aws, ""), self.aws)

    def test_ambiguous_name(self):
        self.assertEqual(h.bait_by_name(self.all, "config", ""), f"one of: {self.aws} {self.kube}")

    def test_suffix_name(self):
        self.assertEqual(h.bait_by_name(self.all, ".kube/config", ""), self.kube)

    def test_null_and_empty_names(self):
        self.assertIsNone(h.bait_by_name(self.all, "(null)", ""))
        self.assertIsNone(h.bait_by_name(self.all, "", ""))
        self.assertIsNone(h.match_name(self.all, [{"name": '"(null)"'}], ""))

    def test_quoted_name(self):
        self.assertEqual(h.match_name(self.all, [{"name": f'"{self.aws}"'}], ""), self.aws)

    def test_default(self):
        self.assertEqual(h.default_bait([self.aws]), self.aws)
        self.assertEqual(h.default_bait(self.all), f"one of: {self.aws} {self.kube}")
        self.assertEqual(h.default_bait([]), "?")
        self.assertEqual(h.which_bait([self.aws], []), self.aws)


# ---------------------------------------------------------------- notify
class Notify(Base):
    def test_ntfy_request(self):
        url, data, hd = h.ntfy_request(self.cfg(NTFY_URL="https://n/t", NTFY_TOKEN="tk"),
                                       "Hé title", "body", "low", "x")
        self.assertEqual((url, data), ("https://n/t", b"body"))
        self.assertEqual(hd, {"Title": "H title", "Priority": "low", "Tags": "x",
                              "Authorization": "Bearer tk"})

    def test_ntfy_without_token(self):
        self.assertNotIn("Authorization", h.ntfy_request(self.cfg(), "t", "b", "low", "x")[2])

    def test_telegram_request(self):
        url, data, _ = h.telegram_request(self.cfg(TELEGRAM_BOT_TOKEN="123:ab", TELEGRAM_CHAT_ID="42"),
                                          "T", "x" * 5000)
        self.assertEqual(url, "https://api.telegram.org/bot123:ab/sendMessage")
        q = h.urllib.parse.parse_qs(data.decode())
        self.assertEqual(q["chat_id"], ["42"])
        self.assertEqual(len(q["text"][0]), 4000)

    def test_discord_request(self):
        _, data, _ = h.discord_request(self.cfg(DISCORD_WEBHOOK="https://d"), "T", "y" * 3000)
        content = json.loads(data)["content"]
        self.assertTrue(content.startswith("**T**\n```\n"))
        self.assertLessEqual(len(content), 2000)  # Discord's limit

    def test_webhook_request(self):
        _, data, _ = h.webhook_request(self.cfg(WEBHOOK_URL="https://w"), "T", "B", None)
        self.assertEqual(json.loads(data), {"title": "T", "message": "B", "event": {}})

    def test_channels(self):
        self.assertEqual(h.channels(self.cfg(), "t", "b", None, "p", "x"), [])
        c = self.cfg(NTFY_URL="n", TELEGRAM_BOT_TOKEN="t", DISCORD_WEBHOOK="d", WEBHOOK_URL="w")
        self.assertEqual([x[0] for x in h.channels(c, "t", "b", None, "p", "x")],
                         ["ntfy", "discord", "webhook"])  # telegram needs a chat id too

    def test_send(self):
        self.assertEqual(h.send("ntfy", "u", b"", {}), "ntfy: ok")
        with mock.patch.object(h, "http", side_effect=OSError("refused")):
            self.assertEqual(h.send("ntfy", "u", b"", {}), "ntfy: FAILED refused")

    def test_notify(self):
        self.assertEqual(h.notify(self.cfg(), "t", "b"), ["no notification channel configured"])
        r = h.notify(self.cfg(NTFY_URL="https://n", WEBHOOK_URL="https://w"), "t", "b")
        self.assertEqual(r, ["ntfy: ok", "webhook: ok"])
        self.assertEqual(self.sent[0][2]["Priority"], "urgent")


# ---------------------------------------------------------------- health
RULES_DASH = ("-w {b} -p wa -k pk-auth\n"
              "-a always,exit -F arch=b64 -S open,openat,openat2 -F path={b} -k pk-auth\n")
RULES_FIELDS = ("-a always,exit -F arch=b64 -S all -F path={b} -F perm=wa -F key=pk-auth\n"
                "-a always,exit -F arch=b64 -S openat -F path={b} -F key=pk-auth\n")


class Health(Base):
    def setUp(self):
        super().setUp()
        self.bait = self.file("bait")
        self.log = self.file("audit.log")

    def healthy(self, rules=RULES_DASH):
        self.run.on(["auditctl", "-s"], 0, "enabled 1\nfailure 1\npid 812")
        self.run.on(["auditctl", "-l"], 0, rules.format(b=self.bait))

    def test_bait_problems(self):
        self.assertEqual(h.bait_problems([]), ["no bait files configured (BAIT_FILE is empty)"])
        gone = os.path.join(self.d, "gone")
        self.assertEqual(h.bait_problems([self.bait, gone]), [f"bait file is gone: {gone}"])

    def test_bait_problems_dangling_symlink_counts_as_there(self):
        link = os.path.join(self.d, "link")
        os.symlink(os.path.join(self.d, "nowhere"), link)
        self.assertEqual(h.bait_problems([link]), [])

    def test_parse_audit_status(self):
        self.assertEqual(h.parse_audit_status("enabled 1\n lonely\npid 812\nbacklog_wait_time 60000"),
                         {"enabled": "1", "pid": "812", "backlog_wait_time": "60000"})

    def test_status_problems(self):
        self.assertEqual(h.status_problems({"enabled": "1", "pid": "5"}), [])
        self.assertEqual(len(h.status_problems({"enabled": "0", "pid": "0"})), 2)
        self.assertEqual(len(h.status_problems({})), 1)  # no pid line = no auditd

    def test_auditd_problems_command_fails(self):
        self.assertEqual(h.auditd_problems(), ["auditctl -s failed: not faked"])

    def test_key_rules(self):
        out = "-w /a -p wa -k pk-auth\n-w /b -p wa -k pk-auth2\n-a x -F key=pk-auth"
        self.assertEqual(h.key_rules(out, KEY), ["-w /a -p wa -k pk-auth", "-a x -F key=pk-auth"])

    def test_rules_for_no_prefix_collision(self):
        rules = [f"-w {self.bait}2 -p wa -k pk-auth"]
        self.assertEqual(h.rules_for(rules, self.bait), [])

    def test_rule_problems_both_formats(self):
        for fmt in (RULES_DASH, RULES_FIELDS):
            self.assertEqual(h.rule_problems(fmt.format(b=self.bait), KEY, [self.bait]), [], fmt)

    def test_rule_problems_missing(self):
        only_watch = f"-w {self.bait} -p wa -k pk-auth\n"
        self.assertEqual(h.rule_problems(only_watch, KEY, [self.bait]),
                         [f"audit rule for opening {self.bait} is not loaded"])
        self.assertEqual(len(h.rule_problems("", KEY, [self.bait])), 2)
        other_key = RULES_DASH.format(b=self.bait).replace("pk-auth", "other")
        self.assertEqual(len(h.rule_problems(other_key, KEY, [self.bait])), 2)

    def test_log_problems(self):
        self.assertEqual(h.log_problems(self.log), [])
        self.assertEqual(len(h.log_problems(self.log + "x")), 1)

    def test_watcher_problems(self):
        self.assertEqual(h.watcher_problems(1000, 900), [])
        self.assertEqual(h.watcher_problems(1000, 1000 - h.WATCHER_STALE - 1),
                         ["the audit log watcher is stuck"])

    def test_health_ok(self):
        self.healthy()
        self.assertEqual(h.health(self.cfg(BAIT_FILE=self.bait, AUDIT_LOG=self.log)), [])

    def test_health_stuck_watcher_only_when_asked(self):
        self.healthy()
        c = self.cfg(BAIT_FILE=self.bait, AUDIT_LOG=self.log)
        class Frozen(list):  # follow() threads left by the Follow tests write _tick[0]
            def __setitem__(self, i, v):
                pass
        with mock.patch.object(h, "_tick", Frozen([0])):
            self.assertEqual(h.health(c), [])
            self.assertEqual(h.health(c, check_watcher=True), ["the audit log watcher is stuck"])

    def test_health_everything_wrong(self):
        p = h.health(self.cfg(BAIT_FILE=self.bait + "x", AUDIT_LOG=self.log + "x"))
        self.assertEqual(len(p), 4)  # bait, auditctl -s, auditctl -l, log


# ---------------------------------------------------------------- liveness
class Liveness(Base):
    def test_state_roundtrip(self):
        c = self.cfg()
        self.assertEqual(h.read_state(c), {})
        h.write_state(c, {"heartbeat": 5})
        self.assertEqual(h.read_state(c), {"heartbeat": 5})
        st = os.stat(os.path.join(c["REPORT_DIR"], h.STATE_FILE))
        self.assertEqual(st.st_mode & 0o777, 0o600)
        self.assertFalse(os.path.exists(os.path.join(c["REPORT_DIR"], h.STATE_FILE + ".tmp")))

    def test_read_state_corrupt(self):
        c = self.cfg()
        self.file("reports/state", "{not json")
        self.assertEqual(h.read_state(c), {})

    def test_reports_since(self):
        c = self.cfg()
        old = self.file("reports/20250101-000000-1.log")
        self.file("reports/20250101-000000-2.log")
        self.file("reports/notes.txt")
        os.utime(old, (100, 100))
        self.assertEqual(h.reports_since(c, 1000), 1)
        self.assertEqual(h.reports_since(self.cfg(REPORT_DIR="/nonexistent"), 0), 0)

    def test_heartbeat_due(self):
        self.assertIsNone(h.heartbeat_due({}, 100, 0))
        self.assertEqual(h.heartbeat_due({}, 100, 7), "start")
        self.assertEqual(h.heartbeat_due({"heartbeat": "garbage"}, 100, 7), "start")
        self.assertIsNone(h.heartbeat_due({"heartbeat": 100}, 100 + 7 * 86400 - 1, 7))
        self.assertEqual(h.heartbeat_due({"heartbeat": 100}, 100 + 7 * 86400, 7), "send")

    def test_heartbeat_body(self):
        b = h.heartbeat_body(self.cfg(HOST_LABEL="nas", BAIT_FILE="/a /b"), ["x", "y"], 3, 7.0)
        self.assertIn("Still watching on nas.", b)
        self.assertIn("Bait files: 2", b)
        self.assertIn("PROBLEMS: x; y", b)
        self.assertIn("Alerts since the last heartbeat: 3", b)
        self.assertIn("Next heartbeat in 7 day(s).", b)

    def test_heartbeat_start_records_without_sending(self):
        c = self.cfg(NTFY_URL="https://n")
        h.heartbeat(c, [], 1000)
        self.assertEqual(self.sent, [])
        self.assertEqual(h.read_state(c), {"heartbeat": 1000})

    def test_heartbeat_send(self):
        c = self.cfg(NTFY_URL="https://n", HEARTBEAT_DAYS="1")
        h.write_state(c, {"heartbeat": 0})
        h.heartbeat(c, [], 86400)
        self.assertEqual(self.sent[0][2]["Priority"], "low")
        self.assertEqual(h.read_state(c), {"heartbeat": 86400})

    def test_heartbeat_retried_when_undelivered(self):
        c = self.cfg(NTFY_URL="https://n", HEARTBEAT_DAYS="1")
        h.write_state(c, {"heartbeat": 0})
        with mock.patch.object(h, "http", side_effect=OSError):
            h.heartbeat(c, [], 86400)
        self.assertEqual(h.read_state(c), {"heartbeat": 0})

    def test_heartbeat_off(self):
        c = self.cfg(HEARTBEAT_DAYS="0")
        h.heartbeat(c, [], 1000)
        self.assertEqual(h.read_state(c), {})

    def test_report_change(self):
        c = self.cfg(NTFY_URL="https://n")
        reported = h.report_change(c, ["a"], set())
        self.assertEqual(reported, {"a"})
        self.assertEqual(self.sent[-1][2]["Title"], f"Honeypot PROBLEM on {h.host(c)}")
        h.report_change(c, ["a"], reported)           # same problem: no repeat
        self.assertEqual(len(self.sent), 1)
        h.report_change(c, ["a", "b"], reported)      # a new one: alert
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(h.report_change(c, [], {"a", "b"}), set())
        self.assertEqual(self.sent[-1][2]["Title"], f"Honeypot recovered on {h.host(c)}")
        h.report_change(c, [], set())                 # healthy, still healthy: silence
        self.assertEqual(len(self.sent), 3)

    def test_checked_problems_needs_a_second_look(self):
        answers = iter([["blip"], []])
        with mock.patch.object(h, "health", lambda cfg, check_watcher: next(answers)):
            self.assertEqual(h.checked_problems()[1], [])

    def test_checked_problems_persistent(self):
        with mock.patch.object(h, "health", lambda cfg, check_watcher: ["down"]):
            self.assertEqual(h.checked_problems()[1], ["down"])

    def test_ping(self):
        h.ping("https://hc")  # urlopen raises: swallowed
        with mock.patch.object(h.urllib.request, "urlopen") as u:
            h.ping("https://hc")
        u.assert_called_once()

    def test_liveness_tick_pings_only_when_healthy(self):
        conf = self.file("c", f"HEARTBEAT_URL=https://hc\nREPORT_DIR={self.d}/r\nHEARTBEAT_DAYS=0")
        with mock.patch.object(h, "CONF_PATH", conf), \
                mock.patch.object(h, "ping") as ping:
            with mock.patch.object(h, "health", lambda cfg, check_watcher: []):
                self.assertEqual(h.liveness_tick(set()), set())
            with mock.patch.object(h, "health", lambda cfg, check_watcher: ["x"]):
                self.assertEqual(h.liveness_tick(set()), {"x"})
        ping.assert_called_once_with("https://hc")


# ---------------------------------------------------------------- report
class Report(Base):
    def test_ignored(self):
        self.assertTrue(h.ignored({"auid": "1000"}, self.cfg(IGNORE_AUIDS="0 1000")))
        self.assertFalse(h.ignored({"auid": "1001"}, self.cfg(IGNORE_AUIDS="0 1000")))
        self.assertFalse(h.ignored({}, self.cfg()))

    def test_debounce_key(self):
        self.assertEqual(h.debounce_key({"ses": "3", "pid": "9"}), "3")
        self.assertEqual(h.debounce_key({"ses": "4294967295", "pid": "9"}), "pid9")

    def test_debounced(self):
        self.assertFalse(h.debounced("k", 30, now=100))
        self.assertTrue(h.debounced("k", 30, now=129))
        self.assertFalse(h.debounced("k", 30, now=131))
        self.assertFalse(h.debounced("other", 30, now=131))

    def test_snapshot(self):
        self.fake_proc(200, 100, "cat")
        self.run.on(["who"], 0, "alice pts/0")
        s = h.snapshot({"pid": "200", "ses": "-1"})
        self.assertEqual(([p["pid"] for p in s["procs"]], s["ip"], s["others"]), ([200], "", "alice pts/0"))

    def test_snapshot_process_already_gone(self):
        self.fake_proc(100, 1, "bash")
        self.assertEqual([p["pid"] for p in h.snapshot({"pid": "200", "ppid": "100"})["procs"]], [100])

    def test_respond(self):
        snap = {"procs": [], "ip": "8.8.8.8"}
        self.assertEqual(h.respond({}, snap, self.cfg(KILL_SESSION="no", BAN_IP="no")),
                         ["none (monitor only)"])
        self.run.on(["nft"], 0)
        a = h.respond({"ses": "-1", "pid": "5"}, snap, self.cfg())
        self.assertEqual(a[0], "killed pid 5 (?)")
        self.assertEqual(a[1], "banned 8.8.8.8 for 1h")

    def test_event_time(self):
        ts = datetime(2026, 11, 20, 10, 0, 0).timestamp()
        self.assertEqual(h.event_time({"_ts": f"{ts}"}), "2026-11-20 10:00:00")

    def test_result_line(self):
        self.assertEqual(h.result_line({"success": "yes", "syscall": "257", "exit": "3"}, {}),
                         "Result:   OPENED (257, exit 3)")
        self.assertEqual(h.result_line({"success": "no"}, {"syscall": "openat", "exit": "EACCES"}),
                         "Result:   attempt DENIED (openat, exit EACCES)")

    def test_event_lines(self):
        ev = h.parse_audit(SYSCALL)
        L = h.event_lines(ev, {"proctitle": "cat x", "cwd": "/w"}, "/bait", "now")
        self.assertEqual(L[0], "File:     /bait")
        self.assertEqual(L[3], "Command:  cat x")
        self.assertIn("pid 200 ppid 100", L[5])
        self.assertIn("session 3, tty pts0", L[7])

    def test_session_line(self):
        self.assertEqual(h.session_line({"Service": "sshd", "Type": "tty", "Timestamp": "T"}),
                         "Session:  sshd tty since T")

    def test_ip_lines(self):
        self.assertIn("no network session", h.ip_lines("", "", {})[0])
        L = h.ip_lines("1.2.3.4", "22", {"rdns": "h", "geo": "FR", "sshlog": ["Accepted"]})
        self.assertEqual(L, ["Source:   1.2.3.4:22", "  rDNS:   h", "  Geo:    FR", "  sshd:   Accepted"])

    def test_claimed_lines(self):
        self.assertEqual(h.claimed_lines("", "1.2.3.4"), [])
        self.assertEqual(h.claimed_lines("1.2.3.4 1 2 22", "1.2.3.4"), [])
        self.assertIn("not trusted", h.claimed_lines("10.0.0.1 1 2 22", "1.2.3.4")[0])
        self.assertIn("not trusted", h.claimed_lines("garbage", "")[0])

    def test_tree_line(self):
        procs = [{"comm": f"p{i}", "pid": i} for i in range(10)]
        self.assertEqual(h.tree_line(procs[:2]), "Tree:     p0(0) <- p1(1)")
        self.assertEqual(h.tree_line(procs).count("<-"), 7)

    def test_report_body(self):
        snap = {"procs": [{"comm": "cat", "pid": 5, "container": "c0ffee"}],
                "sess": {"Service": "sshd"}, "ip": "", "port": "", "claimed": "", "others": "a\nb"}
        body = h.report_body({}, snap, {}, {}, ["x", "y"], "/bait", "now")
        self.assertIn("Session:  sshd", body)
        self.assertIn("Container: c0ffee", body)
        self.assertIn("Tree:     cat(5)", body)
        self.assertIn("Actions:  x; y", body)
        self.assertTrue(body.endswith("Logged in now:\n  a\n  b"))

    def test_event_json(self):
        snap = {"procs": [], "sess": {}, "ip": "1.2.3.4", "claimed": ""}
        j = h.event_json({"pid": "1"}, snap, {}, ["a"])
        self.assertEqual(j["ip"], "1.2.3.4")
        json.dumps(j)  # must be serialisable

    def test_report_name(self):
        self.assertEqual(h.report_name("42", datetime(2026, 1, 2, 3, 4, 5)), "20260102-030405-42.log")
        self.assertRegex(h.report_name("42", datetime.now()), h.REPORT_RE)

    def test_write_report(self):
        c = self.cfg()
        p = h.write_report(c, "r.log", "text")
        with open(p) as f:
            self.assertEqual(f.read(), "text")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(c["REPORT_DIR"]).st_mode & 0o777, 0o700)

    def test_report_text(self):
        t = h.report_text("T", "B", ["ntfy: ok"], {"raw": "RAW"}, [{"pid": 1}])
        self.assertTrue(t.startswith("T\n\nB\n\nNotify: ['ntfy: ok']"))
        self.assertIn("--- ausearch ---\nRAW", t)
        self.assertIn('"pid": 1', t)


# ---------------------------------------------------------------- handle
class Handle(Base):
    def setUp(self):
        super().setUp()
        self.bait = self.file("bait")
        self.conf = self.file("conf", f"BAIT_FILE={self.bait}\nREPORT_DIR={self.d}/r\n"
                                      f"NTFY_URL=https://n\nHOST_LABEL=nas\n")
        p = mock.patch.object(h, "CONF_PATH", self.conf)
        p.start()
        self.addCleanup(p.stop)
        self.run.on(["loginctl", "terminate-session"], 0)

    def reports(self):
        return os.listdir(os.path.join(self.d, "r"))

    def test_full_event(self):
        state = {}
        h.handle(SYSCALL, state)
        self.assertTrue(state["notified"])
        self.assertEqual(self.sent[0][2]["Title"], "Honeypot triggered on nas")
        body = self.sent[0][1].decode()
        self.assertIn(f"File:     {self.bait}", body)
        self.assertIn("terminated login session 3", body)
        (name,) = self.reports()
        self.assertRegex(name, r"-200\.log$")

    def test_debounced_second_event(self):
        h.handle(SYSCALL)
        h.handle(SYSCALL)
        self.assertEqual(len(self.sent), 1)

    def test_ignored_auid(self):
        with open(self.conf, "a") as f:
            f.write("IGNORE_AUIDS=1000\n")
        h.handle(SYSCALL)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.run.calls, [])

    def test_fallback_body(self):
        b = h.fallback_body({"comm": "cat", "pid": "5"}, ValueError("boom"), KEY)
        self.assertIn("ValueError('boom')", b)
        self.assertIn("cat [?] pid 5", b)
        self.assertIn("ausearch -k pk-auth", b)

    def test_safe_handle_sends_fallback(self):
        with mock.patch.object(h, "snapshot", side_effect=RuntimeError("bug")):
            h._safe_handle(SYSCALL)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("building the full report failed", self.sent[0][1].decode())

    def test_safe_handle_no_double_alert(self):
        with mock.patch.object(h, "write_report", side_effect=OSError("disk full")):
            h._safe_handle(SYSCALL)
        self.assertEqual(len(self.sent), 1)  # the full alert went out already

    def test_safe_handle_survives_everything(self):
        with mock.patch.object(h, "snapshot", side_effect=RuntimeError), \
                mock.patch.object(h, "notify", side_effect=RuntimeError):
            h._safe_handle(SYSCALL)  # must not raise


# ---------------------------------------------------------------- audit log
class Follow(Base):
    def setUp(self):
        super().setUp()
        self.log = self.file("audit.log", "old line\n")

    def append(self, text, path=None):
        with open(path or self.log, "a") as f:
            f.write(text)

    def start(self):
        """Run follow() in a thread feeding a queue; returns once it has opened
        the log (a generator does nothing until first asked for a line)."""
        q = queue.Queue()
        opened = threading.Event()
        real_open = h.open_log

        def open_log(path, at_end):
            r = real_open(path, at_end)
            opened.set()
            return r

        def pump():
            with mock.patch.object(h, "open_log", open_log):
                for line in h.follow(self.log):
                    q.put(line)

        threading.Thread(target=pump, daemon=True).start()
        self.assertTrue(opened.wait(3), "follow() never opened the log")
        return q

    def test_open_log(self):
        f, ino = h.open_log(self.log, at_end=True)
        self.assertEqual((f.read(), ino), (b"", os.stat(self.log).st_ino))
        f.close()
        f, _ = h.open_log(self.log, at_end=False)
        self.assertEqual(f.read(), b"old line\n")
        f.close()

    def test_rotated(self):
        ino = os.stat(self.log).st_ino
        self.assertFalse(h.rotated(self.log, ino, 9))
        self.assertTrue(h.rotated(self.log, ino, 100))       # truncated
        self.assertTrue(h.rotated(self.log, ino + 1, 0))     # replaced
        self.assertFalse(h.rotated(self.log + "x", ino, 0))  # momentarily missing

    def test_new_lines_only(self):
        q = self.start()
        self.append("a\n")
        self.assertEqual(q.get(timeout=3), "a\n")  # not "old line"

    def test_partial_line_waits_for_newline(self):
        q = self.start()
        self.append("par")
        with self.assertRaises(queue.Empty):
            q.get(timeout=0.2)
        self.append("tial\n")
        self.assertEqual(q.get(timeout=3), "partial\n")

    def test_survives_rotation(self):
        q = self.start()
        self.append("before\n")
        self.assertEqual(q.get(timeout=3), "before\n")
        os.rename(self.log, self.log + ".1")
        self.append("after rotation\n", self.log)  # new file, read from its start
        self.assertEqual(q.get(timeout=3), "after rotation\n")

    def test_survives_truncation(self):
        q = self.start()
        self.append("x" * 100 + "\n")
        q.get(timeout=3)
        with open(self.log, "w") as f:
            f.write("fresh\n")
        self.assertEqual(q.get(timeout=3), "fresh\n")

    def test_waits_for_a_missing_log(self):
        os.unlink(self.log)
        q = queue.Queue()
        threading.Thread(target=lambda: [q.put(l) for l in h.follow(self.log)], daemon=True).start()
        time.sleep(0.1)
        self.append("first\nsecond\n")  # appears later: whatever it holds by then is skipped
        time.sleep(1.5)
        self.append("third\n")
        self.assertEqual(q.get(timeout=3), "third\n")

    def test_updates_tick(self):
        with mock.patch.object(h, "_tick", [0]):
            self.start()
            self.assertGreater(h._tick[0], 0)


# ---------------------------------------------------------------- CLI
class Cli(Base):
    def setUp(self):
        super().setUp()
        self.conf = self.file("conf", "NTFY_URL=https://n\n")
        p = mock.patch.object(h, "CONF_PATH", self.conf)
        p.start()
        self.addCleanup(p.stop)
        self.out = io.StringIO()
        p = mock.patch("sys.stdout", self.out)
        p.start()
        self.addCleanup(p.stop)

    def test_test(self):
        self.assertEqual(h.main(["--test"]), 0)
        self.assertIn("ntfy: ok", self.out.getvalue())
        with mock.patch.object(h, "http", side_effect=OSError):
            self.assertEqual(h.main(["--test"]), 1)

    def test_health(self):
        with mock.patch.object(h, "health", return_value=[]):
            self.assertEqual(h.main(["--health"]), 0)
        with mock.patch.object(h, "health", return_value=["bad"]):
            self.assertEqual(h.main(["--health"]), 1)
        self.assertIn("ok: every check passes\nbad", self.out.getvalue())

    def test_bans(self):
        self.run.on(["nft", "list", "set"], 0, "set banned")
        self.assertEqual(h.main(["--bans"]), 0)
        self.assertEqual(len(self.run.ran("nft", "list", "set")), 2)

    def test_unban(self):
        self.run.on(["nft", "delete"], 0)
        self.assertEqual(h.main(["--unban", "::ffff:1.2.3.4"]), 0)
        self.assertEqual(self.run.calls[-1][0][-2:], ["banned4", "{ 1.2.3.4 }"])
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(h.main(["--unban", "nope"]), 1)

    def test_usage(self):
        self.assertEqual(h.main(["--what"]), 2)
        self.assertEqual(h.main(["--unban"]), 2)
        self.assertIn("CLI", self.out.getvalue())


if __name__ == "__main__":
    unittest.main()
