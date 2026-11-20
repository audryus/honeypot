# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-host intrusion tripwire for Linux: a fake "passwords" bait file is watched by auditd, and any open/write/attr-change on it triggers a root daemon that contains the intruder, collects forensics, and sends alerts. No build system, no dependencies beyond the Python 3 stdlib and system tools (`auditd`/`ausearch`/`auditctl`, `nft`, `ss`, `loginctl`, `journalctl`, `ip`, `getent`, `who`).

**Core requirement: stealth.** An intruder who can tell this is a honeypot just avoids the bait. Nothing installed may carry an obvious name: the unit name/description, handler path, config path, report dir, audit rules file, audit key and nft table are all user-chosen in the config's STEALTH section (defaults mimic polkit). Journal output from the handler must stay bland (details go only to root-only report files), and the handler must not spawn long-lived tell-tale children (that's why it follows the audit log in-process instead of `tail -F`). Keep these properties when changing anything.

## Files and how they fit together

- `honeypot.conf.example`: the documented config. Users copy it to `./honeypot.conf` (git-ignored) next to the scripts. Two kinds of keys:
  - **STEALTH names** (`NAME_KEYS` in `common.sh`): read by the shell scripts from `./honeypot.conf` (falls back to the example) and applied at install time. `AUDIT_KEY`, `NFT_TABLE`, `REPORT_DIR` are also read by the handler at runtime.
  - **Runtime keys**: read by the handler from the installed config on every event. These must also exist in `DEFAULTS` in `honeypot-handler.py`.
- `common.sh`: sourced by both scripts. Config parsing (`conf_get`/`conf_set`), name validation (`load_names`), "is this ours?" checks used before overwriting or deleting anything, and the `LEGACY_*` original `honeypot` names that get migrated/cleaned automatically.
- `install.sh` (root, idempotent): refuses names that collide with real units/files, installs deps, creates and backdates the bait, migrates legacy installs, installs the handler at `HANDLER_PATH` (mode 700) and **seds `CONF_PATH` into its `CONF_PATH = ...` line** (keep that a single line), installs the config (kept if present, but `NAME_KEYS`, `BAIT_FILE` and `BAIT_CREATED` are re-synced), writes the unit and audit rules, starts the service.
- `examples/<name>`: decoys, laid out like a home folder, installed with `install.sh -e <name>` (repeatable; no `-e`/`-f` = `-e password.txt`). Every file in a decoy is watched. Files are templates: `@@KIND[:N[:name]]@@` tokens are filled by `render-bait.py` with fresh random values at install time, so secrets in the repo never match a real install (never commit fixed fake secrets: they'd be searchable fingerprints). The first path component is the `-e` name and paths are relative to the home folder (`examples/vpn/office-wg0.conf` → `~/vpn/office-wg0.conf`). Install aborts rather than overwrite an existing file unless it's listed as a bait from a previous run (`BAIT_FILE` in the installed config, space-separated), and refuses bait paths that go through a symlink (it runs as root in a user's home; `no_symlink` in `common.sh`, also for `-f`, which is normalised with `realpath -m -s`, never resolved). Files and folders a run creates get `-d`'s fake date; folders that already existed get their mtime restored, and existing baits (earlier runs, existing `-f` files) aren't re-dated. `BAIT_CREATED` records which baits an install created: `--purge` deletes only those, never an existing file watched with `-f`. An existing file is only ever marked created if it already is in `BAIT_CREATED` (even when a decoy now maps to it). `render-bait.py` is all-or-nothing (renders everything, then writes; removes its own files if a write fails). `examples/README.md` documents each decoy and the token kinds.
- `uninstall.sh [--purge]`: removes using the same names (so renaming = uninstall with old names, edit, install). `--purge` deletes config, report files (never `rm -rf` of the dir) and the baits listed in `BAIT_CREATED`, skipping any whose path now goes through a symlink, and removes emptied parent folders up to (never including) a home folder.

### Event pipeline (handler)

`watch()` follows `AUDIT_LOG` via `follow()` (handles rotation; binary mode so `tell()` is a real byte offset). Each `type=SYSCALL` line carrying `key="<AUDIT_KEY>"` is handled in its own thread by `handle()`:

1. `load_conf()` re-reads the config on every event, so runtime keys need no restart. `IGNORE_AUIDS` and a per-session (or per-pid) debounce run first. Bad numeric values fall back to `DEFAULTS` (an exception would drop the alert). There is deliberately no ignore-by-executable list: an intruder would just use that program.
2. **Snapshot before killing**: `proc_chain` (walks `/proc` for ppid chain, cmdline, `SSH_CONNECTION`, docker/podman cgroup), `session_info` (loginctl), `find_remote`. Order matters: containment destroys this state. `find_remote` trusts only unforgeable sources (the sshd process's TCP peer via `ss`, then logind `RemoteHost`); `SSH_CONNECTION` is attacker-controlled environment, so it's only reported as "claimed", never banned.
3. **Containment** (`contain`): `loginctl terminate-session` → fallback: kill the per-connection sshd chain → fallback: kill only the process and a shell parent (never walk further up, since the parent could be a legitimate service). `ban_ip` adds the source IP to sets `banned4/banned6` in `inet <NFT_TABLE>` (with timeout, prerouting hook at raw priority, so it blocks everything) and runs `ss -K` to drop live sockets. Loopback and `BAN_SAFE_IPS` are never banned.
4. **Enrichment** (after containment): `ausearch -a <serial> -ts recent` (serials restart at boot) for proctitle/cwd/PATH records (`which_bait` matches the touched bait by inode, then by name), plus rDNS, ARP MAC, Pi-hole/dnsmasq DHCP leases, ipinfo.io (public IPs only), and recent sshd journal lines.
5. `notify()` sends to any configured channel (ntfy, Telegram, Discord, generic JSON webhook); full report to `<REPORT_DIR>/<timestamp>-<pid>.log`; one neutral line to the journal. If `handle()` raises before notifying, `_safe_handle` still sends a minimal alert (journal gets only the exception type). `AUDIT_LOG`/`AUDIT_KEY` are read once in `watch()`, not per event.

### Liveness (handler)

`watch()` also starts `liveness_loop` (a thread, not a timer unit: no extra visible name). Every `HEALTH_EVERY` (15 min) it runs `health()`: baits exist (`lexists`, never open), per-bait rules in `auditctl -l` (same format-tolerant matching as install.sh), `auditctl -s` enabled/pid, `AUDIT_LOG` exists, and `_tick` (updated by `follow()`) isn't stale. New problems (confirmed by a re-check 60s later) → PROBLEM alert; cleared → "recovered". While healthy it fetches `HEARTBEAT_URL` (dead-man's switch). Every `HEARTBEAT_DAYS` it sends a low-priority heartbeat; the last send time is in `<REPORT_DIR>/state` (JSON, also deleted by `remove_reports`). `--health` runs the same checks from the CLI. Nothing here logs to the journal except a bland `check failed (<Type>)`.

### Audit rule design (install.sh)

The rule deliberately avoids `-w <bait> -p r`: auditd's read class includes getxattr/listxattr, which `ls -l` triggers. Instead it uses `-p wa` plus explicit `open/openat/openat2/open_by_handle_at` syscall rules filtered by `path=`, probing each syscall per arch with `ausyscall`. Before touching the bait, install.sh unloads the audit key (current and legacy) so its own setup doesn't fire an alert; from that point an EXIT trap (`on_failure`) reloads the on-disk rules file if the install fails, so a half-finished run never leaves the trap disarmed, and, until the config records the new baits (`COMMITTED`), deletes the files/folders that run created. It stops a running service before disarming (the trap restarts it on failure). After loading, it verifies every bait has both its watch and its open rule loaded, that auditing is enabled and that no unfiltered `-a never,task` rule exists, then runs an end-to-end test (opens each bait as root with `O_NOATIME` while the service is stopped, then checks `ausearch` saw each path and `AUDIT_LOG` holds the `type=SYSCALL … key="<AUDIT_KEY>"` lines the handler filters for), starts the service and runs `--health`; any failure aborts. Users install and forget (the repo is deleted afterwards), so install time is the only chance to surface a dead trap. Keep these behaviours when changing the installer.

## Development

Tests cover the two Python scripts (stdlib `unittest`, no install needed; the shell scripts have none). The handler tests fake `run()`, `os.kill`, `http` and `urlopen` in `setUp` (`Base` in `tests/test_handler.py`), so they never run a command, kill anything, touch nftables or the network; keep new tests on `Base`. Keep functions small and side effects behind `run()`/`os.kill`/`http` so they stay testable. `tests/` is never installed (install.sh copies only the two scripts).

```bash
python3 -m unittest discover -s tests && rm -rf tests/__pycache__   # all tests (~2 s)
python3 -m py_compile honeypot-handler.py render-bait.py && rm -rf __pycache__
python3 -I render-bait.py alice nas01 examples/.git-credentials /tmp/out   # render one template (install.sh uses `uname -n`, not `hostname -s`)
bash -n install.sh uninstall.sh common.sh        # shellcheck *.sh if installed
HONEYPOT_CONF=./honeypot.conf python3 honeypot-handler.py --test   # notification-only, safe
```

`HONEYPOT_CONF` overrides the baked-in config path. Calling `handle()` or running the watcher for real **kills processes and edits nftables**. Test those on a VM or with `KILL_SESSION=no BAN_IP=no`, and never against your own session. On a live install (names per config): `journalctl -u <SERVICE_NAME> -f`, `sudo <HANDLER_PATH> --bans`, `sudo <HANDLER_PATH> --unban <ip>`.

## Git

The main branch is **`trunk`** (there is no `main`): it's the default branch on `origin` (github.com/audryus/honeypot) and the base for PRs. Commit and push to `trunk` only when asked.
