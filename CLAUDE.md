# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-host intrusion tripwire for Linux: a fake "passwords" bait file is watched by auditd, and any open/write/attr-change on it triggers a root daemon that contains the intruder, collects forensics, and sends alerts. No build system, no tests, no dependencies beyond the Python 3 stdlib and system tools (`auditd`/`ausearch`/`auditctl`, `nft`, `ss`, `loginctl`, `journalctl`, `ip`, `getent`, `who`).

**Core requirement: stealth.** An intruder who can tell this is a honeypot just avoids the bait. Nothing installed may carry an obvious name: the unit name/description, handler path, config path, report dir, audit rules file, audit key and nft table are all user-chosen in the config's STEALTH section (defaults mimic polkit). Journal output from the handler must stay bland (details go only to root-only report files), and the handler must not spawn long-lived tell-tale children (that's why it follows the audit log in-process instead of `tail -F`). Keep these properties when changing anything.

## Files and how they fit together

- `honeypot.conf.example`: the documented config. Users copy it to `./honeypot.conf` (git-ignored) next to the scripts. Two kinds of keys:
  - **STEALTH names** (`NAME_KEYS` in `common.sh`): read by the shell scripts from `./honeypot.conf` (falls back to the example) and applied at install time. `AUDIT_KEY`, `NFT_TABLE`, `REPORT_DIR` are also read by the handler at runtime.
  - **Runtime keys**: read by the handler from the installed config on every event. These must also exist in `DEFAULTS` in `honeypot-handler.py`.
- `common.sh`: sourced by both scripts. Config parsing (`conf_get`/`conf_set`), name validation (`load_names`), "is this ours?" checks used before overwriting or deleting anything, and the `LEGACY_*` original `honeypot` names that get migrated/cleaned automatically.
- `install.sh` (root, idempotent): refuses names that collide with real units/files, installs deps, creates and backdates the bait, migrates legacy installs, installs the handler at `HANDLER_PATH` (mode 700) and **seds `CONF_PATH` into its `CONF_PATH = ...` line** (keep that a single line), installs the config (kept if present, but `NAME_KEYS` and `BAIT_FILE` are re-synced), writes the unit and audit rules, starts the service.
- `examples/<name>`: decoys, laid out like a home folder, installed with `install.sh -e <name>` (repeatable; no `-e`/`-f` = `-e password.txt`). Every file in a decoy is watched. Files are templates: `@@KIND[:N[:name]]@@` tokens are filled by `render-bait.py` with fresh random values at install time, so secrets in the repo never match a real install (never commit fixed fake secrets: they'd be searchable fingerprints). Install aborts rather than overwrite an existing file unless it's listed as a bait from a previous run (`BAIT_FILE` in the installed config, space-separated). Created files and folders are backdated, and folders that already existed get their mtime restored. `examples/README.md` documents each decoy and the token kinds.
- `uninstall.sh [--purge]`: removes using the same names (so renaming = uninstall with old names, edit, install). `--purge` deletes config, report files (never `rm -rf` of the dir) and the bait.

### Event pipeline (handler)

`watch()` follows `AUDIT_LOG` via `follow()` (handles rotation). Each `type=SYSCALL` line carrying `key="<AUDIT_KEY>"` is handled in its own thread by `handle()`:

1. `load_conf()` re-reads the config on every event, so runtime keys need no restart. Ignore lists and a per-session (or per-pid) debounce run first.
2. **Snapshot before killing**: `proc_chain` (walks `/proc` for ppid chain, cmdline, `SSH_CONNECTION`, docker/podman cgroup), `session_info` (loginctl), `find_remote`. Order matters: containment destroys this state.
3. **Containment** (`contain`): `loginctl terminate-session` → fallback: kill the per-connection sshd chain → fallback: kill only the process and a shell parent (never walk further up, since the parent could be a legitimate service). `ban_ip` adds the source IP to sets `banned4/banned6` in `inet <NFT_TABLE>` (with timeout, prerouting hook at raw priority, so it blocks everything) and runs `ss -K` to drop live sockets. Loopback and `BAN_SAFE_IPS` are never banned.
4. **Enrichment** (after containment): `ausearch -a <serial>` for proctitle/cwd, plus rDNS, ARP MAC, Pi-hole/dnsmasq DHCP leases, ipinfo.io (public IPs only), and recent sshd journal lines.
5. `notify()` sends to any configured channel (ntfy, Telegram, Discord, generic JSON webhook); full report to `<REPORT_DIR>/<timestamp>-<pid>.log`; one neutral line to the journal.

### Audit rule design (install.sh)

The rule deliberately avoids `-w <bait> -p r`: auditd's read class includes getxattr/listxattr, which `ls -l` triggers. Instead it uses `-p wa` plus explicit `open/openat/openat2/open_by_handle_at` syscall rules filtered by `path=`, probing each syscall per arch with `ausyscall`. Before touching the bait, install.sh unloads the audit key (current and legacy) so its own setup doesn't fire an alert. Keep both of these behaviours when changing the installer.

## Development

There is no test suite. Useful checks:

```bash
python3 -m py_compile honeypot-handler.py render-bait.py && rm -rf __pycache__
python3 -I render-bait.py alice nas01 examples/.git-credentials /tmp/out   # render one template
bash -n install.sh uninstall.sh common.sh        # shellcheck *.sh if installed
HONEYPOT_CONF=./honeypot.conf python3 honeypot-handler.py --test   # notification-only, safe
```

`HONEYPOT_CONF` overrides the baked-in config path. Calling `handle()` or running the watcher for real **kills processes and edits nftables**. Test those on a VM or with `KILL_SESSION=no BAN_IP=no`, and never against your own session. On a live install (names per config): `journalctl -u <SERVICE_NAME> -f`, `sudo <HANDLER_PATH> --bans`, `sudo <HANDLER_PATH> --unban <ip>`.
