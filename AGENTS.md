# AGENTS.md: for AI agents installing or running this tripwire

You were probably pointed at this repository to **install the tripwire on a
machine** (or check on, change or remove an install). This file is for that.
If you were asked to change the code itself, read [CLAUDE.md](CLAUDE.md) instead.

The tool plants bait files in a user's home. **Anything that opens one is
treated as an intruder**: its login session is ended, its source IP is banned
in the firewall and an alert goes to the owner. That includes you. Read the
[README](README.md) for the full picture; this file lists what's different
when the one doing it is an agent.

## Rules

### 1. Never touch a bait file. Not now, not in a later session.

These all trigger it: `cat`, `less`, `head`, `grep`/`rg` over a folder that
contains a bait, `find ... -exec`, `file`, `sha256sum`, copying, archiving,
opening it in an editor, your own file-reading or search tools, and also
writes and attribute changes (`touch`, `chmod`, `chown`, editing).

Safe (they don't open the file): `ls -l`, `stat`, `test -e`, `find -name`, `du`.

If you're running in the owner's SSH session, a trigger kills **their**
session and bans **their** IP for an hour (unless it's in `BAN_SAFE_IPS`).

- Don't "check that the bait looks right" by reading it. To check the trap,
  use the installer's own end-to-end test (it runs during install), then
  `sudo <HANDLER_PATH> --health` and `sudo <HANDLER_PATH> --test`.
- Keep searches out of that home folder, or limit them to paths you know hold
  no bait. A decoy like `projects` puts baits right where code tools search.
- Don't write the bait paths into an ignore or deny list (agent settings,
  `.gitignore`, indexer config) without asking: a list of "files not to
  touch" sitting in the home folder points an intruder straight at the trap.
- Tell the owner that **any agent working on this machine later** must follow
  this rule too.

### 2. Ask the owner; don't decide for them.

Ask for each of these before installing, and don't fill them in from this
repository's examples:

| What | Why ask |
|---|---|
| STEALTH names in `honeypot.conf` (at least `SERVICE_NAME`, `SERVICE_DESCRIPTION`, `HANDLER_PATH`) | The defaults and the README's example sets are public: an install using them can be recognised. Suggest names that match what's really on this machine (`systemctl list-units --type=service`, `ls /usr/lib /usr/libexec`), and let the owner choose. |
| Notification channel and its token or URL | Alerts are the whole point. Better: the owner pastes the secret into `honeypot.conf` themselves, so it never passes through you. |
| `BAN_SAFE_IPS` | The owner's own address, so they can't be locked out. If you're in their SSH session, `echo "$SSH_CLIENT"` shows the IP they're coming from: offer it, let them confirm. |
| Target user (`-u`) and decoys (`-e`, `-f`) | Pick decoys in folders the owner (and their tools) never browse or search. See "How to choose decoys" and "How to stop false alarms" in the README. |
| Containment on or off at first | `KILL_SESSION=no` and `BAN_IP=no` for the first days on a machine someone works on (desktop, dev box), to catch false alarms without kicking anyone out. |

### 3. Root, and the traces you leave.

The installer needs root, and stealth depends on nothing on the machine
pointing to the trap.

- **sudo logs every command line** (journal / `auth.log`, readable by
  admin users), decoy names included. Best: give the owner the commands to run
  themselves from `sudo -i` with `unset HISTFILE` (README, Quick start). If you
  run them, tell the owner what was logged.
- **Your own records** of this session (transcripts, logs, memory or notes
  files, shell history) hold the names, the config path and the bait paths.
  If you run on this machine, tell the owner where those records are, so they
  can delete them (Claude Code, for example: `~/.claude/projects/<folder>/`).
  Better still: run from another machine, or have the owner run the commands.
- Don't save names, bait paths or config contents anywhere else on the
  machine: not in memory files, notes, commit messages or scripts.
- After a successful install the repository copy must go
  (`rm -rf <the clone>`). Confirm with the owner first. They should keep their
  `honeypot.conf` **off** this machine (it's needed to uninstall or rename later).

### 4. When the installer refuses, stop and report.

Its checks protect the owner's files and the trap itself. Don't work around
them.

- Every refusal is one `ERROR:` line saying what's wrong and what to do.
  Show it to the owner word for word and ask before acting on it.
- A failed install undoes itself: the bait files that run created are removed
  and the previous audit rules and service are restored. Don't clean up by hand.
- Don't delete or move a file it refuses to overwrite ("looks real"), don't
  replace a symlink it refuses to follow, and don't remove a
  `-a never,task` audit rule or change `auditd.conf` without the owner's
  OK: that may be a security policy on purpose.
- NixOS is refused (units and audit rules come from `configuration.nix`).
  Tell the owner; don't try to install around it.

## Install, step by step

1. Read the README's Requirements, Quick start and "How to install".
2. Ask the owner the questions in rule 2 (target user, decoys, containment
   at first).
3. `cp honeypot.conf.example honeypot.conf` and walk the owner through it
   ([next section](#walking-the-owner-through-honeypotconf)).
4. Run (or hand the owner) `./install.sh -u <user> -e <decoy> ...` as root.
5. Read the whole output. Success ends with `Done. Watching N bait file(s)`,
   after `verified: every bait has its open and write rules loaded`, the
   end-to-end test's `ok:` line and `ok: every check passes`.
6. Make sure the owner got the test notification. Ask them; don't assume it.
7. Report (below), then delete the repository copy once the owner agrees.

To see containment work, the owner should trigger it from **another machine**
whose IP isn't in `BAN_SAFE_IPS` (README, "How to test it without locking
yourself out"). Don't trigger it yourself.

## Walking the owner through honeypot.conf

`honeypot.conf` (a copy of [honeypot.conf.example](honeypot.conf.example),
git-ignored) holds every setting. Each key there has a comment explaining it;
go through the file **section by section, in its order**, with the owner:
say what each key does in a sentence, propose a value that fits this machine,
and write it only once they agree. Don't skip a section because its default
looks fine: the owner should know what they're installing.

| Section | Keys | How to guide |
|---|---|---|
| STEALTH | `SERVICE_NAME`, `SERVICE_DESCRIPTION`, `HANDLER_PATH`, `CONF_PATH`, `REPORT_DIR`, `RULES_NAME`, `AUDIT_KEY`, `NFT_TABLE` | Start with the ones marked `[everyone]` in the file. Look at what's really installed (`systemctl list-units --type=service`, `ls /usr/lib /usr/libexec /etc`) and propose 2 or 3 consistent "vendor" sets that fit, never the file's defaults or the README's examples. Respect each key's allowed characters (the installer checks them and refuses names that already exist). |
| BAIT | `BAIT_FILE`, `BAIT_CREATED` | Leave empty: the installer writes them. Decoys are picked with `-e` / `-f` (rule 2, [examples/README.md](examples/README.md)). |
| NOTIFICATION LOOK | `HOST_LABEL` | The name alerts use for this machine; empty = hostname. Useful with several machines. |
| CONTAINMENT | `KILL_SESSION`, `BAN_IP`, `BAN_TIMEOUT`, `BAN_SAFE_IPS` | Explain that `KILL_SESSION=no` alone is not monitor-only (the ban still drops SSH): both `no` for a trial. Get `BAN_SAFE_IPS` right (rule 2): it's what keeps the owner from being locked out. |
| NOISE CONTROL | `IGNORE_AUIDS`, `DEBOUNCE_SECONDS` | Recommend `IGNORE_AUIDS` empty (ignoring a uid also ignores whoever steals that account; never `4294967295`). Ask which backup or indexing tools run here: they get the bait paths excluded in their own config, not here. |
| ENRICHMENT | `IP_LOOKUP` | `yes` sends public attacker IPs (never LAN ones) to ipinfo.io. Let the owner choose. |
| LIVENESS | `HEARTBEAT_DAYS`, `HEARTBEAT_URL` | Explain the "still watching" message and suggest keeping it on. Offer a dead-man's switch (healthchecks.io, Uptime Kuma push), and mention the trade-off in the README's stealth section: an outgoing HTTPS connection every 15 minutes. |
| AUDIT LOG | `AUDIT_LOG` | Check auditd's real log path (`sudo grep -E '^log_file' /etc/audit/auditd.conf`) and change it only if it differs. |
| NOTIFICATIONS | `NTFY_URL`/`NTFY_TOKEN`, `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID`, `DISCORD_WEBHOOK`, `WEBHOOK_URL` | At least one is needed. Ask which app the owner uses and give them that channel's setup steps from the file's comments (ntfy: a long random topic from `openssl rand -hex 16`; Telegram: @BotFather, then the chat id). Tell them the exact lines to fill in and let them paste the secrets themselves (`nano honeypot.conf`), so tokens stay out of your session. Don't print the file back with secrets in it. |

Before installing, show the owner a summary of the chosen values (secrets
shown only as "set" / "empty") and get a yes.

Afterwards there are two copies, and the owner should know which is which:

- **Installed copy at `CONF_PATH`** (root only): runtime settings are changed
  there and apply on the next event, no restart (`AUDIT_LOG` needs a
  `systemctl restart <SERVICE_NAME>`).
- **`honeypot.conf` next to the scripts**: the STEALTH names only take effect
  through `install.sh`, and `uninstall.sh` needs them. The owner keeps this copy
  off the machine, with the repository.

## What to report to the owner

- **Result:** installed, or refused/failed with the exact `ERROR:` line.
- **The installer's final summary**, word for word: service name, config path,
  report folder, `--bans` / `--unban` / `--health` commands. Tell them to keep it
  somewhere safe off this machine.
- **The watched bait paths**, and a reminder that nobody (no person, tool or
  agent) may open, search or touch them.
- **Containment:** on or off (`KILL_SESSION`, `BAN_IP`), and which IPs are in
  `BAN_SAFE_IPS`.
- **What you checked**, and what you didn't (e.g. "the test notification was
  sent; I haven't seen it arrive").
- **Traces left:** sudo log entries, your own session records and where they
  are, and whether the repository copy is deleted yet.
- **Next steps:** confirm the notification arrived, test from another machine,
  keep `honeypot.conf` off the machine.

## Later: checking, changing, removing

- Health: `sudo <HANDLER_PATH> --health` (exit 1 and a reason on any problem).
  Alerts land in `<REPORT_DIR>/*.log` (root only) and the owner's channel.
  The journal (`journalctl -u <SERVICE_NAME>`) has only bland one-liners.
- Bans: `sudo <HANDLER_PATH> --bans`, `sudo <HANDLER_PATH> --unban <ip>`.
- Runtime settings (containment, channels, `BAN_SAFE_IPS`): edit `<CONF_PATH>`;
  no restart needed. Names (STEALTH section) only change by uninstalling with
  the old names and installing with the new ones (README, "How to rename").
- Uninstall needs the repository and the owner's `honeypot.conf` (same names):
  `./uninstall.sh` keeps the baits and reports, `--purge` deletes them (only
  the baits the installer created).
