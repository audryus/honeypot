# honeypot: a bait-file tripwire for Linux

Plant files that look like forgotten secrets (AWS keys, a kubeconfig, a crypto
wallet, a production `.env`...). Nobody legitimate ever opens them. The moment
anyone does, this tool:

1. **Contains the intruder**: ends their login session, bans their IP in the
   firewall and cuts their open connections.
2. **Collects evidence**: command line, process tree, user, session, source IP,
   reverse DNS, MAC address, DHCP lease, geolocation, recent SSH logins.
3. **Alerts you within seconds** on your phone or chat (ntfy, Telegram, Discord,
   or any webhook).

It's built to be **invisible**. Nothing installed carries the word "honeypot".
You choose every name (service, process, config path, firewall table...), so an
intruder looking around sees an ordinary system service and walks right into
the bait.

It's one Python file (stdlib only) plus shell scripts. There's nothing to
compile and no pip packages. It uses Linux's own audit subsystem (`auditd`), so
detection is in-kernel and can't be skipped by tools that avoid `cat`.

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start (5 minutes)](#quick-start-5-minutes)
- [How-to guides](#how-to-guides)
  - [Choose your stealth names](#how-to-choose-your-stealth-names)
  - [Set up notifications](#how-to-set-up-notifications)
  - [Choose decoys](#how-to-choose-decoys)
  - [Install](#how-to-install)
  - [Test it without locking yourself out](#how-to-test-it-without-locking-yourself-out)
  - [Avoid locking yourself out for real](#how-to-avoid-locking-yourself-out-for-real)
  - [Read alerts, reports and logs](#how-to-read-alerts-reports-and-logs)
  - [Know it's still working (heartbeat, health checks)](#how-to-know-its-still-working)
  - [Manage IP bans](#how-to-manage-ip-bans)
  - [Stop false alarms (backups, indexers)](#how-to-stop-false-alarms)
  - [Change settings after installing](#how-to-change-settings-after-installing)
  - [Look at or edit a bait file yourself](#how-to-look-at-or-edit-a-bait-file-yourself)
  - [Add, remove or switch decoys](#how-to-add-remove-or-switch-decoys)
  - [Rename an existing install](#how-to-rename-an-existing-install)
  - [Watch a file of your own](#how-to-watch-a-file-of-your-own)
  - [Create your own decoy](#how-to-create-your-own-decoy)
  - [Protect several machines](#how-to-protect-several-machines)
  - [Upgrade from an older version](#how-to-upgrade-from-an-older-version)
  - [Uninstall](#how-to-uninstall)
- [What an alert looks like](#what-an-alert-looks-like)
- [Reference](#reference)
  - [install.sh options](#installsh-options)
  - [uninstall.sh options](#uninstallsh-options)
  - [Handler commands](#handler-commands)
  - [Configuration keys](#configuration-keys)
  - [What gets installed where](#what-gets-installed-where)
- [Stealth: what is hidden and what isn't](#stealth-what-is-hidden-and-what-isnt)
- [Containment in detail](#containment-in-detail)
- [Limitations](#limitations)
- [Privacy and security notes](#privacy-and-security-notes)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)
- [License](#license)

---

## How it works

```
 intruder runs: cat ~/.aws/credentials
          │
          ▼
 ┌──────────────────┐  kernel audit rule matches the open() of a bait path
 │  Linux kernel    │──────────────────────────────────────────────┐
 └──────────────────┘                                              ▼
                                                    /var/log/audit/audit.log
                                                                   │ followed by
                                                                   ▼
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ handler (systemd service with a name you chose, e.g. polkit-agent-helper)   │
 │  1. snapshot  : process tree, cmdline, SSH_CONNECTION, login session, IP    │
 │  2. contain   : loginctl terminate-session / kill, nft ban, ss -K sockets   │
 │  3. enrich    : ausearch, rDNS, ARP/MAC, DHCP lease, ipinfo.io, sshd log    │
 │  4. notify    : ntfy / Telegram / Discord / webhook                         │
 │  5. report    : full root-only report file + one bland journal line         │
 └─────────────────────────────────────────────────────────────────────────────┘
```

- **Detection** uses audit rules on the `open`, `openat`, `openat2` and
  `open_by_handle_at` syscalls for each bait path, plus a write/attribute watch.
  It does *not* use the audit "read" class, because that also fires on
  `ls -l` (which reads extended attributes). So **listing a folder, `ls -l` and
  `stat` do not trigger. Opening, reading, copying, editing, `chmod` and
  `chown` do.**
- **The state snapshot happens before containment**, because killing the
  session destroys the evidence.
- **The config is re-read on every event**, so most settings change without a
  restart.

---

## Requirements

| | |
|---|---|
| OS | Linux with **systemd** |
| Package manager (for auto-install of deps) | `apt` (Debian/Ubuntu), `dnf` (Fedora/RHEL), `pacman` (Arch). Others work if you install the deps by hand. |
| Dependencies (installed automatically) | `auditd`/`audit`, `nftables`, `python3`, `iproute2` |
| Privileges | root (`sudo`) |
| Network | Outbound HTTPS for notifications (and ipinfo.io if enabled) |

`auditd` must be running and its rules must not be locked. If
`auditctl -s` shows `enabled 2`, rules can only change after a reboot. See
[Troubleshooting](#troubleshooting).

---

## Quick start (5 minutes)

```bash
# 0. Work in a root shell with history off. `sudo ./install.sh -e .aws` would be
#    logged by sudo (journal / auth.log, readable by adm/wheel users) and saved
#    in your ~/.bash_history: the first places an intruder reads.
sudo -i
unset HISTFILE

# 1. Get the code onto the machine, somewhere only root can see
git clone https://github.com/audryus/honeypot.git /root/hp && cd /root/hp

# 2. Make your private config (git-ignored) and edit it
cp honeypot.conf.example honeypot.conf
nano honeypot.conf
#    - change the STEALTH names (at least SERVICE_NAME, SERVICE_DESCRIPTION, HANDLER_PATH)
#    - set NTFY_URL (or another channel)
#    - put your own laptop's IP in BAN_SAFE_IPS

# 3. Install with one or more decoys (-u: the user whose home gets the baits)
./install.sh -u alice -e .aws -e projects

# 4. You should get a test notification. Then remove all traces of the repo.
#    (Keep a copy of your honeypot.conf somewhere safe, OFF this machine.)
cd / && rm -rf /root/hp
exit
```

Then [test it safely](#how-to-test-it-without-locking-yourself-out).

> ⚠️ **Read this before testing:** with the default settings, opening a bait
> file **kills your own session** and, if you're connected over SSH, **bans
> your IP** for an hour, unless that IP is in `BAN_SAFE_IPS`.

---

## How-to guides

### How to choose your stealth names

If an intruder can tell this is a trap, they'll avoid the bait. Every name the
tool leaves on the system is set in the **STEALTH** section of
`honeypot.conf`. The defaults copy polkit, but **they're published in this
repository**, so anyone who knows the project could look for them. Pick your
own.

1. Look at what's already on the machine and copy its style:
   ```bash
   systemctl list-units --type=service | less
   ls /usr/lib /usr/libexec
   ```
2. Choose a "vendor" and use it consistently. Example sets:

   | Key | polkit-style (default) | udisks-style | fwupd-style |
   |---|---|---|---|
   | `SERVICE_NAME` | `polkit-agent-helper` | `udisks2-monitor` | `fwupd-refresh-agent` |
   | `SERVICE_DESCRIPTION` | `Authorization Agent Helper` | `Disk Manager Monitor` | `Firmware Update Refresh Agent` |
   | `HANDLER_PATH` | `/usr/lib/polkit-1/polkit-agent-helper` | `/usr/libexec/udisks2/udisks-monitor` | `/usr/local/lib/fwupd/fwupd-agent` |
   | `CONF_PATH` | `/etc/polkit-1/agent-helper.conf` | `/etc/udisks2/monitor.conf` | `/etc/fwupd/agent.conf` |
   | `REPORT_DIR` | `/var/lib/polkit-1/agent-cache` | `/var/cache/udisks2/monitor` | `/var/lib/fwupd/agent` |
   | `RULES_NAME` | `50-polkit` | `40-udisks` | `60-fwupd` |
   | `AUDIT_KEY` | `pk-auth` | `udisks-mon` | `fwupd-ref` |
   | `NFT_TABLE` | `raw_filter` | `filter_early` | `netguard` |

3. Change the ones **any user can see** first: `SERVICE_NAME`,
   `SERVICE_DESCRIPTION` (shown by `systemctl`) and `HANDLER_PATH` (shown by
   `ps`). Each key's comment in the config says who can see it.

The installer **refuses** a name that already belongs to a real unit or file,
so you can't overwrite anything by accident. Allowed characters are listed in
the config comments; the installer validates them.

### How to set up notifications

Configure one or more channels in `honeypot.conf` (or later in the installed
config at `CONF_PATH`). Every configured channel gets every alert.

**ntfy (simplest, free, no account)**
1. Install the ntfy app ([ntfy.sh](https://ntfy.sh)) on your phone.
2. Generate a long random topic name. **Anyone who knows the topic can read your
   alerts and send fake ones.**
   ```bash
   openssl rand -hex 16        # e.g. 3f9c1a7e5b2d48c0a6e1f4b9d7c2e8a1
   ```
3. Subscribe to it in the app, then set:
   ```ini
   NTFY_URL=https://ntfy.sh/3f9c1a7e5b2d48c0a6e1f4b9d7c2e8a1
   ```
   For self-hosted ntfy or protected topics, also set `NTFY_TOKEN=tk_...`.
   Alerts are sent with *urgent* priority.

**Telegram**
1. Talk to [@BotFather](https://t.me/BotFather), send `/newbot`, copy the token.
2. Send any message to your new bot (it can't message you first).
3. Get your chat id from [@userinfobot](https://t.me/userinfobot).
   ```ini
   TELEGRAM_BOT_TOKEN=123456789:AAH-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   TELEGRAM_CHAT_ID=987654321
   ```

**Discord**: Channel settings → Integrations → Webhooks → New Webhook → Copy URL.
```ini
DISCORD_WEBHOOK=https://discord.com/api/webhooks/123/abcDEF...
```

**Generic webhook** (Home Assistant, n8n, Node-RED, your own script). It gets a
JSON POST like this:
```json
{ "title": "Honeypot triggered on nas01", "message": "<the text alert>", "event": { "audit": {...}, "ip": "...", "processes": [...], "actions": [...] } }
```
```ini
WEBHOOK_URL=http://homeassistant.lan:8123/api/webhook/tripwire-x7k2
```

**Check it**, either while installing (it sends a test automatically) or any
time after:
```bash
sudo <HANDLER_PATH> --test     # prints "ntfy: ok" / "telegram: FAILED <reason>" per channel
```

To label the machine in alerts, set `HOST_LABEL=homelab-nas` (the default is
the hostname).

### How to choose decoys

Decoys live in [`examples/`](examples/README.md). Each one is copied into the
user's home, and **every file in it is watched**:

| `-e` | Creates | Bait for |
|---|---|---|
| `password.txt` *(default)* | `~/password.txt` | Root, sudo and homelab service passwords |
| `.aws` | `~/.aws/credentials`, `~/.aws/config` | Cloud keys with prod/terraform roles |
| `.ssh` | `~/.ssh/deploy_prod_ed25519` | A "prod deploy" SSH private key (your real keys are untouched) |
| `.git-credentials` | `~/.git-credentials` | GitHub/GitLab/Gitea tokens |
| `.kube` | `~/.kube/config` | Cluster-admin kubeconfig plus a CI token |
| `.electrum` | `~/.electrum/wallets/default_wallet` | Unencrypted Bitcoin wallet with seed phrase |
| `projects` | `~/projects/billing-api/.env`, `docker-compose.yml` | Production `.env` with Stripe live key, DB URL, JWT, SendGrid, AWS |
| `vpn` | `~/vpn/office-wg0.conf` | WireGuard client config with full access to the internal 10.0.0.0/8 network |

Rules of thumb:

- **Never pick a decoy for a tool you use on that machine.** If you run `aws`,
  `kubectl`, Electrum, or `git` with `credential.helper store` there, that tool
  reads the file and you get an alert (and your session gets killed).
- **Make it fit the machine.** A `projects/` folder suits a dev box or VPS.
  A wallet on a NAS is a bit odd. Two or three decoys that make sense together
  look more real than all of them.
- **Personalise it.** Edit the template files before installing: rename
  profiles, clusters, hosts and project names to match your environment.

All secrets are **randomly generated at install time** from `@@TOKEN@@`
placeholders. No two installs share a key, so nobody can search for a key from
your bait and find this repository.

If a decoy's target file **already exists** (e.g. your real `~/.kube/config`),
the installer **stops** and leaves it untouched.

### How to install

```bash
sudo ./install.sh [-u user] [-e decoy]... [-f file]... [-d date]
```

> **Stealth:** `sudo` logs the full command line, decoy names included, where
> admin users can read it. The examples here use `sudo ./install.sh` for
> brevity; for real, run them from a root shell with history off as in the
> [Quick start](#quick-start-5-minutes) (`sudo -i`, `unset HISTFILE`, then
> `./install.sh -u <user> ...`). The same goes for `uninstall.sh`.

Common cases:

```bash
sudo ./install.sh                                   # default decoy: ~/password.txt
sudo ./install.sh -e .aws                           # one decoy
sudo ./install.sh -e .git-credentials -e projects   # several decoys
sudo ./install.sh -u alice -e .kube                 # plant in another user's home
sudo ./install.sh -e .aws -d "14 months ago"        # make it look older
sudo ./install.sh -e .ssh -f /srv/backup/db.key     # decoy + a file of your own
```

The installer:

1. Checks your names don't clash with real units or files.
2. Installs the dependencies and enables `auditd`.
3. Creates the decoy files with random secrets, owned by the user, mode 600.
   Every file **and folder it creates** (e.g. a new `~/.aws/`) gets the same
   fake old date. Folders that already existed, such as `~/.ssh` or your home,
   keep their original date, so nothing looks freshly touched. It refuses any
   bait path that goes through a symlink (also for `-f`).
4. Installs the handler (root-only, mode 700), the config, the systemd unit and
   the audit rules.
5. **Verifies the trap can fire**: every bait has its open and write rules
   loaded, kernel auditing is enabled, and no `-a never,task` rule silences
   it. If not, it stops with an error instead of leaving a dead trap behind.
6. **End-to-end test**: with the service stopped (so nothing gets contained),
   it opens each bait once as root, without changing its access time, and
   checks that auditd logged every open and that `AUDIT_LOG` holds the exact
   line the handler reacts to. These test events never raise an alert: the
   service starts afterwards and only reads new events.
7. Starts the service, runs its health check and sends a test notification.
8. Prints a summary with your service name, config path, report folder and ban
   commands. **Save that summary**, then **delete the repository from the
   machine**.

It's **idempotent**: running it again with the same options changes nothing
important. Existing bait files keep their content and their dates (`-d` only
applies to what a run creates), and your installed config keeps its settings.
If an install fails halfway, the bait files and folders that run created are
removed again (so a re-run doesn't refuse them as real files) and the previous
audit rules are reloaded so the old setup keeps watching.

### How to test it without locking yourself out

1. Switch to **monitor-only mode** by editing the installed config (no restart
   needed):
   ```bash
   sudo nano <CONF_PATH>
   #   KILL_SESSION=no
   #   BAN_IP=no
   ```
2. Trigger it:
   ```bash
   cat ~/.aws/credentials      # or whichever bait you installed
   ```
3. Within a few seconds you should get an alert ending with
   `Actions: none (monitor only)`. Check the journal and the report:
   ```bash
   journalctl -u <SERVICE_NAME> -n 5
   sudo ls -lt <REPORT_DIR>/
   ```
4. Turn containment back on:
   ```bash
   sudo sed -i 's/^KILL_SESSION=.*/KILL_SESSION=yes/; s/^BAN_IP=.*/BAN_IP=yes/' <CONF_PATH>
   ```

**To test full containment**, use a *different* machine whose IP is **not** in
`BAN_SAFE_IPS` (a phone with Termux, a VM, a spare laptop). SSH in as the bait
user and `cat` the bait. The SSH session should drop immediately and that
machine can't reach the server until the ban expires or you
[unban it](#how-to-manage-ip-bans).

Repeat alerts from the same session are debounced for `DEBOUNCE_SECONDS`
(30 by default). Wait between tests.

### How to avoid locking yourself out for real

- Put at least one machine you can always reach the server from in
  `BAN_SAFE_IPS`. Its sessions are still killed, but its IP is never banned:
  ```ini
  BAN_SAFE_IPS=192.168.1.10 192.168.1.11
  ```
- Keep console access (physical, IPMI, VPS web console) as a last resort.
- Bans live in memory only. **A reboot clears every ban.**
- If you're locked out but have console access:
  ```bash
  sudo <HANDLER_PATH> --unban 192.168.1.50
  # or remove all bans at once:
  sudo nft delete table inet <NFT_TABLE>      # recreated on the next service start
  ```

### How to read alerts, reports and logs

| Where | What | Who can read it |
|---|---|---|
| Your phone or chat | The full alert ([example](#what-an-alert-looks-like)) | You |
| `<REPORT_DIR>/<YYYYmmdd-HHMMSS>-<pid>.log` | Full alert + raw `ausearch` output + JSON process tree + delivery status | root |
| `journalctl -u <SERVICE_NAME>` | Neutral one-liners only: `agent started`, `request 1234 handled (delivered): <report path>` | admins (adm/wheel group) |

```bash
sudo ls -lt <REPORT_DIR>/ | head          # newest reports
sudo less <REPORT_DIR>/20261120-221503-48211.log
journalctl -u <SERVICE_NAME> -f           # follow live
sudo ausearch -k <AUDIT_KEY> -i | less    # raw kernel audit events for the bait
```

The journal is deliberately vague (no "intrusion" wording, no bait paths),
because admin users who can read it might be the intruder.

### How to know it's still working

You'll install this and forget about it, so it speaks up by itself:

| What | When | Setting |
|---|---|---|
| **PROBLEM alert** listing what's broken (bait deleted, audit rules gone, auditd stopped, auditing disabled, watcher stuck) | Within ~15 minutes of it breaking; a "recovered" message when fixed | always on |
| **Heartbeat**: a low-priority "still watching" message with the check results and the number of alerts since the last one | Every `HEARTBEAT_DAYS` days (default 7) | `HEARTBEAT_DAYS=0` turns it off |
| **Dead-man's switch**: a URL fetched every 15 minutes while all checks pass | An outside service alerts you when the pings stop | `HEARTBEAT_URL` (healthchecks.io, Uptime Kuma push) |

**No heartbeat for longer than `HEARTBEAT_DAYS` means something is wrong**:
the machine, the service or your notification channel (an expired token
fails silently otherwise). The dead-man's switch is the only one that also
works when the machine is off or offline, so set it up if you can.

Check by hand at any time:

```bash
sudo <HANDLER_PATH> --health     # "ok: every check passes", or the list of problems (exit code 1)
```

A rule deleted by a root intruder (`auditctl -D`) also shows up as a PROBLEM
alert, unless they stop the service first.

### How to manage IP bans

```bash
sudo <HANDLER_PATH> --bans                  # list banned IPs with remaining time
sudo <HANDLER_PATH> --unban 203.0.113.7     # lift one ban
```

- Change the duration with `BAN_TIMEOUT`, using nft units: `30m`, `1h`, `12h`,
  `1d`, `7d`, `1d12h`.
- A ban drops **all** traffic from that IP (SSH, web UIs, databases, and even
  Docker-published ports) because it filters in the earliest stage of
  packet processing.
- Loopback is never banned. Single IPs only, IPv4 and IPv6.
- To disable banning entirely, set `BAN_IP=no`.

### How to stop false alarms

Some legitimate programs open every file in a home folder: backup tools
(restic, borg, rsync, Déjà Dup), desktop indexers (baloo, tracker), antivirus.

**On a machine with a desktop or that you develop on, your own tools can trip
it, and the default containment then ends your own session** (graphical
included). Watch out for:

- **File managers** (Nautilus, Dolphin, Thunar...) that read a file to guess
  its type when the name has no telling extension (`credentials`, `config`,
  `.env`, `default_wallet`), or to draw a preview. Just opening `~/.aws` in one
  can be enough.
- **Editors and IDEs** opened on a folder containing a bait (VS Code on
  `~/projects`, search-in-files, git integrations).
- **Shell plugins** that read files on `cd`, e.g. oh-my-zsh `dotenv` (reads
  `.env`), or tools like `mise`/`direnv` configured to load `.env`.

Prefer decoys in folders you never browse, test with `KILL_SESSION=no` and
`BAN_IP=no` for a few days of normal use, then turn containment on.

1. Find the program in the report's `Process:` line (the path in brackets):
   ```
   Process:  restic [/usr/bin/restic] pid 9123 ppid 1
   ```
2. Exclude the bait paths **in that tool's own configuration**: `restic
   --exclude`, `borg --exclude`, the excluded folders of baloo or tracker,
   your antivirus exclusions. Or pick decoys outside the folders it scans.

There is deliberately **no "allowed programs" list**. An intruder would just use
the allowed program (`rsync`, `tar`, `python3`...) to read the bait silently.

`IGNORE_AUIDS` ignores whole login users. **Leave it empty unless you really
need it**: if you ignore your own uid, an intruder using your stolen account is
ignored too. Never put `4294967295` (no login user) there: that ignores every
daemon, cron job and web shell.

### How to change settings after installing

| Setting | How | Restart? |
|---|---|---|
| Notifications, containment, ignore lists, ban time, IP lookup, `HOST_LABEL` | Edit `<CONF_PATH>` | **No**, read on every event |
| STEALTH names | See [rename](#how-to-rename-an-existing-install) | Re-install |
| Decoys | See [add/remove decoys](#how-to-add-remove-or-switch-decoys) | Re-run `install.sh` |

```bash
sudo nano <CONF_PATH>
sudo <HANDLER_PATH> --test          # confirm notifications still work
```

Forgot where you installed it? These names come from your saved
`honeypot.conf`. On the machine itself, root can find them with:
```bash
sudo grep -rl 'watches the auditd log for access to a bait file' /usr /opt 2>/dev/null   # handler
sudo auditctl -l                                                                        # key and bait paths
```

### How to look at or edit a bait file yourself

Opening a bait **is** the trigger, even for you. To work on one safely:

```bash
sudo systemctl stop <SERVICE_NAME>     # events while stopped are ignored for good
nano ~/.aws/credentials                # look, edit, rename profiles...
touch -d "97 days ago" ~/.aws/credentials   # make it look old again
sudo systemctl start <SERVICE_NAME>
```

`ls -l` and `stat` never trigger, so you can check dates and permissions any
time. If you replaced the file (some editors write a new file instead of
editing in place), re-run `install.sh` with the same options to reload the
audit rules.

### How to add, remove or switch decoys

You need the repository and your `honeypot.conf` back on the machine for a
moment.

```bash
# copy repo + your saved honeypot.conf back, then:
sudo ./install.sh -e .aws -e .git-credentials     # list ALL decoys you want now
```

- Decoys already installed are kept as they are (same secrets, same dates).
- New ones are created.
- Baits you left out are **no longer watched**. The installer prints
  `note: <file> is no longer watched (delete it if unneeded)`. Delete those
  yourself if you don't want them lying around.

Then delete the repository again.

### How to rename an existing install

The scripts only know the names in your `honeypot.conf`, so remove the install
under the old names first:

```bash
sudo ./uninstall.sh                 # honeypot.conf still has the OLD names
nano honeypot.conf                  # change the STEALTH names
sudo ./install.sh -e <same decoys>  # installs under the NEW names
```

Without `--purge`, uninstall keeps the bait files, the old config and the
reports. The old config stays at the old `CONF_PATH`. Copy any settings you
changed there into your new config, then delete it.

### How to watch a file of your own

`-f` watches any path, absolute or relative to the user's home (repeatable):

```bash
sudo ./install.sh -f Documents/vault-recovery-codes.txt
sudo ./install.sh -e .aws -f /srv/backups/.db-root-password -f notes/root.txt
```

- Paths that go through a symlink are refused (the installer runs as root in
  the user's home and must not be tricked into creating a file elsewhere). If
  the symlink is legitimate (e.g. `/home` -> `/var/home`), the error shows the
  real path: pass that instead.

- If the file **doesn't exist**, it's created from the `password.txt` template.
- If it **exists**, it's watched as it is: content and dates aren't touched,
  and `uninstall.sh --purge` never deletes it. Only pick files nothing
  legitimate reads.
- Folders created for a new file get the fake date too; existing folders and
  the other files in them are left alone.

### How to create your own decoy

The shipped `vpn` decoy is a small, complete model. Here's how it's built, so
you can make your own the same way.

1. Put the files under `examples/` at the path they should have **relative to
   the home folder**. The first path component is what you pass to `-e`, and
   everything under it is installed:
   ```
   examples/vpn/office-wg0.conf       -e vpn  → ~/vpn/office-wg0.conf
   examples/.aws/credentials, config  -e .aws → ~/.aws/credentials, ~/.aws/config
   examples/password.txt              -e password.txt → ~/password.txt
   ```
2. Write the file with `@@TOKEN@@` placeholders for anything secret. Match the
   real format closely. A WireGuard key is 32 bytes, which is 43 base64
   characters plus `=`, and the 43rd character is always one of
   `AEIMQUYcgkosw048`. So the key is 42 random characters plus a fixed valid
   last one:
   ```ini
   # office VPN - full access to 10.0.0.0/8 (servers, NAS, iDRAC)
   # import: sudo cp office-wg0.conf /etc/wireguard/wg0.conf && sudo wg-quick up wg0
   [Interface]
   PrivateKey = @@B64:42@@A=
   Address = 10.8.0.14/32
   DNS = 10.0.0.53

   [Peer]
   PublicKey = @@B64:42@@E=
   PresharedKey = @@B64:42@@Q=
   Endpoint = @@HOST@@-@@LOWER:5@@.duckdns.org:51820
   AllowedIPs = 10.0.0.0/8
   PersistentKeepalive = 25
   ```
   The comments do the selling: they tell the intruder what the file unlocks
   and how to use it.
3. Preview the result, then install:
   ```bash
   h=$(uname -n); mkdir -p /tmp/preview && python3 -I render-bait.py "$USER" "${h%%.*}" \
       examples/vpn/office-wg0.conf /tmp/preview/wg0.conf && cat /tmp/preview/wg0.conf
   rm -rf /tmp/preview
   sudo ./install.sh -e vpn
   ```

Token reference:

| Token | Becomes |
|---|---|
| `@@USER@@` / `@@HOST@@` | bait owner / short hostname |
| `@@HEX:N@@` `@@DIGITS:N@@` `@@ALNUM:N@@` | random chars, N long |
| `@@UPPER:N@@` / `@@LOWER:N@@` | A-Z0-9 / a-z0-9 |
| `@@B64:N@@` / `@@B64URL:N@@` | base64 / url-safe base64 alphabet |
| `@@B58:N@@` / `@@BECH32:N@@` | bitcoin alphabets |
| `@@PASS:N@@` | password-like (letters, digits, `!*-_.~+=`), safe in URLs; quote it in YAML (`!` and `*` are special there) |
| `@@WORDS:N@@` | N seed-phrase words |
| `@@UUID@@` | random UUID |
| `@@KIND:N:name@@` | **same value** everywhere `name` appears in one install (e.g. a DB password in both `.env` and `docker-compose.yml`) |

Ideas: `.pgpass`, `.my.cnf`, `.netrc`, `.config/rclone/rclone.conf`,
`.docker/config.json`, a `.password-store`-looking folder, `backup/id_rsa.old`,
a `terraform.tfstate`.

**Don't put fixed fake secrets in templates.** Anything fixed is published in
your fork and can be searched for. Paths can't contain spaces.

### How to protect several machines

Keep one private copy of the repository and your `honeypot.conf` on your
workstation, then for each server:

```bash
scp -r ./honeypot server1:.cache-sync        # bland name, your home only briefly
ssh -t server1 sudo -i                       # root shell: sudo logs only "bash"
# then, on server1 as root:
unset HISTFILE
mv ~<you>/.cache-sync /root/hp && cd /root/hp
./install.sh -u <user> -e projects
cd / && rm -rf /root/hp; exit
```

Use a **different decoy mix and different STEALTH names per machine**, so one
compromised server doesn't reveal the setup of the others. `HOST_LABEL` makes
alerts easy to tell apart.

### How to upgrade from an older version

Early versions used obvious names (`honeypot.service`,
`/usr/local/sbin/honeypot-handler`, `/etc/honeypot.conf`,
`/var/log/honeypot/`, audit key and nft table `honeypot`). Just run the new
installer:

```bash
sudo ./install.sh -f password.txt     # or the -e/-f you want now
```

It stops and removes the old service, handler, rules and firewall table, and
**moves** your old config and reports to the new paths, keeping your
notification settings.

To pick up a newer handler version with the same names, re-run `install.sh`
with the same options.

### How to uninstall

You need the repository and the same `honeypot.conf` you installed with.

```bash
sudo ./uninstall.sh            # remove service, handler, audit rules, firewall table
sudo ./uninstall.sh --purge    # ...and also the config, the reports and the bait files it created
```

- It only deletes files it recognises as its own, never a real file that
  happens to share a name. `--purge` deletes only baits the installer
  *created*: an existing file you watched with `-f` is kept. (Installs made
  before this was tracked don't record it, so their baits are listed, not
  deleted.)
- With `--purge`, folders created by decoys are removed if they end up empty
  (e.g. `~/.kube`). Your real folders such as `~/.ssh` are never removed while
  they still contain your files, and a home folder is never removed.
- A bait whose path now goes through a symlink (e.g. someone replaced `~/.kube`
  with a link to `/etc`) is **skipped** and reported, never followed: delete
  it yourself after checking.
- It also cleans up installs from older versions.
- Active bans disappear with the firewall table.

---

## What an alert looks like

```
Honeypot triggered on nas01

File:     /home/alice/.aws/credentials
When:     2026-11-20 22:15:03
Result:   OPENED (openat, exit 3)
Command:  cat .aws/credentials
Cwd:      /home/alice
Process:  cat [/usr/bin/cat] pid 48211 ppid 48190
User:     uid alice (1000), euid alice (1000)
Login as: alice (1000)  (session 57, tty pts1)
Session:  sshd tty since Fri 2026-11-20 22:14:41 UTC
Source:   203.0.113.7:51544
  rDNS:   static-203-0-113-7.example-isp.net
  Geo:    Frankfurt, Hesse, DE, AS64500 Example Hosting
  sshd:   Accepted password for alice from 203.0.113.7 port 51544 ssh2
Tree:     cat(48211) <- bash(48190) <- sshd(48189) <- sshd(48170) <- sshd(812) <- systemd(1)
Actions:  terminated login session 57; banned 203.0.113.7 for 1h; killed 1 open socket(s) from 203.0.113.7
Logged in now:
  bob      pts/0        2026-11-20 21:02 (192.168.1.10)
```

How to read it:

- **Result**: `OPENED` means the file was actually opened. `attempt DENIED`
  means someone tried but lacked permission, e.g. another user poking around.
- **Login as** is the *original* login user, even after `sudo` or `su`. If it
  differs from **User**, someone escalated.
- **Source** missing (`no network session found`) means local access, a
  service, cron, or a container. Check **Tree** and **Container**.
- **Container** shows the Docker/Podman container id when the access came from
  inside one (`docker ps | grep <id>`).
- **MAC** / **DHCP** appear for LAN sources (from the ARP table and
  Pi-hole/dnsmasq leases), which helps identify a device in your home.
- **sshd** lines show how they got in (password, key, which user).
- **Env claims SSH_CONNECTION=...** appears when the process environment names
  a different source than the real connection. The intruder can set that
  variable to anything (e.g. your router's IP, so it gets banned instead), so
  it is only reported, never banned. It also shows up harmlessly when the
  link to sshd was broken (`setsid`, a detached `tmux`).

---

## Reference

### install.sh options

| Option | Default | Meaning |
|---|---|---|
| `-u user` | the user running `sudo` | Owner of the bait files (whose home they go into) |
| `-e decoy` | `password.txt` when no `-e`/`-f` | Decoy from `examples/`; repeatable |
| `-f file` | none | Extra file to watch (absolute or relative to home); repeatable; created from the `password.txt` template if missing; refused if its path goes through a symlink |
| `-d date` | `97 days ago` | Fake modification date for the files and folders this run creates, anything `date -d` accepts (`"2025-03-14"`, `"8 months ago"`) |
| `-h` | | Show usage |

Settings and names come from `./honeypot.conf` next to the script, or from
`honeypot.conf.example` if there's none (you get a warning).

### uninstall.sh options

| Option | Meaning |
|---|---|
| *(none)* | Remove service, handler, audit rules and firewall table; keep config, reports and baits |
| `--purge` | Also delete config, reports and the bait files the installer created (never an existing file watched with `-f`) |

### Handler commands

Run as root, using your `HANDLER_PATH`:

| Command | Does |
|---|---|
| `<HANDLER_PATH>` | Run the watcher (this is what systemd runs) |
| `<HANDLER_PATH> --test` | Send a test notification on every channel; exit code 0 only if all succeed |
| `<HANDLER_PATH> --health` | Check the trap can fire (baits exist, rules loaded, auditd up, auditing on); exit code 1 on any problem |
| `<HANDLER_PATH> --bans` | List banned IPv4/IPv6 addresses |
| `<HANDLER_PATH> --unban IP` | Remove an IP from the ban list |

For development, set `HONEYPOT_CONF=/path/to/conf` to use another config file.

### Configuration keys

The full documentation with examples is in
[`honeypot.conf.example`](honeypot.conf.example). Format: `KEY=value`, `#`
comments, quotes optional.

| Key | Default | When applied | Purpose |
|---|---|---|---|
| `SERVICE_NAME` | `polkit-agent-helper` | install | systemd unit name |
| `SERVICE_DESCRIPTION` | `Authorization Agent Helper` | install | unit description |
| `HANDLER_PATH` | `/usr/lib/polkit-1/polkit-agent-helper` | install | where the handler is installed (visible in `ps`) |
| `CONF_PATH` | `/etc/polkit-1/agent-helper.conf` | install | where this config is installed |
| `REPORT_DIR` | `/var/lib/polkit-1/agent-cache` | install + runtime | incident report folder |
| `RULES_NAME` | `50-polkit` | install | `/etc/audit/rules.d/<name>.rules` |
| `AUDIT_KEY` | `pk-auth` | install + runtime | audit key tagging bait events |
| `NFT_TABLE` | `raw_filter` | install + runtime | nftables table holding the bans |
| `BAIT_FILE` | *(set by installer)* | runtime | space-separated list of watched files |
| `BAIT_CREATED` | *(set by installer)* | uninstall | the baits the installer created (what `--purge` may delete) |
| `HOST_LABEL` | hostname | runtime | machine name in alerts |
| `KILL_SESSION` | `yes` | runtime | end the intruder's session / kill the process |
| `BAN_IP` | `yes` | runtime | firewall-ban the source IP |
| `BAN_TIMEOUT` | `1h` | runtime | ban duration (nft units; invalid → `1h`) |
| `BAN_SAFE_IPS` | *(empty)* | runtime | IPs never banned |
| `IGNORE_AUIDS` | *(empty)* | runtime | login uids to ignore entirely |
| `DEBOUNCE_SECONDS` | `30` | runtime | one alert per session per window (invalid → `30`) |
| `IP_LOOKUP` | `yes` | runtime | ipinfo.io lookup for public IPs |
| `NTFY_URL` / `NTFY_TOKEN` | *(empty)* | runtime | ntfy channel |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | *(empty)* | runtime | Telegram channel |
| `DISCORD_WEBHOOK` | *(empty)* | runtime | Discord channel |
| `WEBHOOK_URL` | *(empty)* | runtime | generic JSON POST |
| `HEARTBEAT_DAYS` | `7` | runtime | "still watching" message every N days (`0` = off; invalid → `7`) |
| `HEARTBEAT_URL` | *(empty)* | runtime | dead-man's-switch URL fetched every 15 min while healthy |
| `AUDIT_LOG` | `/var/log/audit/audit.log` | runtime | audit log to follow (only if your distro logs elsewhere) |

### What gets installed where

| What | Path (defaults) | Mode |
|---|---|---|
| Handler | `HANDLER_PATH` → `/usr/lib/polkit-1/polkit-agent-helper` | 700 root |
| Config | `CONF_PATH` → `/etc/polkit-1/agent-helper.conf` | 600 root |
| systemd unit | `/etc/systemd/system/<SERVICE_NAME>.service` | 644 |
| Audit rules | `/etc/audit/rules.d/<RULES_NAME>.rules` | 640 |
| Reports | `REPORT_DIR/*.log` (+ `REPORT_DIR/state`: when the last heartbeat went out) | 700 dir / 600 files |
| Firewall | nft table `inet <NFT_TABLE>` with sets `banned4`, `banned6` | in memory |
| Bait files | user's home (per decoy) | 600, owned by the user |

---

## Stealth: what is hidden and what isn't

**Hidden or disguised:**

- No installed file, unit, process, firewall table, audit key or journal line
  is *named* "honeypot". (The handler and installed config do contain the word,
  but only root can read them.)
- The handler is root-only (mode 700): other users can see that it exists, but
  can't read it.
- The config path is built into the handler, so `ps` shows no `--config` flag.
- The audit log is read in-process: no `tail -F /var/log/audit/audit.log`
  child process.
- The journal only gets bland lines. Details go to root-only report files.
- Bait secrets are unique per install, so they can't be searched online.
- Baits and the folders created for them carry a fake old modification date.
  Existing folders keep their real date.

**Still visible (know your exposure):**

| Clue | Seen by | Mitigation |
|---|---|---|
| **The repository itself left on the machine** | everyone | **Delete it after installing.** This is the biggest giveaway. Keep it in `/root` meanwhile, not `/tmp`. |
| **Shell history** (`git clone .../honeypot.git`, `install.sh -e .aws`) | the account's user (and an intruder using it) | Install from `sudo -i` with `unset HISTFILE` ([Quick start](#quick-start-5-minutes)); clean up `~/.bash_history` / `~/.zsh_history` if you already did it the plain way |
| **sudo log** (`COMMAND=/…/install.sh -e .aws` in the journal / `auth.log`) | adm / wheel users | Same: from a root shell, sudo only logs the shell |
| Package manager log shows `audit`/`nftables` being installed (`/var/log/apt/history.log`, `pacman.log`, `dnf.log`) | often everyone | Usually harmless; install them some days earlier if it matters |
| `ps` shows `python3 <HANDLER_PATH>` | everyone | Pick a path where a Python helper is plausible |
| With `HEARTBEAT_URL`: an HTTPS connection every 15 minutes (`ss -tn` shows the remote address, not the process) | everyone | Looks like any agent phoning home; leave it empty if that matters more than the dead-man's switch |
| A bait's *change time* (`stat` → `Change:`) is the install date | everyone | Can't be faked on Linux; only mtime/atime can |
| `auditctl -l` lists the bait paths | root | An intruder with root owns the box anyway |
| Installed config comments describe the tool | root | Same as above |
| The alert title says "Honeypot triggered" | you, plus anyone who knows your ntfy topic | Use a long random topic |

The guiding idea: an intruder **without root** shouldn't be able to tell. One
**with root** can find anything, but by then the alert has already fired.

---

## Containment in detail

When `KILL_SESSION=yes`, the handler tries these in order and stops at the
first that works:

1. **`loginctl terminate-session <id>`** ends the whole login (SSH, console),
   including every process in it.
2. **SSH fallback**: if there's no session, it kills the per-connection `sshd`
   processes found in the process tree.
3. **No session at all** (web shell, cron job, container): it kills only the
   process that opened the bait and its parent **if** that parent is a shell.
   It never goes further up, because the parent could be your web server or
   database.

The source IP comes only from places the intruder can't forge: the TCP peer of
the `sshd` process in the process tree (as the kernel sees it), otherwise the
login session's remote host recorded by logind. `SSH_CONNECTION` from the
environment is reported but never trusted.

When `BAN_IP=yes` and a source IP is known, it adds the IP to an nftables set
with a timeout, dropping everything at the earliest point (including traffic to
Docker containers), then kills that IP's open sockets with `ss -K`.
`BAN_SAFE_IPS` and loopback are skipped.

---

## Limitations

- **It detects opening, not looking.** `ls`, `ls -l`, `stat` and `find`
  without reading don't trigger. Copying (`cp`, `scp`, `tar`, `rsync`) does,
  because it opens the file.
- **The source IP is only known for network logins** (SSH). Local console use,
  cron, services and containers get contained but not banned.
- **Bans are in memory**: a reboot or `nft flush ruleset` clears them.
- **`ss -K`** requires a kernel with socket destroy support (most distro
  kernels). Otherwise existing connections survive until the session is killed.
- **Root intruders** can stop the service, delete rules or read everything.
  You still get the alert if they open a bait first, which is the usual
  sequence.
- **The audit log must be at `AUDIT_LOG`** (default
  `/var/log/audit/audit.log`) and auditd must be running. `AUDIT_LOG` is read
  when the service starts: restart it after changing that one key.
- **io_uring opens are not caught.** A file opened through io_uring
  (`IORING_OP_OPENAT`) bypasses syscall audit rules. Everyday tools (`cat`,
  `cp`, editors, scripts, `scp`, `tar`) use the normal syscalls and are caught;
  a deliberate, tailored evasion might not be.
- **One alert per session per `DEBOUNCE_SECONDS`**, so a burst of reads gives
  one alert.
- **Events that happen while the service is down are never alerted** (it
  starts reading the audit log at its end). They are still in the audit log:
  `sudo ausearch -k <AUDIT_KEY> -i`.
- **The fake secrets fail a close look**: the SSH key, kubeconfig
  certificates and seed phrase don't validate, and the cloud keys don't work.
  That's fine because the alert fires on the *open*, before anyone can check,
  but the intruder will know afterwards.
- **Bait paths can't contain spaces or `* ? [`.**
- **It's a tripwire, not a full IDS.** Use it alongside updates, key-only SSH,
  fail2ban/CrowdSec and backups.

---

## Privacy and security notes

- **`IP_LOOKUP=yes`** sends the *intruder's public IP* (never LAN IPs) to
  ipinfo.io. Set `IP_LOOKUP=no` to keep everything local.
- **Notifications** go to third parties (ntfy.sh, Telegram, Discord) and
  contain the alert details: usernames, paths, IPs.
- **Your `honeypot.conf`** holds notification tokens and your secret names. It's
  in `.gitignore`. Don't commit it, and store it off the protected machine
  (password manager, encrypted notes).
- **Bait secrets are fake.** They grant access to nothing. Still, don't reuse a
  real password in a template.
- **The handler runs as root** because it must read the audit log, kill
  processes and change the firewall. It uses only the Python standard library.

---

## Troubleshooting

**No alert when I open the bait**
```bash
systemctl status <SERVICE_NAME>                  # running?
sudo auditctl -l | grep <AUDIT_KEY>              # rules loaded?
sudo ausearch -k <AUDIT_KEY> -ts recent -i       # did the kernel log the open?
journalctl -u <SERVICE_NAME> -n 20               # did the handler see it?
sudo <HANDLER_PATH> --test                       # do notifications work at all?
```
- Rules missing and `auditctl -s` shows `enabled 2`: audit rules are locked
  until reboot. Reboot, or remove `-e 2` from your audit config if you don't
  need it.
- `ausearch` shows the event but there's no `handled` line in the journal:
  check `IGNORE_AUIDS`, the debounce window, and that
  `AUDIT_LOG` points to the real audit log.
- The journal says `delivery failed`: read the newest report in `REPORT_DIR`.
  Its `Notify:` line has the error from each channel.

**`install.sh` says "exists and isn't ours"**: a name you picked belongs to a
real file or unit. Choose another name in `honeypot.conf`.

**`install.sh` says a bait "already exists and looks real"**: you have a real
file at that path (e.g. your actual `~/.aws/credentials`). Choose a different
decoy. It refuses on purpose.

**"End-to-end test: … NOT logged by auditd"** or **"… not into AUDIT_LOG"**:
the rules are loaded but events don't arrive where the handler reads them.
Check `systemctl status auditd`, `auditctl -s`, and that `AUDIT_LOG` in
`<CONF_PATH>` matches `log_file` in `/etc/audit/auditd.conf`.

**A PROBLEM alert**: run `sudo <HANDLER_PATH> --health` to see what's still
broken. Missing rules after an audit config change: re-run `install.sh` with
the same options (or `sudo augenrules --load`).

**"audit rule not loaded"**: auditd isn't running or rules are locked. Check
`systemctl status auditd` and `auditctl -s`.

**I got banned from my own machine**: use another device, the console, or wait
for `BAN_TIMEOUT`. Then `sudo <HANDLER_PATH> --unban <your-ip>` and add your IP
to `BAN_SAFE_IPS`.

**Alerts from a backup or indexing tool**: exclude the bait paths in that tool's
configuration ([how](#how-to-stop-false-alarms)).

**I lost my `honeypot.conf` and need to uninstall**: as root, recover the names
from the installed config:
```bash
sudo auditctl -l                       # shows the key and bait paths
sudo grep -rl '^AUDIT_KEY=' /etc 2>/dev/null   # finds the installed config
```
Copy that installed config into the repository as `honeypot.conf`, then run
`sudo ./uninstall.sh`.

---

## Repository layout

```
.
├── install.sh              installer (idempotent)
├── uninstall.sh            remover (--purge for everything)
├── common.sh               shared shell helpers: config parsing, name checks, cleanup
├── honeypot-handler.py     the watcher daemon + CLI (stdlib-only Python)
├── render-bait.py          fills @@TOKEN@@ templates with random values
├── honeypot.conf.example   documented configuration; copy to honeypot.conf
├── examples/               decoys (templates), see examples/README.md
│   ├── password.txt
│   ├── .aws/  .ssh/  .kube/  .electrum/  projects/  vpn/
│   └── .git-credentials
├── tests/                  unit tests (python3 -m unittest discover -s tests; bats tests/shell),
│                           integration test (CI only)
└── LICENSE
```

---

## License

[MIT](LICENSE) © 2026 Audryus
