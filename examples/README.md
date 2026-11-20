# Decoys

Each entry in this folder is a decoy. It is copied into the target user's home
at the same relative path, and **every file in it becomes a tripwire**:

```bash
sudo ./install.sh -e .aws                         # one decoy
sudo ./install.sh -e .git-credentials -e projects  # several at once
sudo ./install.sh -u alice -e .kube -d "8 months ago"
```

The files are templates. Every `@@TOKEN@@` is replaced with fresh random
values at install time, so no two installs share a key, and nobody can google a
secret from your bait and land on this repository. If a target file already
exists (it's probably real and in use), the installer aborts and leaves it
untouched.

| Decoy (`-e`) | Lands at | Why intruders go for it |
|---|---|---|
| `password.txt` *(default)* | `~/password.txt` | The classic: root, sudo and homelab service passwords. |
| `.aws` | `~/.aws/credentials`, `~/.aws/config` | Cloud keys with prod/terraform roles. Credential stealers and `trufflehog` scans look here first. |
| `.ssh` | `~/.ssh/deploy_prod_ed25519` | An unreferenced "prod deploy" private key. It's added next to your real keys; nothing in `~/.ssh` is overwritten. |
| `.git-credentials` | `~/.git-credentials` | GitHub / GitLab / Gitea tokens in plain text. Supply-chain gold. |
| `.kube` | `~/.kube/config` | Cluster-admin kubeconfig for a "prod" cluster plus a CI service-account token. |
| `.electrum` | `~/.electrum/wallets/default_wallet` | Unencrypted Bitcoin wallet with seed phrase and xprv. Every infostealer hunts for wallets. |
| `projects` | `~/projects/billing-api/.env`, `docker-compose.yml` | A production `.env` with Stripe live key, DB URL, JWT, SendGrid and AWS secrets. Anyone grepping for `sk_live` or `.env` files finds it. |
| `vpn` | `~/vpn/office-wg0.conf` | WireGuard client config promising full access to the internal network. That's lateral movement on a plate. `wg-quick` only reads `/etc/wireguard`, so a real WireGuard setup never touches this file. |

## Picking decoys

- **Don't use a decoy for a tool you use on that machine.** Your own `aws`,
  `kubectl`, `git` (with `credential.helper store`) or Electrum would read the
  file and set off the alarm. For example, use `.kube` on a box that never runs
  kubectl.
- **Mind your own desktop and IDE.** A file manager guessing a file's type, an
  IDE opened on `~/projects` or a shell plugin reading `.env` on `cd` opens the
  bait too (and ends your session). See "How to stop false alarms" in the main
  README.
- **Fit the machine.** A NAS with a Bitcoin wallet is odd, but a dev box with a
  `projects/` folder is perfectly normal. Mix two or three decoys that make
  sense together.
- **Make it yours.** Edit the templates before installing: rename profiles,
  hosts, clusters and projects to match your setup. The defaults are public.

## Writing your own

Put each file at the path it should have relative to the home folder, e.g.
`examples/vpn/office-wg0.conf` lands at `~/vpn/office-wg0.conf`. The first path
component is the decoy name (`-e vpn`), and everything under it is installed.
Tokens (the full reference is in `render-bait.py`):

| Token | Becomes |
|---|---|
| `@@USER@@`, `@@HOST@@` | bait owner, short hostname |
| `@@HEX:32@@`, `@@DIGITS:12@@`, `@@ALNUM:20@@` | random chars of that set and length |
| `@@UPPER:16@@`, `@@LOWER:8@@` | A-Z0-9, a-z0-9 |
| `@@B64:40@@`, `@@B64URL:43@@` | base64 / url-safe base64 alphabet |
| `@@B58:105@@`, `@@BECH32:38@@` | bitcoin alphabets |
| `@@PASS:24@@` | password-like, safe inside URLs (quote it in YAML: it may start with `!` or `*`) |
| `@@WORDS:12@@` | seed-phrase-like word list |
| `@@UUID@@` | random UUID |
| `@@KIND:N:name@@` | same value everywhere `name` is used in one install (e.g. a DB password in both `.env` and `docker-compose.yml`) |

Avoid paths with spaces. This README is never copied.
