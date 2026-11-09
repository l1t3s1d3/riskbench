# Local VM deploy

Everything in this folder sets up a self-contained deploy pipeline on a single
Linux VM you control. Push a commit, the VM runs the test suite and a security
pipeline, migrates the database, and restarts the service. No GitHub Actions,
no third-party control plane.

```
dev machine                       VM
-----------                       ----------------------------------
$ git push vm main   -------->    /srv/git/riskbench.git (bare repo)
                                        │ post-receive hook
                                        ▼
                                  /opt/riskdesk/work  (checkout)
                                        │
                                        ├─ pytest       (unit tests)
                                        ├─ ruff         (lint / bug patterns)
                                        ├─ bandit       (Python SAST)
                                        ├─ pip-audit    (dependency CVEs)
                                        ├─ gitleaks     (secret scan)
                                        │
                                        ▼ (all green)
                                  pip install, migrate, systemctl restart
                                        │
                                        ▼
                                  Caddy :443 → uvicorn 127.0.0.1:8080
```

Any security-pipeline failure aborts the deploy. The previous version keeps
serving traffic. The scan report is written to
`/var/log/riskdesk/deploy-<timestamp>.log` on the VM, and the exit code of the
`git push` tells you success or failure.

## One-time setup

### On the VM (as root or with sudo)

Copy `deploy/bootstrap-vm.sh` to the VM and run it. It:

- installs system packages (python3.11, caddy, git, ufw)
- creates the `riskdesk` service user and the `deploy` user that owns the git repo
- initialises the bare git repo at `/srv/git/riskbench.git`
- installs the post-receive hook that triggers the pipeline
- creates `/etc/riskdesk/env` from the template (chmod 0640, root:riskdesk)
- installs the systemd unit and Caddyfile
- opens ufw ports 22 and 443
- does **not** start the service until you fill in `/etc/riskdesk/env`

```sh
# on the VM
sudo bash bootstrap-vm.sh
sudoedit /etc/riskdesk/env          # fill in secrets
sudoedit /etc/caddy/Caddyfile       # set hostname or use 'tls internal'
sudo systemctl enable --now caddy
# Do NOT start riskdesk yet -- it needs code deployed first. The first
# `git push vm HEAD:main` populates /opt/riskdesk/current and starts
# the service. After that:
# sudo systemctl enable riskdesk    # so it comes up on reboot
```

Add your dev machine's SSH public key to `/home/deploy/.ssh/authorized_keys`
on the VM (the bootstrap script leaves the file empty for you to fill).

### On your dev machine

Add the VM as a git remote and push:

```sh
git remote add vm deploy@<vm-host>:/srv/git/riskbench.git
git push vm claude/risk-desk-vuln-app-bfvkig:main
```

The `main` branch on the VM's bare repo is what gets deployed. Pushing any
local branch to `main` on the remote triggers the pipeline.

## Everyday workflow

```sh
# make changes, commit locally
git add . && git commit -m "..."

# deploy
git push vm HEAD:main
```

Output of each pipeline stage streams back over SSH, so you see the test and
scan output live in your terminal. A pipeline failure exits non-zero and the
push ends with "failed to update ref". Fix locally and push again.

## Files

| File | Role |
|---|---|
| `bootstrap-vm.sh` | One-shot installer; run as root on the VM |
| `post-receive` | Git hook installed into `/srv/git/riskbench.git/hooks/` |
| `deploy.sh` | The actual pipeline (tests + security scans + restart) |
| `security-scan.sh` | Runs ruff, bandit, pip-audit, gitleaks |
| `riskdesk.service` | systemd unit for the uvicorn process |
| `Caddyfile` | TLS termination; auto-renews Let's Encrypt certs |
| `riskdesk.env.example` | Secrets template; copied to `/etc/riskdesk/env` |
| `backup.sh` | Daily SQLite snapshot (installed as a cron job) |

## Security pipeline tuning

Edit `security-scan.sh` to adjust severity thresholds. Defaults:

- **ruff**: fails on any error-level finding. Rules in `pyproject.toml`.
- **bandit**: fails on HIGH confidence + MEDIUM severity or worse.
- **pip-audit**: fails on any known-vulnerable dependency (OSV database).
- **gitleaks**: fails on any secret found in the commit range being deployed.

To bypass a scanner in an emergency (don't make this a habit):

```sh
BYPASS_SCANS=1 git push vm HEAD:main
```

The bypass is logged with the actor's SSH key and the commit sha.

## Rollback

The post-receive hook keeps the previous worktree at
`/opt/riskdesk/previous`. To roll back:

```sh
# on the VM
sudo /opt/riskdesk/rollback.sh
```

That script swaps `previous` back into place and restarts the service. It does
not touch the database (SQLite migrations are additive-only, so last-version
code reads the newer schema fine).

## What this doesn't cover

- **Horizontal scale.** This is one VM, one SQLite file, one scheduler.
  Fine for the data volumes this app targets.
- **High availability.** If the VM dies, restore the latest `backup.sh`
  snapshot to a new VM and re-run bootstrap. Do a dry-run restore every
  quarter.
- **Patching.** `unattended-upgrades` is enabled by bootstrap for security
  updates. Reboot the VM monthly during a quiet window.
