# Packwork Deploy

Deployment control panel behind **https://deploy.pazl.info** — a Flask app that
receives GitHub webhooks, runs deploys, and doubles as a general server-ops
console (file manager, PTY terminal, systemd control, server monitor).

## Running it

Served by gunicorn under systemd, proxied by nginx:

```
nginx (deploy.pazl.info) → 127.0.0.1:9000 → gunicorn → deploy_webhook:app
```

| | |
|---|---|
| Service | `packwork-deploy.service` (runs as root) |
| Working dir | `/srv/code/Source_Code/packworx/deploy` |
| Secrets | `/etc/packwork-deploy.env` — **never** committed |
| Database | MySQL `packworx_deploy` |
| Logs | `/var/log/packwork-deploy.{access,error}.log` |

## Setup from a clean checkout

`venv/` is deliberately not tracked:

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
cp deploy.env.example /etc/packwork-deploy.env   # then fill in real values
venv/bin/python migrate.py
```

## How a deploy runs

`_run_deploy()` in `deploy_webhook.py` picks a runner — `LocalRunner`
(subprocess) or `RemoteRunner` (SSH, per `repo.server_id`) — then:

1. `git rev-parse HEAD` → old SHA (an unborn HEAD is tolerated: first deploy)
2. `git fetch origin <branch>`
3. `git reset --hard origin/<branch>` — **local edits are discarded**
4. diff old..new, or list the whole tree on an initial checkout
5. run `branch.commands` in order, stopping at the first non-zero exit
6. optional health check, then email + Slack notification

Post-deploy commands run **only when the SHA changed**. A re-deploy with no new
commits syncs git and stops there.

`auto_deploy = false` short-circuits before step 1: it records an `awaiting`
deploy and emails for approval instead.

## Layout

| Module | Purpose |
|---|---|
| `deploy_webhook.py` | app factory, webhook receiver, deploy engine |
| `admin.py` | dashboard, repos/branches, deploy history, rollback |
| `mirrors.py` | push a branch to a second git remote (snapshot, not history) |
| `file_manager.py` / `fs.py` | browse, edit, upload, chmod, delete |
| `server_monitor.py` | CPU/mem/disk stats, systemd service control |
| `terminal.py` / `terminal_pty.py` | one-shot commands + interactive PTY |
| `servers.py` / `ssh.py` / `remote_stats.py` | remote servers over SSH |
| `auth.py` / `permissions.py` | login, TOTP, 27-key RBAC |
| `api.py` | bearer-token API for programmatic deploys |
| `scheduler.py` | APScheduler cron builds + metrics sampling |

Permissions are defined in code (`permissions.py`); roles in the database just
map to those keys. `is_admin` bypasses every check.

## Updating this app

It is registered in its own panel, but **auto-deploy is off** — a bad push here
breaks the tool you would use to fix it. The restart is deferred via
`systemd-run` so it cannot kill the deploy that triggered it, and `py_compile`
gates the restart so a syntax error leaves the old process running.

If the panel is ever broken, recover from a shell, not the web UI:

```bash
cd /srv/code/Source_Code/packworx/deploy
git reset --hard <last-good-sha>
systemctl restart packwork-deploy.service
```
