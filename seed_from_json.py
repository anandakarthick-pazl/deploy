"""
One-time data migration: import existing repos.json into the DB.
Also creates the initial admin user with no password (forces first-login setup).

Safe to run multiple times — uses upsert semantics keyed on (owner, name) and (repo_id, branch_name).
"""

import json
import os
import sys
from pathlib import Path

# Make the Flask app importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from deploy_webhook import create_app
from models import Branch, Repo, User, db

JSON_PATH = Path(os.getenv("REPOS_CONFIG", Path(__file__).resolve().parent / "repos.json"))


def ensure_admin():
    if User.query.filter_by(username="admin").first():
        print("[seed] user 'admin' already exists — leaving as-is")
        return
    admin = User(username="admin", password_hash=None, is_active=True)
    db.session.add(admin)
    db.session.commit()
    print("[seed] created user 'admin' (no password — first login at /login will prompt to set one)")


def upsert_repo_from_json(repo_name, cfg):
    owner = cfg.get("owner", "")
    if not owner:
        print(f"[seed] skipping {repo_name}: no owner in JSON")
        return None
    repo = Repo.query.filter_by(owner=owner, name=repo_name).first()
    if not repo:
        repo = Repo(owner=owner, name=repo_name, is_active=True)
        db.session.add(repo)
    repo.recipients = cfg.get("recipients") or []
    db.session.flush()    # gets repo.id

    branches_cfg = cfg.get("branches", {})
    for branch_name, bcfg in branches_cfg.items():
        br = Branch.query.filter_by(repo_id=repo.id, name=branch_name).first()
        if not br:
            br = Branch(repo_id=repo.id, name=branch_name, is_active=True)
            db.session.add(br)
        br.path       = bcfg.get("path", "")
        br.commands   = bcfg.get("commands") or []
        br.recipients = bcfg.get("recipients") or None
    return repo


def main():
    app = create_app()
    with app.app_context():
        ensure_admin()

        if not JSON_PATH.exists():
            print(f"[seed] repos.json not found at {JSON_PATH}, skipping import")
            return
        data = json.loads(JSON_PATH.read_text())
        repos = data.get("repos", {})
        if not repos:
            print("[seed] no repos to import from JSON")
            return
        for name, cfg in repos.items():
            upsert_repo_from_json(name, cfg)
        db.session.commit()

        # report
        print(f"\n[seed] {Repo.query.count()} repo(s), {Branch.query.count()} branch(es) in DB:")
        for r in Repo.query.order_by(Repo.name).all():
            print(f"  - {r.owner}/{r.name}  branches={[b.name for b in r.branches]}")


if __name__ == "__main__":
    main()
