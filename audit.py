"""Append-only audit log helper. Import and call `log(...)` from anywhere."""

from datetime import datetime

from flask import has_request_context, request
from flask_login import current_user

from models import AuditLog, db


def log(action: str, target_type: str | None = None, target_id=None,
        target_label: str | None = None, details: dict | None = None,
        actor=None) -> None:
    """Record an audit event. Never raises — failures are swallowed so a bad
    audit write can't break a real operation."""
    try:
        user_id = None
        username = None
        if actor is not None:
            user_id  = getattr(actor, "id", None)
            username = getattr(actor, "username", None)
        elif has_request_context() and current_user.is_authenticated:
            user_id  = current_user.id
            username = current_user.username

        ip = ua = None
        if has_request_context():
            ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or request.remote_addr
            if ip:
                ip = ip.split(",")[0].strip()[:45]
            ua = (request.headers.get("User-Agent") or "")[:255]

        row = AuditLog(
            user_id=user_id, username=username,
            action=action,
            target_type=target_type,
            target_id=target_id,
            target_label=(target_label or "")[:255] or None,
            details=details,
            ip_address=ip, user_agent=ua,
        )
        db.session.add(row)
        db.session.commit()
    except Exception:
        try: db.session.rollback()
        except Exception: pass
