"""Login / logout / first-time password setup / forgot-password."""

import base64
import io
import secrets
from datetime import datetime, timedelta

import pyotp
import qrcode
from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

import audit
from models import User, db

auth_bp = Blueprint("auth", __name__)

RESET_TOKEN_LIFETIME = timedelta(hours=24)


def _generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username, is_active=True).first()

        # First-time setup: account has no password yet — accept any login,
        # then force the user to set one.
        if user and user.needs_password_setup:
            session["needs_setup_uid"] = user.id
            return redirect(url_for("auth.first_password"))

        if not user or not user.check_password(password):
            audit.log("login.fail", details={"username": username})
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        # Two-factor: defer login until the code is verified.
        if user.totp_enabled and user.totp_secret:
            session["pending_2fa_uid"] = user.id
            session["pending_2fa_next"] = request.args.get("next") or ""
            return redirect(url_for("auth.totp_verify"))

        user.last_login_at = datetime.utcnow()
        db.session.commit()
        login_user(user, remember=True)
        audit.log("login.success", actor=user)
        next_url = request.args.get("next") or url_for("admin.dashboard")
        return redirect(next_url)

    return render_template("login.html")


@auth_bp.route("/2fa/verify", methods=["GET", "POST"])
def totp_verify():
    uid = session.get("pending_2fa_uid")
    if not uid:
        return redirect(url_for("auth.login"))
    user = User.query.get(uid)
    if not user or not user.totp_secret:
        session.pop("pending_2fa_uid", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
            session.pop("pending_2fa_uid", None)
            next_url = session.pop("pending_2fa_next", None) or url_for("admin.dashboard")
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            audit.log("login.success", actor=user, details={"2fa": True})
            return redirect(next_url)
        audit.log("2fa.fail", actor=user)
        flash("Invalid code. Try again.", "danger")
    return render_template("totp_verify.html", username=user.username)


def _totp_qr_data_url(secret: str, username: str) -> str:
    """Return a data:image/png base64 URL for the otpauth:// QR."""
    from deploy_webhook import _company_name
    issuer = _company_name() or "Packwork Deploy"
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@auth_bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    user = current_user
    if user.totp_enabled and user.totp_secret:
        flash("2FA is already enabled. Disable it first if you want to reset.", "info")
        return redirect(url_for("admin.dashboard"))

    # Generate (or reuse a pending) secret in session
    secret = session.get("pending_totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["pending_totp_secret"] = secret

    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            user.totp_secret  = secret
            user.totp_enabled = True
            db.session.commit()
            session.pop("pending_totp_secret", None)
            audit.log("2fa.enable", actor=user)
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("admin.dashboard"))
        flash("That code didn't match — make sure your authenticator's time is in sync.", "danger")

    qr = _totp_qr_data_url(secret, user.username)
    return render_template("totp_setup.html", qr_data_url=qr, secret=secret)


@auth_bp.route("/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    pw = request.form.get("password") or ""
    if not current_user.check_password(pw):
        flash("Wrong password.", "danger")
        return redirect(url_for("admin.dashboard"))
    current_user.totp_secret  = None
    current_user.totp_enabled = False
    db.session.commit()
    audit.log("2fa.disable", actor=current_user)
    flash("Two-factor authentication disabled.", "info")
    return redirect(url_for("admin.dashboard"))


@auth_bp.route("/first-password", methods=["GET", "POST"])
def first_password():
    uid = session.get("needs_setup_uid")
    if not uid:
        return redirect(url_for("auth.login"))
    user = User.query.get(uid)
    if not user:
        session.pop("needs_setup_uid", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        p1 = request.form.get("password") or ""
        p2 = request.form.get("password_confirm") or ""
        if len(p1) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif p1 != p2:
            flash("Passwords don't match.", "danger")
        else:
            user.set_password(p1)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            session.pop("needs_setup_uid", None)
            login_user(user, remember=True)
            flash("Password set. You're logged in.", "success")
            return redirect(url_for("admin.dashboard"))

    return render_template("first_password.html", username=user.username)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if email:
            user = User.query.filter_by(email=email, is_active=True).first()
            if user:
                user.reset_token = _generate_reset_token()
                user.reset_token_expires = datetime.utcnow() + RESET_TOKEN_LIFETIME
                db.session.commit()
                from deploy_webhook import send_reset_email
                send_reset_email(user, user.reset_token)
        # Always show the same response — no user enumeration.
        flash(
            "If an account exists for that email, a password reset link has been sent. "
            "Check your inbox (and spam folder).",
            "info",
        )
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))

    user = User.query.filter_by(reset_token=token).first()
    if (not user
            or not user.reset_token_expires
            or user.reset_token_expires < datetime.utcnow()
            or not user.is_active):
        flash("This reset link is invalid or has expired. Please request a new one.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        p1 = request.form.get("password") or ""
        p2 = request.form.get("password_confirm") or ""
        if len(p1) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif p1 != p2:
            flash("Passwords don't match.", "danger")
        else:
            user.set_password(p1)
            user.reset_token = None
            user.reset_token_expires = None
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            flash("Password set. You're signed in.", "success")
            return redirect(url_for("admin.dashboard"))

    return render_template("reset_password.html", username=user.username)


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        cur = request.form.get("current_password") or ""
        p1  = request.form.get("password") or ""
        p2  = request.form.get("password_confirm") or ""
        if not current_user.check_password(cur):
            flash("Current password is wrong.", "danger")
        elif len(p1) < 8:
            flash("New password must be at least 8 characters.", "danger")
        elif p1 != p2:
            flash("Passwords don't match.", "danger")
        else:
            current_user.set_password(p1)
            db.session.commit()
            flash("Password updated.", "success")
            return redirect(url_for("admin.dashboard"))
    return render_template("change_password.html")
