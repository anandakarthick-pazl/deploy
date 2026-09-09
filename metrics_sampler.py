"""Background sampler — once a minute, records CPU/memory/disk into
`server_metrics`, then evaluates threshold alerts and pings Slack/email.

Started from inside scheduler.py (which already holds the worker-zero lock,
so this never runs twice).
"""

from datetime import datetime, timedelta

import psutil

from models import AppSettings, ServerAlert, ServerMetric, db


METRIC_RETENTION_DAYS = 14


def sample_once(app):
    with app.app_context():
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            try:
                disk = psutil.disk_usage("/")
            except Exception:
                disk = None
            load = list(psutil.getloadavg())[0] if hasattr(psutil, "getloadavg") else None

            db.session.add(ServerMetric(
                cpu_pct        = round(cpu, 1),
                mem_used_bytes = int(mem.used),
                mem_total_bytes= int(mem.total),
                mem_pct        = round(mem.percent, 1),
                disk_used_bytes  = int(disk.used)  if disk else None,
                disk_total_bytes = int(disk.total) if disk else None,
                disk_pct         = round(disk.percent, 1) if disk else None,
                load_1m        = round(load, 2) if load is not None else None,
            ))
            db.session.commit()

            # Prune anything older than the retention window
            cutoff = datetime.utcnow() - timedelta(days=METRIC_RETENTION_DAYS)
            ServerMetric.query.filter(ServerMetric.sampled_at < cutoff).delete()
            db.session.commit()

            _evaluate_alerts(app, cpu=cpu, mem_pct=mem.percent,
                             disk_pct=disk.percent if disk else 0.0)
        except Exception:
            db.session.rollback()
            app.logger.exception("metric sample failed")


# ---------------------------------------------------------------------------
# Threshold alerts
# ---------------------------------------------------------------------------
_TRACKED = {
    "cpu":  ("CPU",          "%"),
    "mem":  ("Memory",       "%"),
    "disk": ("Disk (root)",  "%"),
}


def _open_alert(metric):
    return (ServerAlert.query.filter_by(metric=metric, resolved_at=None)
            .order_by(ServerAlert.id.desc()).first())


def _evaluate_alerts(app, *, cpu, mem_pct, disk_pct):
    s = AppSettings.query.get(1)
    if not s or not s.alerts_enabled:
        return
    samples = {"cpu": cpu, "mem": mem_pct, "disk": disk_pct}
    thresholds = {
        "cpu":  s.cpu_threshold,
        "mem":  s.mem_threshold,
        "disk": s.disk_threshold,
    }
    for metric, value in samples.items():
        thr = thresholds.get(metric)
        if not thr:
            continue
        open_alert = _open_alert(metric)
        breaching = value >= thr
        if breaching and not open_alert:
            # Open a new alert
            alert = ServerAlert(metric=metric, threshold=thr, peak_value=value)
            db.session.add(alert)
            db.session.commit()
            _notify_state(app, alert, value, opening=True)
        elif breaching and open_alert:
            if value > (open_alert.peak_value or 0):
                open_alert.peak_value = value
                db.session.commit()
        elif not breaching and open_alert:
            open_alert.resolved_at = datetime.utcnow()
            db.session.commit()
            _notify_state(app, open_alert, value, opening=False)


def _notify_state(app, alert, current_value, opening: bool):
    """Send Slack + email when an alert opens or resolves."""
    metric_label, unit = _TRACKED.get(alert.metric, (alert.metric, ""))
    if opening:
        title = f"🚨  {metric_label} alert opened — {current_value:.1f}{unit} (threshold {alert.threshold:.0f}{unit})"
        body  = (f"<p><b>{metric_label}</b> usage just hit "
                 f"<b>{current_value:.1f}{unit}</b>, above the configured threshold of "
                 f"<b>{alert.threshold:.0f}{unit}</b>.</p>"
                 f"<p>Started at {alert.started_at} UTC.</p>")
        color = "#ef4444"
    else:
        duration = (alert.resolved_at - alert.started_at).total_seconds()
        title = f"✅  {metric_label} alert resolved — back to {current_value:.1f}{unit}"
        body  = (f"<p><b>{metric_label}</b> dropped back to <b>{current_value:.1f}{unit}</b>.</p>"
                 f"<p>Incident lasted {int(duration)} s. Peak: {alert.peak_value:.1f}{unit}.</p>")
        color = "#10b981"

    # Slack
    try:
        from deploy_webhook import _post_slack_raw
        _post_slack_raw(title, color, [
            {"title": "Metric",    "value": metric_label,                     "short": True},
            {"title": "Value",     "value": f"{current_value:.1f}{unit}",     "short": True},
            {"title": "Threshold", "value": f"{alert.threshold:.0f}{unit}",   "short": True},
            {"title": "Status",    "value": "OPEN" if opening else "RESOLVED","short": True},
        ])
    except Exception:
        app.logger.exception("slack alert post failed")

    # Email — to MAIL_TO fallback recipient
    try:
        import os
        from deploy_webhook import _send_email, _company_name
        recipients = [r.strip() for r in os.getenv("MAIL_TO", "").split(",") if r.strip()]
        if recipients:
            html = f"<html><body><h3>{title}</h3>{body}<p style='font-size:11px;color:#666;'>{_company_name()} server monitor</p></body></html>"
            _send_email(title, html, recipients)
    except Exception:
        app.logger.exception("alert email failed")

    alert.notified_at = datetime.utcnow()
    db.session.commit()
