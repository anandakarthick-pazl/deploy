"""
Cron-based scheduled builds.

We use APScheduler in-process but only one gunicorn worker actually runs the
scheduler — coordinated by an OS-level flock on /tmp/packwork-deploy-scheduler.lock.
The other workers detect they can't acquire the lock and skip scheduling.

The scheduler is initialized from `create_app()` after the DB is ready, and
exposes `refresh_jobs()` so the admin blueprint can call it whenever a branch's
`schedule_cron` is changed.
"""

import fcntl
import os
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

_LOCK_PATH = Path("/tmp/packwork-deploy-scheduler.lock")
_lock_fp = None              # holds the lock for the lifetime of this worker
_scheduler: BackgroundScheduler | None = None


def _try_acquire_lock() -> bool:
    """Try to acquire an exclusive non-blocking flock. Keeps fp open if successful."""
    global _lock_fp
    try:
        _lock_fp = open(_LOCK_PATH, "w")
        fcntl.flock(_lock_fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_fp.write(str(os.getpid()))
        _lock_fp.flush()
        return True
    except BlockingIOError:
        if _lock_fp:
            try: _lock_fp.close()
            except Exception: pass
            _lock_fp = None
        return False


def start_scheduler(app):
    """Boot the scheduler if we win the lock. Idempotent — safe to call from each worker."""
    global _scheduler
    if _scheduler is not None:
        return
    if not _try_acquire_lock():
        app.logger.info("Scheduler already running in another worker (skipping).")
        return
    _scheduler = BackgroundScheduler(timezone="UTC", daemon=True)
    _scheduler.start()

    # Metric sampler — captures one CPU/memory/disk snapshot per minute and
    # evaluates threshold alerts. Coalesce so a paused worker doesn't fire
    # multiple catch-up runs at once.
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        from metrics_sampler import sample_once
        _scheduler.add_job(
            sample_once, IntervalTrigger(seconds=60),
            id="metrics-sampler", args=(app,),
            coalesce=True, max_instances=1, replace_existing=True,
        )
    except Exception:
        app.logger.exception("metrics sampler bootstrap failed")

    refresh_jobs(app)
    app.logger.info("Scheduler started in pid=%s", os.getpid())


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def refresh_jobs(app):
    """Re-read all schedule_cron values from the DB and reconfigure jobs.

    Always wipes existing jobs first so a removed cron value cleanly unschedules.
    Safe to call from any worker — it's a no-op in workers that don't hold the lock.
    """
    if _scheduler is None:
        return
    with app.app_context():
        from models import Branch
        # Remove all existing jobs
        for job in _scheduler.get_jobs():
            _scheduler.remove_job(job.id)

        added = 0
        for br in Branch.query.filter(Branch.schedule_cron.isnot(None), Branch.is_active == True).all():  # noqa: E712
            cron_expr = (br.schedule_cron or "").strip()
            if not cron_expr:
                continue
            try:
                trigger = CronTrigger.from_crontab(cron_expr, timezone=None)
            except Exception as e:
                app.logger.warning("Bad cron %r for branch %s/%s: %s",
                                   cron_expr, br.repo.name, br.name, e)
                continue
            _scheduler.add_job(
                _fire_scheduled_build, trigger=trigger,
                id=f"branch-{br.id}", replace_existing=True,
                args=(br.id,), coalesce=True, misfire_grace_time=120,
            )
            added += 1
        app.logger.info("Scheduler refreshed: %s job(s) active", added)


def _fire_scheduled_build(branch_id: int):
    """Triggered by APScheduler when a cron rule fires."""
    # Imported lazily to avoid circular import at module load time.
    from deploy_webhook import app, trigger_manual_deploy
    from models import Branch

    with app.app_context():
        br = Branch.query.get(branch_id)
        if not br or not br.is_active:
            return
        try:
            trigger_manual_deploy(br, "scheduler")
            app.logger.info("Scheduler fired build for %s/%s", br.repo.name, br.name)
        except Exception:
            app.logger.exception("Scheduled build for branch %s failed to start", branch_id)
