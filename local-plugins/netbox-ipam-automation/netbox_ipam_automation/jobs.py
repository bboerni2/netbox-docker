from __future__ import annotations

from datetime import timedelta

import django_rq
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from core.choices import JobStatusChoices
from core.exceptions import JobFailed
from ipam.models import IPRange
from netbox.jobs import JobRunner, system_job

from .models import GlobalSettings, RangePolicy, ScanRun, ip_range_to_target
from .services import (
    apply_scan_observations,
    build_scan_request,
    classify_scan_result,
    scan_range,
    select_due_candidates,
)


ACTIVE_SCANRUN_STATUSES = (
    ScanRun.StatusChoices.QUEUED,
    ScanRun.StatusChoices.RUNNING,
)
TERMINAL_SCANRUN_STATUSES = (
    ScanRun.StatusChoices.COMPLETED,
    ScanRun.StatusChoices.PARTIAL,
    ScanRun.StatusChoices.FAILED,
    ScanRun.StatusChoices.CANCELLED,
)
ACTIVE_RQ_STATUSES = {"queued", "started", "deferred", "scheduled"}


def get_global_settings() -> GlobalSettings:
    return GlobalSettings.objects.order_by("pk").first() or GlobalSettings()


def rq_job_is_active(job) -> bool:
    try:
        rq_job = django_rq.get_queue(job.queue_name or "default").fetch_job(str(job.job_id))
        status = rq_job.get_status(refresh=True) if rq_job else None
        return getattr(status, "value", status) in ACTIVE_RQ_STATUSES
    except Exception:
        # Redis trouble must not cause healthy jobs to be declared failed.
        return True


def fail_scan_run(scan_run: ScanRun, message: str, *, error_type="OrphanedScanRun", now=None) -> bool:
    if scan_run.status in TERMINAL_SCANRUN_STATUSES:
        return False
    now = now or timezone.now()
    errors = (scan_run.summary or {}).get("errors", [])
    if not isinstance(errors, list):
        errors = []
    scan_run.summary = {
        **(scan_run.summary or {}),
        "accepted": False,
        "errors": [*errors, {"error": error_type, "message": message}][-50:],
    }
    scan_run.status = ScanRun.StatusChoices.FAILED
    scan_run.classification = ScanRun.ClassificationChoices.FAILED
    scan_run.error_count = max(scan_run.error_count, 1)
    scan_run.finished_at = now
    scan_run.message = message[:255]
    scan_run.save(
        update_fields=(
            "summary",
            "status",
            "classification",
            "error_count",
            "finished_at",
            "message",
            "last_updated",
        )
    )
    return True


def reconcile_stale_scan_runs(*, now=None) -> int:
    now = now or timezone.now()
    cutoff = now - timedelta(seconds=getattr(settings, "RQ_DEFAULT_TIMEOUT", 300))
    reconciled = 0
    for scan_run in ScanRun.objects.filter(status__in=ACTIVE_SCANRUN_STATUSES).prefetch_related("jobs"):
        latest_job = max(scan_run.jobs.all(), key=lambda job: job.created, default=None)
        if latest_job and latest_job.status in JobStatusChoices.TERMINAL_STATE_CHOICES:
            detail = latest_job.error or f"Execution job ended with status {latest_job.status}."
        elif latest_job and scan_run.last_updated <= cutoff and not rq_job_is_active(latest_job):
            detail = "Execution job is no longer active in RQ."
        elif latest_job is None and scan_run.last_updated <= cutoff:
            detail = "No execution job exists for this queued scan run."
        else:
            continue
        reconciled += fail_scan_run(scan_run, detail, now=now)
    return reconciled


def get_policy_target(policy: RangePolicy | None) -> str:
    if not policy:
        return ""
    return policy.target_cidr or ip_range_to_target(policy.target_range)


def get_scan_policy(scan_run: ScanRun) -> RangePolicy | None:
    if scan_run.policy:
        return scan_run.policy
    if not scan_run.target_range:
        return None
    return RangePolicy(
        target_range=scan_run.target_range,
        scan_start=str(scan_run.target_range.start_address.ip),
        scan_end=str(scan_run.target_range.end_address.ip),
    )


def get_policy_schedule(policy: RangePolicy, global_settings: GlobalSettings) -> tuple[str, int | None, str]:
    mode = global_settings.schedule_mode if policy.schedule_mode == RangePolicy.ScheduleModeChoices.INHERIT else policy.schedule_mode
    return (
        mode,
        policy.interval_minutes if mode == RangePolicy.ScheduleModeChoices.INTERVAL and policy.schedule_mode != RangePolicy.ScheduleModeChoices.INHERIT else global_settings.default_scan_interval_minutes,
        policy.cron_expressions if mode == RangePolicy.ScheduleModeChoices.CRON and policy.schedule_mode != RangePolicy.ScheduleModeChoices.INHERIT else global_settings.default_cron_expressions,
    )


def prepare_scan_run(
    scan_run: ScanRun,
    *,
    requested_by=None,
    trigger: str,
    scheduled_for=None,
) -> ScanRun:
    if requested_by and not scan_run.requested_by:
        scan_run.requested_by = requested_by
    scan_run.status = ScanRun.StatusChoices.QUEUED
    scan_run.trigger = trigger
    scan_run.classification = ScanRun.ClassificationChoices.PENDING
    if scheduled_for is not None:
        scan_run.scheduled_for = scheduled_for
    if not scan_run.target_range and scan_run.policy:
        scan_run.target_range = scan_run.policy.target_range
    if not scan_run.target_cidr and scan_run.policy:
        scan_run.target_cidr = get_policy_target(scan_run.policy)
    if not scan_run.target_cidr and scan_run.target_range:
        scan_run.target_cidr = ip_range_to_target(scan_run.target_range)
    return scan_run


def enqueue_scan_run(scan_run: ScanRun):
    return ExecuteScanRunJob.enqueue(
        instance=scan_run,
        user=scan_run.requested_by,
    )


def submit_manual_scan_run(scan_run: ScanRun, *, requested_by=None) -> ScanRun:
    prepare_scan_run(
        scan_run,
        requested_by=requested_by,
        trigger=ScanRun.TriggerChoices.MANUAL,
    )
    scan_run.full_clean()
    scan_run.save()
    enqueue_scan_run(scan_run)
    return scan_run


def create_due_scheduled_scan_runs(*, now=None) -> dict[str, int]:
    now = now or timezone.now()
    global_settings = get_global_settings()
    reconcile_stale_scan_runs(now=now)
    if not global_settings.enabled:
        return {"created": 0, "active": 0}

    active_count = ScanRun.objects.filter(status__in=ACTIVE_SCANRUN_STATUSES).count()
    available_slots = max(global_settings.max_concurrent_scans - active_count, 0)
    if available_slots == 0:
        return {"created": 0, "active": active_count}

    policies = list(RangePolicy.objects.filter(enabled=True).select_related("target_range").order_by("pk"))
    active_keys = {
        ("policy", policy_id)
        for policy_id in ScanRun.objects.filter(
            status__in=ACTIVE_SCANRUN_STATUSES,
            policy_id__isnull=False,
        ).values_list("policy_id", flat=True)
    }
    active_keys.update(
        ("range", range_id)
        for range_id in ScanRun.objects.filter(
            status__in=ACTIVE_SCANRUN_STATUSES,
            policy_id__isnull=True,
            target_range_id__isnull=False,
        ).values_list("target_range_id", flat=True)
    )

    candidates = []
    targets = []
    for policy in policies:
        if not policy.target_range_id:
            continue
        last_scan_run = (
            ScanRun.objects.filter(
                policy=policy,
                trigger=ScanRun.TriggerChoices.SCHEDULED,
            )
            .order_by("-scheduled_for", "-created")
            .first()
        )
        schedule_mode, interval_minutes, cron_expressions = get_policy_schedule(policy, global_settings)
        candidates.append(
            {
                "key": ("policy", policy.pk),
                "enabled": policy.enabled,
                "schedule_mode": schedule_mode,
                "interval_minutes": interval_minutes,
                "cron_expressions": cron_expressions,
                "last_scheduled_for": (
                    (last_scan_run.scheduled_for or last_scan_run.created) if last_scan_run else None
                ),
            }
        )
        targets.append({"key": ("policy", policy.pk), "policy": policy, "target_range": policy.target_range})

    if global_settings.scan_all_active_ranges:
        overridden_range_ids = RangePolicy.objects.filter(target_range_id__isnull=False).values_list(
            "target_range_id", flat=True
        )
        for target_range in IPRange.objects.filter(status="active").exclude(pk__in=overridden_range_ids).order_by("pk"):
            last_scan_run = (
                ScanRun.objects.filter(
                    policy__isnull=True,
                    target_range=target_range,
                    trigger=ScanRun.TriggerChoices.SCHEDULED,
                )
                .order_by("-scheduled_for", "-created")
                .first()
            )
            key = ("range", target_range.pk)
            candidates.append(
                {
                    "key": key,
                    "enabled": True,
                    "schedule_mode": RangePolicy.ScheduleModeChoices.INTERVAL,
                    "interval_minutes": global_settings.default_scan_interval_minutes,
                    "cron_expressions": "",
                    "last_scheduled_for": (
                        (last_scan_run.scheduled_for or last_scan_run.created) if last_scan_run else None
                    ),
                }
            )
            targets.append({"key": key, "policy": None, "target_range": target_range})

    due_candidates = select_due_candidates(
        candidates,
        now=now,
        active_keys=active_keys,
        max_new_runs=available_slots,
    )
    due_by_key = {candidate["key"]: candidate for candidate in due_candidates}

    created = 0
    for target in targets:
        key = target["key"]
        if key not in due_by_key:
            continue

        policy = target["policy"]
        target_range = target["target_range"]
        scheduled_for = due_by_key[key]["scheduled_for"]
        with transaction.atomic():
            if policy:
                RangePolicy.objects.select_for_update().get(pk=policy.pk)
            else:
                IPRange.objects.select_for_update().get(pk=target_range.pk)
            duplicate = ScanRun.objects.filter(
                trigger=ScanRun.TriggerChoices.SCHEDULED,
                scheduled_for=scheduled_for,
            )
            duplicate = duplicate.filter(policy=policy) if policy else duplicate.filter(
                policy__isnull=True, target_range=target_range
            )
            if duplicate.exists():
                continue
            scan_run = prepare_scan_run(
                ScanRun(policy=policy, target_range=target_range),
                trigger=ScanRun.TriggerChoices.SCHEDULED,
                scheduled_for=scheduled_for,
            )
            scan_run.full_clean()
            scan_run.save()
        enqueue_scan_run(scan_run)
        created += 1

    return {"created": created, "active": active_count}


def schedule_scan_run(scan_run) -> dict[str, object]:
    target_cidr = scan_run.target_cidr or get_policy_target(scan_run.policy)
    if not target_cidr:
        raise ValueError("scan_run requires target_cidr or a linked policy target.")
    return build_scan_request(
        scan_run_id=scan_run.pk or 0,
        target_cidr=target_cidr,
        scheduled_for=scan_run.scheduled_for,
    )


def classify_scan_run(scan_run) -> str:
    return classify_scan_result(
        observed_hosts=scan_run.observed_hosts,
        responsive_hosts=scan_run.responsive_hosts,
        error_count=scan_run.error_count,
    )


def execute_scan_run(scan_run_id, *, job_id="manual", logger=None):
    scan_run = ScanRun.objects.select_related("policy__target_range", "target_range").get(pk=scan_run_id)
    if scan_run.status in TERMINAL_SCANRUN_STATUSES:
        if logger:
            logger.info("Skipping terminal scan run %s", scan_run.pk)
        return scan_run

    if not scan_run.target_range and scan_run.policy:
        scan_run.target_range = scan_run.policy.target_range
    if not scan_run.target_cidr:
        scan_run.target_cidr = get_policy_target(scan_run.policy)
    if not scan_run.target_cidr and scan_run.target_range:
        scan_run.target_cidr = ip_range_to_target(scan_run.target_range)
    if not scan_run.target_cidr:
        scan_run.status = ScanRun.StatusChoices.FAILED
        scan_run.classification = ScanRun.ClassificationChoices.FAILED
        scan_run.finished_at = timezone.now()
        scan_run.message = "No policy target is configured for this scan run."
        scan_run.save(update_fields=("target_range", "target_cidr", "status", "classification", "finished_at", "message", "last_updated"))
        raise JobFailed(scan_run.message)

    if not scan_run.started_at:
        scan_run.started_at = timezone.now()
    scan_run.status = ScanRun.StatusChoices.RUNNING
    scan_run.message = "Executing TCP scan."
    scan_run.save(
        update_fields=("target_range", "target_cidr", "started_at", "status", "message", "last_updated")
    )

    global_settings = get_global_settings()
    request_payload = schedule_scan_run(scan_run)
    if logger:
        logger.info("Using TCP adapter for scan run %s", scan_run.pk)

    try:
        scan_policy = get_scan_policy(scan_run)
        scan_result = scan_range(scan_policy, global_settings=global_settings)
        observation_summary = apply_scan_observations(
            scan_policy,
            scan_result["responsive_hosts"],
            global_settings=global_settings,
            hostnames=scan_result["hostnames"],
        )
    except Exception as exc:
        scan_run.summary = {
            **(scan_run.summary or {}),
            "adapter": "tcp",
            "accepted": False,
            "job_id": str(job_id),
            "scheduled_for": request_payload["scheduled_for"],
            "target_cidr": request_payload["target_cidr"],
            "errors": [{"error": type(exc).__name__, "message": str(exc)}],
        }
        scan_run.error_count = 1
        scan_run.classification = ScanRun.ClassificationChoices.FAILED
        scan_run.status = ScanRun.StatusChoices.FAILED
        scan_run.finished_at = timezone.now()
        scan_run.message = f"TCP scan failed: {exc}"
        scan_run.save(
            update_fields=(
                "summary",
                "error_count",
                "classification",
                "finished_at",
                "status",
                "message",
                "last_updated",
            )
        )
        raise JobFailed(scan_run.message) from exc

    scan_run.summary = {
        **(scan_run.summary or {}),
        "adapter": "tcp",
        "accepted": True,
        "job_id": str(job_id),
        "scheduled_for": request_payload["scheduled_for"],
        "target_cidr": request_payload["target_cidr"],
        "observed_hosts": observation_summary["observed_hosts"],
        "scanned_hosts": scan_result["scanned_hosts"],
        "responsive_hosts": scan_result["responsive_hosts"],
        "updated": observation_summary["updated"],
        "skipped_protected": observation_summary["skipped_protected"],
        "errors": scan_result["errors"],
        "hostnames": scan_result["hostnames"],
        "open_ports": scan_result["open_ports"],
        "ports": scan_result["ports"],
        "timeout_seconds": scan_result["timeout_seconds"],
        "worker_count": scan_result["worker_count"],
    }
    scan_run.observed_hosts = observation_summary["observed_hosts"]
    scan_run.responsive_hosts = observation_summary["responsive_hosts"]
    scan_run.error_count = 0
    scan_run.classification = classify_scan_run(scan_run)
    scan_run.finished_at = timezone.now()
    if scan_run.classification == ScanRun.ClassificationChoices.FAILED:
        scan_run.status = ScanRun.StatusChoices.FAILED
    elif scan_run.classification == ScanRun.ClassificationChoices.PARTIAL:
        scan_run.status = ScanRun.StatusChoices.PARTIAL
    else:
        scan_run.status = ScanRun.StatusChoices.COMPLETED
    scan_run.message = (
        f"TCP scan completed: {scan_run.responsive_hosts}/{scan_result['scanned_hosts']} responsive, "
        f"{observation_summary['updated']} updated, {observation_summary['skipped_protected']} protected."
    )
    scan_run.save(
        update_fields=(
            "summary",
            "observed_hosts",
            "responsive_hosts",
            "error_count",
            "classification",
            "finished_at",
            "status",
            "message",
            "last_updated",
        )
    )
    return scan_run


class ExecuteScanRunJob(JobRunner):
    class Meta:
        name = "Execute IPAM scan run"

    def run(self, *args, **kwargs):
        scan_run = self.job.object
        if scan_run is None:
            raise JobFailed("Scan execution job is missing its ScanRun instance.")
        try:
            execute_scan_run(scan_run.pk, job_id=self.job.job_id, logger=self.logger)
        except Exception as exc:
            scan_run.refresh_from_db()
            fail_scan_run(
                scan_run,
                f"Scan execution failed: {exc}",
                error_type=type(exc).__name__,
            )
            raise


@system_job(interval=1)
class ScheduleScanRunsJob(JobRunner):
    class Meta:
        name = "Schedule IPAM scan runs"

    @classmethod
    def enqueue_once(cls, *args, **kwargs):
        stale_jobs = cls.get_jobs().filter(status__in=JobStatusChoices.ENQUEUED_STATE_CHOICES)
        for job in stale_jobs:
            if not rq_job_is_active(job):
                job.terminate(
                    status=JobStatusChoices.STATUS_ERRORED,
                    error="Periodic scheduler job is no longer active in RQ.",
                )
        return super().enqueue_once(*args, **kwargs)

    def run(self, *args, **kwargs):
        result = create_due_scheduled_scan_runs()
        self.logger.info(f"Created {result['created']} scheduled scan runs")
