from __future__ import annotations

from django.db import transaction
from django.utils import timezone
from core.exceptions import JobFailed
from netbox.jobs import JobRunner, system_job

from .models import GlobalSettings, RangePolicy, ScanRun, ip_range_to_target
from .services import (
    build_scan_request,
    classify_scan_result,
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


def get_global_settings() -> GlobalSettings:
    return GlobalSettings.objects.order_by("pk").first() or GlobalSettings()


def get_policy_target(policy: RangePolicy | None) -> str:
    if not policy:
        return ""
    return policy.target_cidr or ip_range_to_target(policy.target_range)


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
    if not scan_run.target_cidr and scan_run.policy:
        scan_run.target_cidr = get_policy_target(scan_run.policy)
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
    if not global_settings.enabled:
        return {"created": 0, "active": 0}

    active_count = ScanRun.objects.filter(status__in=ACTIVE_SCANRUN_STATUSES).count()
    available_slots = max(global_settings.max_concurrent_scans - active_count, 0)
    if available_slots == 0:
        return {"created": 0, "active": active_count}

    policies = list(RangePolicy.objects.filter(enabled=True).order_by("pk"))
    active_policy_ids = set(
        ScanRun.objects.filter(
            status__in=ACTIVE_SCANRUN_STATUSES,
            policy_id__isnull=False,
        ).values_list("policy_id", flat=True)
    )

    candidates = []
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
                "key": policy.pk,
                "enabled": policy.enabled,
                "schedule_mode": schedule_mode,
                "interval_minutes": interval_minutes,
                "cron_expressions": cron_expressions,
                "last_scheduled_for": (
                    (last_scan_run.scheduled_for or last_scan_run.created) if last_scan_run else None
                ),
            }
        )

    due_candidates = select_due_candidates(
        candidates,
        now=now,
        active_keys=active_policy_ids,
        max_new_runs=available_slots,
    )
    due_by_id = {candidate["key"]: candidate for candidate in due_candidates}

    created = 0
    for policy in policies:
        if policy.pk not in due_by_id:
            continue

        scheduled_for = due_by_id[policy.pk]["scheduled_for"]
        with transaction.atomic():
            RangePolicy.objects.select_for_update().get(pk=policy.pk)
            if ScanRun.objects.filter(
                policy=policy,
                trigger=ScanRun.TriggerChoices.SCHEDULED,
                scheduled_for=scheduled_for,
            ).exists():
                continue
            scan_run = prepare_scan_run(
                ScanRun(policy=policy),
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


class ExecuteScanRunJob(JobRunner):
    class Meta:
        name = "Execute IPAM scan run"

    @transaction.atomic
    def run(self, *args, **kwargs):
        scan_run = self.job.object
        if scan_run is None:
            raise JobFailed("Scan execution job is missing its ScanRun instance.")

        scan_run = ScanRun.objects.select_for_update().select_related("policy").get(pk=scan_run.pk)
        if scan_run.status in TERMINAL_SCANRUN_STATUSES:
            self.logger.info("Skipping terminal scan run %s", scan_run.pk)
            return

        if not scan_run.target_cidr:
            scan_run.target_cidr = get_policy_target(scan_run.policy)
        if not scan_run.target_cidr:
            scan_run.status = ScanRun.StatusChoices.FAILED
            scan_run.classification = ScanRun.ClassificationChoices.FAILED
            scan_run.finished_at = timezone.now()
            scan_run.message = "No policy target is configured for this scan run."
            scan_run.save(
                update_fields=("target_cidr", "status", "classification", "finished_at", "message", "last_updated")
            )
            raise JobFailed(scan_run.message)

        if not scan_run.started_at:
            scan_run.started_at = timezone.now()
        scan_run.status = ScanRun.StatusChoices.RUNNING
        scan_run.message = "Executing scan adapter."
        scan_run.save(update_fields=("started_at", "status", "message", "last_updated"))

        request_payload = schedule_scan_run(scan_run)
        self.logger.info("Using %s adapter for scan run %s", request_payload["mode"], scan_run.pk)

        scan_run.summary = {
            **(scan_run.summary or {}),
            "adapter": request_payload["mode"],
            "accepted": request_payload["accepted"],
            "job_id": str(self.job.job_id),
            "scheduled_for": request_payload["scheduled_for"],
            "target_cidr": request_payload["target_cidr"],
        }
        scan_run.classification = classify_scan_run(scan_run)
        scan_run.finished_at = timezone.now()
        if scan_run.classification == ScanRun.ClassificationChoices.FAILED:
            scan_run.status = ScanRun.StatusChoices.FAILED
        elif scan_run.classification == ScanRun.ClassificationChoices.PARTIAL:
            scan_run.status = ScanRun.StatusChoices.PARTIAL
        else:
            scan_run.status = ScanRun.StatusChoices.COMPLETED
        scan_run.message = request_payload["message"]
        scan_run.save(
            update_fields=(
                "summary",
                "classification",
                "finished_at",
                "status",
                "message",
                "last_updated",
            )
        )


@system_job(interval=1)
class ScheduleScanRunsJob(JobRunner):
    class Meta:
        name = "Schedule IPAM scan runs"

    def run(self, *args, **kwargs):
        result = create_due_scheduled_scan_runs()
        self.logger.info("Created %s scheduled scan runs", result["created"])
