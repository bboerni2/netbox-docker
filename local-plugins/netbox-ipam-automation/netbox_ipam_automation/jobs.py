from __future__ import annotations

from .services import build_scan_request, classify_scan_result


def schedule_scan_run(scan_run) -> dict[str, object]:
    policy = scan_run.policy
    target_range = getattr(policy, "target_range", None)
    target_cidr = scan_run.target_cidr or getattr(policy, "target_cidr", "")
    if target_range and not target_cidr:
        target_cidr = str(target_range)
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
