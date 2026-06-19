from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_network


def normalize_cidr(value: str) -> str:
    return str(ip_network(value, strict=False))


def next_scheduled_for(
    interval_minutes: int,
    *,
    last_scheduled_for: datetime | None = None,
    now: datetime | None = None,
) -> datetime:
    if interval_minutes < 1:
        raise ValueError("interval_minutes must be >= 1")
    reference = last_scheduled_for or now or datetime.now(timezone.utc)
    return reference + timedelta(minutes=interval_minutes)


def classify_scan_result(
    *,
    observed_hosts: int,
    responsive_hosts: int,
    error_count: int,
) -> str:
    if min(observed_hosts, responsive_hosts, error_count) < 0:
        raise ValueError("scan counters cannot be negative")
    if observed_hosts and responsive_hosts > observed_hosts:
        raise ValueError("responsive_hosts cannot exceed observed_hosts")
    if observed_hosts == 0 and error_count == 0:
        return "pending"
    if observed_hosts == 0 and error_count > 0:
        return "failed"
    if error_count > 0:
        return "partial"
    if responsive_hosts > 0:
        return "responsive"
    return "quiet"


def build_scan_request(
    *,
    scan_run_id: int,
    target_cidr: str,
    scheduled_for: datetime | None = None,
) -> dict[str, object]:
    return {
        "accepted": True,
        "mode": "stub",
        "scan_run_id": scan_run_id,
        "target_cidr": target_cidr if "-" in target_cidr else normalize_cidr(target_cidr),
        "scheduled_for": scheduled_for.isoformat() if scheduled_for else None,
        "message": "Raw network scanning is intentionally not implemented in this skeleton.",
    }


if __name__ == "__main__":
    assert normalize_cidr("192.0.2.13/24") == "192.0.2.0/24"
    assert classify_scan_result(observed_hosts=10, responsive_hosts=2, error_count=0) == "responsive"
    assert classify_scan_result(observed_hosts=10, responsive_hosts=0, error_count=0) == "quiet"
    assert classify_scan_result(observed_hosts=0, responsive_hosts=0, error_count=1) == "failed"
