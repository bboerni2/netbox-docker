from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network, summarize_address_range
import os
import re
import socket
import subprocess

from croniter import croniter
from django.db import transaction
from django.utils import timezone as django_timezone
from defusedxml import ElementTree

MANAGED_IP_STATUSES = {"active", "free", "deprecated"}
SCAN_ERROR_LIMIT = 50
NMAP_ROUTED_PROBES = ("-PE", "-PP", "-PS22,80,443,445,3389", "-PA80,443")
NMAP_ROOT_ONLY_PROBES = ("-PU53,161",)


def normalize_cidr(value: str) -> str:
    return str(ip_network(value, strict=False))


def ip_range_to_network(start_address, end_address) -> IPv4Network:
    start = ip_address(str(start_address).split("/")[0])
    end = ip_address(str(end_address).split("/")[0])
    if start.version != 4 or end.version != 4:
        raise ValueError("Only IPv4 ranges are supported.")

    networks = list(summarize_address_range(start, end))
    if len(networks) != 1:
        raise ValueError("The target IP range must match one exact IPv4 subnet.")

    network = networks[0]
    if network.network_address != start or network.broadcast_address != end:
        raise ValueError("The target IP range must span the full IPv4 subnet, including network and broadcast.")

    return network


def parse_cron_expressions(value: str) -> list[str]:
    expressions: list[str] = []
    seen: set[str] = set()

    for raw_expression in value.splitlines():
        expression = " ".join(raw_expression.split())
        if not expression:
            continue
        if len(expression.split()) != 5:
            raise ValueError(f"Invalid cron expression '{expression}': exactly five fields are required.")
        croniter(expression)
        if expression not in seen:
            seen.add(expression)
            expressions.append(expression)

    return expressions


def normalize_cron_expressions(value: str) -> str:
    return "\n".join(parse_cron_expressions(value))


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


def is_due_for_interval(
    interval_minutes: int,
    *,
    now: datetime,
    last_scheduled_for: datetime | None = None,
) -> bool:
    if last_scheduled_for is None:
        return True
    return next_scheduled_for(
        interval_minutes,
        last_scheduled_for=last_scheduled_for,
        now=now,
    ) <= now


def due_time_for_cron(
    cron_expressions: str,
    *,
    now: datetime,
    last_scheduled_for: datetime | None = None,
) -> datetime | None:
    current_minute = django_timezone.localtime(now).replace(second=0, microsecond=0)
    due_matches = [
        expression
        for expression in parse_cron_expressions(cron_expressions)
        if croniter(expression, current_minute - timedelta(seconds=1)).get_next(datetime) == current_minute
    ]
    if not due_matches:
        return None
    if last_scheduled_for and last_scheduled_for >= current_minute:
        return None
    return current_minute


def due_time_for_candidate(candidate: dict[str, object], *, now: datetime) -> datetime | None:
    schedule_mode = str(candidate["schedule_mode"])
    last_scheduled_for = candidate.get("last_scheduled_for")

    if schedule_mode == "interval":
        interval_minutes = int(candidate["interval_minutes"])
        if last_scheduled_for is None:
            return now
        due_at = next_scheduled_for(interval_minutes, last_scheduled_for=last_scheduled_for, now=now)
        return due_at if due_at <= now else None

    if schedule_mode == "cron":
        return due_time_for_cron(
            str(candidate["cron_expressions"]),
            now=now,
            last_scheduled_for=last_scheduled_for,
        )

    raise ValueError(f"Unsupported schedule mode '{schedule_mode}'.")


def select_due_candidates(
    candidates: list[dict[str, object]],
    *,
    now: datetime,
    active_keys: set[object] | None = None,
    max_new_runs: int,
) -> list[dict[str, object]]:
    if max_new_runs < 0:
        raise ValueError("max_new_runs must be >= 0")
    if max_new_runs == 0:
        return []

    due_candidates: list[dict[str, object]] = []
    active_keys = active_keys or set()
    current_minute = now.replace(second=0, microsecond=0)

    for candidate in candidates:
        if candidate.get("key") in active_keys:
            continue
        if not candidate.get("enabled", True):
            continue

        due_at = due_time_for_candidate(candidate, now=current_minute)
        if due_at is None:
            continue

        due_candidates.append({**candidate, "scheduled_for": due_at})
        if len(due_candidates) >= max_new_runs:
            break

    return due_candidates


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


def parse_deprecated_since(description: str) -> datetime | None:
    if not description.startswith("Deprecated since "):
        return None
    try:
        return datetime.strptime(description.replace("Deprecated since ", "").strip(), "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def sanitize_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    value = re.sub(r"[^a-zA-Z0-9._-]", "", hostname.strip().rstrip("."))
    return value[:255] or None


def normalize_mac_address(value: str | None) -> str | None:
    if not value:
        return None
    stripped = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(stripped) != 12:
        return None
    return ":".join(stripped[index : index + 2] for index in range(0, 12, 2)).lower()


def ipaddress_has_mac_custom_field() -> bool:
    from django.contrib.contenttypes.models import ContentType
    from extras.models import CustomField
    from ipam.models import IPAddress

    content_type = ContentType.objects.get_for_model(IPAddress)
    return CustomField.objects.filter(name="MacAddress", object_types=content_type).exists()


def discovery_maps(discovery_results) -> tuple[set[object], dict[str, str], dict[str, str]]:
    responsive = set()
    hostnames = {}
    mac_addresses = {}
    for result in discovery_results or []:
        if not result.get("is_active"):
            continue
        host = str(ip_address(str(result["ip"]).split("/", 1)[0]))
        responsive.add(ip_address(host))
        hostname = sanitize_hostname(result.get("hostname")) or sanitize_hostname(reverse_dns(host))
        mac_address = normalize_mac_address(result.get("mac_address"))
        if hostname:
            hostnames[host] = hostname
        if mac_address:
            mac_addresses[host] = mac_address
    return responsive, hostnames, mac_addresses


def apply_scan_observations(
    policy,
    discovery_results,
    *,
    global_settings,
    now=None,
    dry_run: bool = False,
) -> dict[str, object]:
    from ipam.models import IPAddress

    now = now or django_timezone.now()
    network = ip_range_to_network(policy.target_range.start_address, policy.target_range.end_address)
    responsive, hostnames, mac_addresses = discovery_maps(discovery_results)
    deprecated_cutoff = now - timedelta(days=global_settings.deprecated_last_seen_days)
    free_cutoff_days = global_settings.deprecated_grace_period_days
    can_write_mac = ipaddress_has_mac_custom_field()
    summary = {
        "observed_hosts": 0,
        "responsive_hosts": len(responsive),
        "updated": 0,
        "created": 0,
        "planned_creates": [],
        "planned_active_updates": [],
        "planned_deprecations": [],
        "planned_frees": [],
        "skipped_protected": 0,
        "warnings": [],
    }
    if mac_addresses and not can_write_mac:
        summary["warnings"].append("MacAddress custom field is missing for ipam.ipaddress; skipped MAC writes.")

    existing_by_host = {}
    for ip_obj in IPAddress.objects.filter(vrf_id=policy.target_range.vrf_id):
        host = ip_address(str(ip_obj.address).split("/", 1)[0])
        if host not in network:
            continue
        existing_by_host[host] = ip_obj

    for host, ip_obj in existing_by_host.items():
        summary["observed_hosts"] += 1
        is_responsive = host in responsive

        if ip_obj.status not in MANAGED_IP_STATUSES:
            summary["skipped_protected"] += 1
            continue

        update_fields = []
        if is_responsive:
            if ip_obj.status != "active":
                ip_obj.status = "active"
                update_fields.append("status")
            hostname = hostnames.get(str(host))
            if hostname and not ip_obj.dns_name:
                ip_obj.dns_name = hostname
                update_fields.append("dns_name")
            mac_address = mac_addresses.get(str(host))
            if mac_address and can_write_mac and not (ip_obj.custom_field_data or {}).get("MacAddress"):
                ip_obj.custom_field_data = {**(ip_obj.custom_field_data or {}), "MacAddress": mac_address}
                update_fields.append("custom_field_data")
            if ip_obj.description.startswith("Deprecated since "):
                ip_obj.description = ""
                update_fields.append("description")
            if update_fields:
                summary["planned_active_updates"].append(str(host))
        elif ip_obj.status == "active":
            if ip_obj.last_updated and ip_obj.last_updated <= deprecated_cutoff:
                ip_obj.status = "deprecated"
                ip_obj.description = f"Deprecated since {now.date().isoformat()}"
                update_fields.extend(("status", "description"))
                summary["planned_deprecations"].append(str(host))
        elif ip_obj.status == "deprecated":
            deprecated_since = parse_deprecated_since(ip_obj.description)
            if deprecated_since and (now.date() - deprecated_since.date()).days >= free_cutoff_days:
                ip_obj.status = "free"
                ip_obj.description = ""
                ip_obj.dns_name = ""
                update_fields.extend(("status", "description", "dns_name"))
                summary["planned_frees"].append(str(host))
        elif ip_obj.status == "free" and (ip_obj.description or ip_obj.dns_name):
            ip_obj.description = ""
            ip_obj.dns_name = ""
            update_fields.extend(("description", "dns_name"))

        if update_fields:
            if not dry_run:
                ip_obj.full_clean()
                ip_obj.save(update_fields=(*update_fields, "last_updated"))
            summary["updated"] += 1

    missing_hosts = sorted(responsive - set(existing_by_host), key=int)
    for host in missing_hosts:
        if host not in network:
            continue
        address = f"{host}/{network.prefixlen}"
        summary["planned_creates"].append(str(host))
        if dry_run:
            continue
        ip_obj = IPAddress(
            address=address,
            vrf=policy.target_range.vrf,
            tenant=policy.target_range.tenant,
            status="active",
            dns_name=hostnames.get(str(host), ""),
        )
        mac_address = mac_addresses.get(str(host))
        if mac_address and can_write_mac:
            ip_obj.custom_field_data = {"MacAddress": mac_address}
        ip_obj.full_clean()
        ip_obj.save()
        summary["created"] += 1

    summary["observed_hosts"] = max(summary["observed_hosts"], len(responsive))
    return summary


def iter_policy_scan_hosts(policy):
    start = ip_address(str(policy.scan_start).split("/", 1)[0])
    end = ip_address(str(policy.scan_end).split("/", 1)[0])
    current = int(start)
    last = int(end)
    while current <= last:
        yield str(IPv4Address(current))
        current += 1


def count_policy_scan_hosts(policy) -> int:
    start = ip_address(str(policy.scan_start).split("/", 1)[0])
    end = ip_address(str(policy.scan_end).split("/", 1)[0])
    return int(end) - int(start) + 1


def reverse_dns(host: str) -> str | None:
    try:
        return socket.gethostbyaddr(host)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


class DiscoveryError(RuntimeError):
    pass


def effective_discovery_mode(policy, global_settings) -> str:
    mode = getattr(policy, "discovery_mode", "inherit") or "inherit"
    if mode == "inherit":
        mode = getattr(global_settings, "default_discovery_mode", "routed") or "routed"
    if mode == "auto":
        return "routed"
    if mode not in {"routed", "local_l2"}:
        raise ValueError(f"Unsupported discovery mode '{mode}'.")
    return mode


def nmap_targets_for_policy(policy) -> list[str]:
    network = ip_range_to_network(policy.target_range.start_address, policy.target_range.end_address)
    start = ip_address(str(policy.scan_start or network.network_address).split("/", 1)[0])
    end = ip_address(str(policy.scan_end or network.broadcast_address).split("/", 1)[0])
    if start == network.network_address and end == network.broadcast_address:
        return [str(network)]
    return list(iter_policy_scan_hosts(policy))


def build_nmap_command(policy, global_settings) -> tuple[list[str], str, list[str]]:
    mode = effective_discovery_mode(policy, global_settings)
    targets = nmap_targets_for_policy(policy)
    if mode == "local_l2":
        return ["nmap", "-sn", "-PR", "-n", *targets, "-oX", "-"], mode, targets
    probes = [*NMAP_ROUTED_PROBES]
    if os.geteuid() == 0:
        probes.extend(NMAP_ROOT_ONLY_PROBES)
    return [
        "nmap",
        "-sn",
        "-n",
        *probes,
        "--max-retries",
        "1",
        "--host-timeout",
        "5s",
        *targets,
        "-oX",
        "-",
    ], mode, targets


def parse_nmap_xml(xml_text: str) -> list[dict[str, object]]:
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise DiscoveryError(f"Malformed nmap XML: {exc}") from exc

    results = []
    for host in root.findall("host"):
        status = host.find("status")
        is_active = status is not None and status.get("state") == "up"
        address = None
        mac_address = None
        vendor = None
        for item in host.findall("address"):
            if item.get("addrtype") == "ipv4":
                address = item.get("addr")
            elif item.get("addrtype") == "mac":
                mac_address = normalize_mac_address(item.get("addr"))
                vendor = item.get("vendor")
        if not address:
            continue
        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = sanitize_hostname(hostname_node.get("name"))
        results.append(
            {
                "ip": address,
                "is_active": is_active,
                "sources": ["nmap"] if is_active else [],
                "hostname": hostname,
                "mac_address": mac_address,
                "vendor": vendor,
                "raw": {"state": status.get("state") if status is not None else None},
            }
        )
    return results


def scan_range(policy, *, global_settings) -> dict[str, object]:
    command, mode, targets = build_nmap_command(policy, global_settings)
    target_count = count_policy_scan_hosts(policy)
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "nmap failed").strip()
        raise DiscoveryError(message[:500])

    warnings = [line.strip() for line in completed.stderr.splitlines() if line.strip()]
    results = parse_nmap_xml(completed.stdout)
    responsive_hosts = sorted(
        [result["ip"] for result in results if result.get("is_active")],
        key=lambda value: int(ip_address(value)),
    )
    hostnames = {
        result["ip"]: result["hostname"]
        for result in results
        if result.get("is_active") and result.get("hostname")
    }
    for host in responsive_hosts:
        if host not in hostnames:
            hostname = sanitize_hostname(reverse_dns(host))
            if hostname:
                hostnames[host] = hostname

    return {
        "adapter": "nmap",
        "discovery_mode": mode,
        "command": command,
        "targets": targets,
        "results": results,
        "scanned_hosts": target_count,
        "nmap_reported_hosts": len(results),
        "responsive_hosts": responsive_hosts,
        "hostnames": hostnames,
        "mac_addresses": {
            result["ip"]: result["mac_address"]
            for result in results
            if result.get("is_active") and result.get("mac_address")
        },
        "errors": [],
        "warnings": warnings[:SCAN_ERROR_LIMIT],
    }


def build_scan_request(
    *,
    scan_run_id: int,
    target_cidr: str,
    scheduled_for: datetime | None = None,
) -> dict[str, object]:
    return {
        "accepted": True,
        "mode": "nmap",
        "scan_run_id": scan_run_id,
        "target_cidr": target_cidr if "-" in target_cidr else normalize_cidr(target_cidr),
        "scheduled_for": scheduled_for.isoformat() if scheduled_for else None,
        "message": "nmap discovery request accepted.",
    }


def minutes_to_interval_parts(minutes: int | None) -> tuple[int | None, str]:
    if not minutes:
        return None, "minutes"
    for unit, factor in (("weeks", 10080), ("days", 1440), ("hours", 60), ("minutes", 1)):
        if minutes % factor == 0:
            return minutes // factor, unit
    return minutes, "minutes"


def interval_parts_to_minutes(value: int | None, unit: str | None) -> int | None:
    if value in (None, ""):
        return None
    factor = {
        "minutes": 1,
        "hours": 60,
        "days": 1440,
        "weeks": 10080,
    }.get(unit or "minutes")
    if factor is None:
        raise ValueError(f"Unsupported interval unit '{unit}'.")
    if int(value) < 1:
        raise ValueError("Interval value must be at least 1.")
    return int(value) * factor


def as_ipv4_address(value: str | None, *, field_name: str) -> IPv4Address | None:
    if not value:
        return None
    parsed = ip_address(value)
    if parsed.version != 4:
        raise ValueError(f"{field_name} must be an IPv4 address.")
    return parsed


def preview_range_policy_initialization(policy, gateway) -> list[dict[str, object]]:
    from ipam.models import IPAddress

    if not policy.target_range_id:
        raise ValueError("The policy has no target IP range.")
    network = ip_range_to_network(policy.target_range.start_address, policy.target_range.end_address)
    gateway = as_ipv4_address(str(gateway), field_name="Gateway")
    if gateway not in network:
        raise ValueError(f"Gateway must be inside {network}.")
    if gateway in (network.network_address, network.broadcast_address):
        raise ValueError("Gateway must differ from the network and broadcast addresses.")

    desired = (
        (network.network_address, "reserved", "Network"),
        (network.broadcast_address, "reserved", "Broadcast"),
        (gateway, "gateway", "Gateway"),
    )
    return [
        {
            "address": f"{address}/{network.prefixlen}",
            "status": status,
            "purpose": purpose,
            "exists": IPAddress.objects.filter(
                address__net_host=str(address),
                vrf_id=policy.target_range.vrf_id,
            ).exists(),
        }
        for address, status, purpose in desired
    ]


@transaction.atomic
def initialize_range_policy(policy, gateway) -> int:
    from ipam.models import IPAddress, IPRange

    policy.target_range = IPRange.objects.select_for_update().get(pk=policy.target_range_id)
    preview = preview_range_policy_initialization(policy, gateway)
    created = 0
    for item in preview:
        if item["exists"]:
            continue
        ip_address_object = IPAddress(
            address=item["address"],
            vrf=policy.target_range.vrf,
            tenant=policy.target_range.tenant,
            status=item["status"],
            description=item["purpose"],
        )
        ip_address_object.full_clean()
        ip_address_object.save()
        created += 1
    return created


if __name__ == "__main__":
    assert normalize_cidr("192.0.2.13/24") == "192.0.2.0/24"
    assert str(ip_range_to_network("192.0.2.0/30", "192.0.2.3/30")) == "192.0.2.0/30"
    assert parse_cron_expressions("0 * * * *\n0 * * * *\n*/15 * * * *") == ["0 * * * *", "*/15 * * * *"]
    assert classify_scan_result(observed_hosts=10, responsive_hosts=2, error_count=0) == "responsive"
    assert classify_scan_result(observed_hosts=10, responsive_hosts=0, error_count=0) == "quiet"
    assert classify_scan_result(observed_hosts=0, responsive_hosts=0, error_count=1) == "failed"
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    due = select_due_candidates(
        [
            {"key": 1, "enabled": True, "schedule_mode": "interval", "interval_minutes": 60, "last_scheduled_for": None},
            {"key": 2, "enabled": True, "schedule_mode": "interval", "interval_minutes": 60, "last_scheduled_for": now},
            {
                "key": 3,
                "enabled": True,
                "schedule_mode": "cron",
                "cron_expressions": "0 * * * *",
                "last_scheduled_for": now - timedelta(hours=2),
            },
        ],
        now=now,
        active_keys={1},
        max_new_runs=1,
    )
    assert [item["key"] for item in due] == [3]
