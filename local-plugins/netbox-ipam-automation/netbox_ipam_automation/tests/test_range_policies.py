from datetime import datetime, timezone
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from ipam.models import IPAddress, IPRange

from netbox_ipam_automation.forms import GlobalSettingsForm
from netbox_ipam_automation.jobs import create_due_scheduled_scan_runs
from netbox_ipam_automation.models import GlobalSettings, RangePolicy, ScanRun
from netbox_ipam_automation.services import (
    due_time_for_cron,
    initialize_range_policy,
    parse_cron_expressions,
)


class RangePolicyTest(TestCase):
    def setUp(self):
        self.ip_range = IPRange(
            start_address="198.51.100.0/30",
            end_address="198.51.100.3/30",
            status="active",
        )
        self.ip_range.full_clean()
        self.ip_range.save()

    def test_full_range_includes_network_and_broadcast(self):
        policy = RangePolicy(name="Production range", target_range=self.ip_range)
        policy.full_clean()

        self.assertEqual(policy.slug, "production-range")
        self.assertEqual(policy.scan_start, "198.51.100.0")
        self.assertEqual(policy.scan_end, "198.51.100.3")
        self.assertEqual(policy.target_cidr, "198.51.100.0-198.51.100.3")

    def test_rejects_scan_bounds_outside_range(self):
        policy = RangePolicy(
            name="Invalid range",
            target_range=self.ip_range,
            scan_start="198.51.99.255",
            scan_end="198.51.100.2",
        )

        with self.assertRaises(ValidationError):
            policy.full_clean()

    def test_initialization_creates_only_missing_special_addresses(self):
        policy = RangePolicy(name="Initialized range", target_range=self.ip_range)
        policy.full_clean()
        policy.save()
        existing = IPAddress(address="198.51.100.0/30", status="active")
        existing.full_clean()
        existing.save()

        created = initialize_range_policy(policy, "198.51.100.1")

        self.assertEqual(created, 2)
        existing.refresh_from_db()
        self.assertEqual(existing.status, "active")
        self.assertEqual(
            {(str(address), status) for address, status in IPAddress.objects.values_list("address", "status")},
            {
                ("198.51.100.0/30", "active"),
                ("198.51.100.1/30", "gateway"),
                ("198.51.100.3/30", "reserved"),
            },
        )


class SchedulingTest(TestCase):
    def test_multiple_cron_expressions_are_validated_and_deduplicated(self):
        self.assertEqual(
            parse_cron_expressions("0,30 * * * *\n0,30 * * * *\n15 * * * *"),
            ["0,30 * * * *", "15 * * * *"],
        )
        with self.assertRaises(ValueError):
            parse_cron_expressions("0 * * *")

    def test_cron_fires_once_per_matching_minute(self):
        now = datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)
        due = due_time_for_cron("0,30 * * * *\n30 * * * *", now=now)

        self.assertEqual(due, now.replace(second=0, microsecond=0))
        self.assertIsNone(
            due_time_for_cron(
                "0,30 * * * *",
                now=now,
                last_scheduled_for=now.replace(second=0, microsecond=0),
            )
        )

    def test_global_cron_mode_does_not_clear_interval_fallback(self):
        settings = GlobalSettings(
            schedule_mode="cron",
            default_interval_minutes=60,
            default_cron_expressions="0 * * * *",
        )
        settings.full_clean()
        self.assertEqual(settings.default_interval_minutes, 60)

        form = GlobalSettingsForm(
            data={
                "name": "default",
                "enabled": True,
                "schedule_mode": "cron",
                "default_cron_expressions": "0 * * * *",
                "max_concurrent_scans": 1,
            },
            instance=settings,
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save(commit=False).default_interval_minutes, 60)

    @patch("netbox_ipam_automation.jobs.enqueue_scan_run")
    def test_scheduler_does_not_create_duplicate_cron_runs(self, enqueue_scan_run):
        ip_range = IPRange(
            start_address="203.0.113.0/30",
            end_address="203.0.113.3/30",
            status="active",
        )
        ip_range.full_clean()
        ip_range.save()
        GlobalSettings.objects.create(
            schedule_mode="cron",
            default_cron_expressions="30 * * * *\n30 * * * *",
            max_concurrent_scans=10,
        )
        policy = RangePolicy(name="Cron range", target_range=ip_range)
        policy.full_clean()
        policy.save()
        now = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)

        self.assertEqual(create_due_scheduled_scan_runs(now=now)["created"], 1)
        self.assertEqual(create_due_scheduled_scan_runs(now=now)["created"], 0)
        self.assertEqual(ScanRun.objects.filter(policy=policy).count(), 1)
        enqueue_scan_run.assert_called_once()
