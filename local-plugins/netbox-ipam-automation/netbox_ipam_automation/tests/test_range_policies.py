from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from ipam.models import IPAddress, IPRange

from netbox_ipam_automation.forms import GlobalSettingsForm, RangePolicyForm
from netbox_ipam_automation.jobs import create_due_scheduled_scan_runs
from netbox_ipam_automation.models import GlobalSettings, RangePolicy, ScanRun
from netbox_ipam_automation.services import (
    apply_scan_observations,
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

    def test_form_explains_address_and_schedule_inputs(self):
        form = RangePolicyForm()

        self.assertEqual(form.fields["enabled"].label, "Schedule enabled")
        self.assertEqual(dict(form.fields["schedule_mode"].choices)["inherit"], "Global default")
        self.assertIn("auto-select the first address", form.fields["scan_start"].help_text)
        self.assertIn("one five-field cron expression per line", form.fields["cron_expressions"].help_text)

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
            default_scan_interval_minutes=60,
            default_cron_expressions="0 * * * *",
        )
        settings.full_clean()
        self.assertEqual(settings.default_scan_interval_minutes, 60)

        form = GlobalSettingsForm(
            data={
                "name": "default",
                "enabled": True,
                "schedule_mode": "cron",
                "default_cron_expressions": "0 * * * *",
                "max_concurrent_scans": 1,
                "deprecated_last_seen_days": 2,
                "deprecated_grace_period_days": 14,
            },
            instance=settings,
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save(commit=False).default_scan_interval_minutes, 60)

    def test_global_deprecation_defaults_are_validated(self):
        settings = GlobalSettings(deprecated_last_seen_days=2, deprecated_grace_period_days=14)
        settings.full_clean()

        with self.assertRaises(ValidationError):
            GlobalSettings(deprecated_last_seen_days=0, deprecated_grace_period_days=14).full_clean()

        with self.assertRaises(ValidationError):
            GlobalSettings(deprecated_last_seen_days=2, deprecated_grace_period_days=0).full_clean()

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


class ScanStatusPolicyTest(TestCase):
    def setUp(self):
        self.ip_range = IPRange(
            start_address="192.0.2.0/29",
            end_address="192.0.2.7/29",
            status="active",
        )
        self.ip_range.full_clean()
        self.ip_range.save()
        self.policy = RangePolicy(name="Scan status policy", target_range=self.ip_range)
        self.policy.full_clean()
        self.policy.save()
        self.settings = GlobalSettings(
            deprecated_last_seen_days=2,
            deprecated_grace_period_days=14,
        )

    def _create_ip(self, address, status, **kwargs):
        ip = IPAddress(address=address, status=status, **kwargs)
        ip.save()
        return ip

    def test_scan_observations_change_only_managed_statuses(self):
        now = datetime(2026, 1, 20, 12, 0, tzinfo=timezone.utc)
        active = self._create_ip("192.0.2.1/29", "active")
        free = self._create_ip("192.0.2.2/29", "free", description="old", dns_name="old.example")
        deprecated = self._create_ip("192.0.2.3/29", "deprecated", description="Deprecated since 2026-01-01")
        reserved = self._create_ip("192.0.2.4/29", "reserved")
        gateway = self._create_ip("192.0.2.5/29", "gateway")
        dhcp = self._create_ip("192.0.2.6/29", "dhcp")
        custom = self._create_ip("192.0.2.7/29", "custom")
        old_seen = now - timedelta(days=3)
        IPAddress.objects.filter(pk=active.pk).update(last_updated=old_seen)

        summary = apply_scan_observations(
            self.policy,
            responsive_hosts={"192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"},
            global_settings=self.settings,
            now=now,
        )

        active.refresh_from_db()
        free.refresh_from_db()
        deprecated.refresh_from_db()
        reserved.refresh_from_db()
        gateway.refresh_from_db()
        dhcp.refresh_from_db()
        custom.refresh_from_db()

        self.assertEqual(active.status, "deprecated")
        self.assertEqual(free.status, "active")
        self.assertEqual(free.description, "old")
        self.assertEqual(deprecated.status, "free")
        self.assertEqual(reserved.status, "reserved")
        self.assertEqual(gateway.status, "gateway")
        self.assertEqual(dhcp.status, "dhcp")
        self.assertEqual(custom.status, "custom")
        self.assertEqual(summary["skipped_protected"], 4)
