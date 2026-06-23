from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

from core.models import Job
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from ipam.models import IPAddress, IPRange

from netbox_ipam_automation.forms import GlobalSettingsForm, RangePolicyForm
from netbox_ipam_automation.jobs import (
    ExecuteScanRunJob,
    ScheduleScanRunsJob,
    create_due_scheduled_scan_runs,
    execute_scan_run,
    prune_scan_run_history,
    reconcile_stale_scan_runs,
)
from netbox_ipam_automation.models import GlobalSettings, RangePolicy, ScanRun
from netbox_ipam_automation.services import (
    DiscoveryError,
    apply_scan_observations,
    build_nmap_command,
    due_time_for_cron,
    initialize_range_policy,
    parse_nmap_xml,
    parse_cron_expressions,
    scan_range,
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
        self.assertIn("local L2", form.fields["discovery_mode"].help_text)

    def test_discovery_mode_defaults_to_inherit(self):
        policy = RangePolicy(name="Discovery mode", target_range=self.ip_range)
        policy.full_clean()

        self.assertEqual(policy.discovery_mode, RangePolicy.DiscoveryModeChoices.INHERIT)

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
                "max_tasks_per_template": 100,
                "deprecated_last_seen_days": 2,
                "deprecated_grace_period_days": 14,
                "default_discovery_mode": "routed",
            },
            instance=settings,
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save(commit=False).default_scan_interval_minutes, 60)

    def test_global_deprecation_defaults_are_validated(self):
        settings = GlobalSettings(deprecated_last_seen_days=2, deprecated_grace_period_days=14)
        settings.full_clean()
        self.assertEqual(settings.max_tasks_per_template, 100)

        with self.assertRaises(ValidationError):
            GlobalSettings(deprecated_last_seen_days=0, deprecated_grace_period_days=14).full_clean()

        with self.assertRaises(ValidationError):
            GlobalSettings(deprecated_last_seen_days=2, deprecated_grace_period_days=0).full_clean()

        with self.assertRaises(ValidationError):
            GlobalSettings(max_tasks_per_template=0).full_clean()

    @patch("netbox_ipam_automation.jobs.enqueue_scan_run")
    def test_global_default_schedules_active_ranges_without_policies(self, enqueue_scan_run):
        active_range = IPRange(
            start_address="192.0.2.0/30",
            end_address="192.0.2.3/30",
            status="active",
        )
        active_range.full_clean()
        active_range.save()
        reserved_range = IPRange(
            start_address="192.0.2.4/30",
            end_address="192.0.2.7/30",
            status="reserved",
        )
        reserved_range.full_clean()
        reserved_range.save()
        GlobalSettings.objects.create(
            scan_all_active_ranges=True,
            default_scan_interval_minutes=60,
            max_concurrent_scans=10,
        )

        self.assertEqual(create_due_scheduled_scan_runs(now=datetime(2026, 1, 1, tzinfo=timezone.utc))["created"], 1)
        scan_run = ScanRun.objects.get()
        self.assertIsNone(scan_run.policy)
        self.assertEqual(scan_run.target_range, active_range)
        self.assertEqual(scan_run.target_cidr, "192.0.2.0-192.0.2.3")
        enqueue_scan_run.assert_called_once_with(scan_run)

    @patch("netbox_ipam_automation.jobs.enqueue_scan_run")
    def test_global_default_is_opt_in_and_policy_can_disable_a_range(self, enqueue_scan_run):
        target_range = IPRange(
            start_address="192.0.2.0/30",
            end_address="192.0.2.3/30",
            status="active",
        )
        target_range.full_clean()
        target_range.save()
        settings = GlobalSettings.objects.create(max_concurrent_scans=10)

        self.assertEqual(create_due_scheduled_scan_runs()["created"], 0)

        settings.scan_all_active_ranges = True
        settings.save()
        RangePolicy.objects.create(name="Do not scan", target_range=target_range, enabled=False)
        self.assertEqual(create_due_scheduled_scan_runs()["created"], 0)
        enqueue_scan_run.assert_not_called()

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


class SchedulerRecoveryTest(TestCase):
    def _scan_run(self):
        return ScanRun.objects.create(status=ScanRun.StatusChoices.QUEUED)

    def _job(self, scan_run=None, *, status="running", name="Execute IPAM scan run", error=""):
        return Job.objects.create(
            object=scan_run,
            name=name,
            status=status,
            error=error,
            interval=1 if scan_run is None else None,
            job_id=uuid4(),
            queue_name="default",
        )

    @override_settings(RQ_DEFAULT_TIMEOUT=300)
    def test_orphaned_scan_run_without_job_is_failed_after_timeout(self):
        now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        scan_run = self._scan_run()
        ScanRun.objects.filter(pk=scan_run.pk).update(last_updated=now - timedelta(minutes=6))

        self.assertEqual(reconcile_stale_scan_runs(now=now), 1)
        scan_run.refresh_from_db()
        self.assertEqual(scan_run.status, ScanRun.StatusChoices.FAILED)
        self.assertEqual(scan_run.classification, ScanRun.ClassificationChoices.FAILED)
        self.assertEqual(scan_run.error_count, 1)
        self.assertEqual(scan_run.finished_at, now)
        self.assertEqual(scan_run.summary["errors"][0]["error"], "OrphanedScanRun")

    def test_terminal_execution_job_is_failed_but_active_rq_job_is_preserved(self):
        now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        failed_scan = self._scan_run()
        active_scan = self._scan_run()
        self._job(failed_scan, status="errored", error="worker error")
        self._job(active_scan, status="running")
        ScanRun.objects.filter(pk=active_scan.pk).update(last_updated=now - timedelta(hours=1))

        with patch("netbox_ipam_automation.jobs.rq_job_is_active", return_value=True):
            self.assertEqual(reconcile_stale_scan_runs(now=now), 1)

        failed_scan.refresh_from_db()
        active_scan.refresh_from_db()
        self.assertEqual(failed_scan.status, ScanRun.StatusChoices.FAILED)
        self.assertEqual(active_scan.status, ScanRun.StatusChoices.QUEUED)

    @patch("netbox_ipam_automation.jobs.enqueue_scan_run")
    def test_recovery_frees_capacity_for_implicit_scan(self, enqueue_scan_run):
        now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        stale_scan = self._scan_run()
        ScanRun.objects.filter(pk=stale_scan.pk).update(last_updated=now - timedelta(hours=1))
        target_range = IPRange(
            start_address="192.0.2.0/30",
            end_address="192.0.2.3/30",
            status="active",
        )
        target_range.full_clean()
        target_range.save()
        GlobalSettings.objects.create(scan_all_active_ranges=True, max_concurrent_scans=1)

        result = create_due_scheduled_scan_runs(now=now)

        stale_scan.refresh_from_db()
        self.assertEqual(stale_scan.status, ScanRun.StatusChoices.FAILED)
        self.assertEqual(result, {"created": 1, "active": 0})
        enqueue_scan_run.assert_called_once()

    def test_system_job_replaces_stale_rq_entry_without_duplicating_healthy_schedule(self):
        stale_job = self._job(name=ScheduleScanRunsJob.name, status="scheduled")
        with (
            patch("netbox_ipam_automation.jobs.rq_job_is_active", return_value=False),
            patch.object(ScheduleScanRunsJob, "enqueue", return_value="replacement") as enqueue,
        ):
            self.assertEqual(ScheduleScanRunsJob.enqueue_once(interval=1), "replacement")
            enqueue.assert_called_once()
        stale_job.refresh_from_db()
        self.assertEqual(stale_job.status, "errored")

        healthy_job = self._job(name=ScheduleScanRunsJob.name, status="scheduled")
        with (
            patch("netbox_ipam_automation.jobs.rq_job_is_active", return_value=True),
            patch.object(ScheduleScanRunsJob, "enqueue") as enqueue,
        ):
            self.assertEqual(ScheduleScanRunsJob.enqueue_once(interval=1), healthy_job)
            enqueue.assert_not_called()

    def test_unexpected_execute_error_fails_scan_run_and_core_job(self):
        scan_run = self._scan_run()
        core_job = self._job(scan_run, status="pending")

        with patch("netbox_ipam_automation.jobs.execute_scan_run", side_effect=RuntimeError("unexpected")):
            ExecuteScanRunJob.handle(core_job)

        scan_run.refresh_from_db()
        core_job.refresh_from_db()
        self.assertEqual(scan_run.status, ScanRun.StatusChoices.FAILED)
        self.assertEqual(core_job.status, "errored")


class ScanRunRetentionTest(TestCase):
    def _range(self, start, end):
        ip_range = IPRange(start_address=start, end_address=end, status="active")
        ip_range.full_clean()
        ip_range.save()
        return ip_range

    def _terminal_run(self, **kwargs):
        return ScanRun.objects.create(status=ScanRun.StatusChoices.COMPLETED, **kwargs)

    def test_prunes_combined_netid_history_and_related_job_but_keeps_active_runs(self):
        target_range = self._range("192.0.2.0/30", "192.0.2.3/30")
        other_range = self._range("192.0.2.4/30", "192.0.2.7/30")
        policy = RangePolicy.objects.create(name="Retention policy", target_range=target_range)
        oldest = self._terminal_run(policy=policy, target_cidr="192.0.2.0-192.0.2.3")
        self._terminal_run(target_range=target_range, target_cidr="192.0.2.0-192.0.2.3")
        self._terminal_run(target_range=target_range, target_cidr="192.0.2.0-192.0.2.3")
        active = ScanRun.objects.create(target_range=target_range, status=ScanRun.StatusChoices.RUNNING)
        self._terminal_run(target_range=other_range, target_cidr="192.0.2.4-192.0.2.7")
        self._terminal_run(target_range=other_range, target_cidr="192.0.2.4-192.0.2.7")
        related_job = Job.objects.create(
            object=oldest,
            name="Execute IPAM scan run",
            status="completed",
            job_id=uuid4(),
            queue_name="default",
            log_entries=[{"level": "info", "message": "old log"}],
        )
        highest_id = ScanRun.objects.order_by("-pk").values_list("pk", flat=True).first()

        self.assertEqual(prune_scan_run_history(max_tasks=2), 1)

        self.assertFalse(ScanRun.objects.filter(pk=oldest.pk).exists())
        self.assertFalse(Job.objects.filter(pk=related_job.pk).exists())
        self.assertTrue(ScanRun.objects.filter(pk=active.pk).exists())
        self.assertEqual(ScanRun.objects.filter(target_range=target_range, status="completed").count(), 2)
        self.assertEqual(ScanRun.objects.filter(target_range=other_range, status="completed").count(), 2)
        self.assertGreater(self._terminal_run(target_range=target_range).pk, highest_id)

    def test_target_cidr_is_used_when_policy_and_range_are_missing(self):
        runs = [self._terminal_run(target_cidr="198.51.100.0-198.51.100.3") for _ in range(3)]

        self.assertEqual(prune_scan_run_history(max_tasks=2), 1)
        self.assertFalse(ScanRun.objects.filter(pk=runs[0].pk).exists())
        self.assertEqual(ScanRun.objects.filter(pk__in=[runs[1].pk, runs[2].pk]).count(), 2)

    def test_scheduler_prunes_when_scan_scheduling_is_disabled(self):
        target_range = self._range("203.0.113.0/30", "203.0.113.3/30")
        GlobalSettings.objects.create(enabled=False, max_tasks_per_template=1)
        self._terminal_run(target_range=target_range)
        self._terminal_run(target_range=target_range)
        core_job = Job.objects.create(
            name=ScheduleScanRunsJob.name,
            status="running",
            job_id=uuid4(),
            queue_name="default",
        )

        ScheduleScanRunsJob(core_job).run()

        self.assertEqual(ScanRun.objects.filter(target_range=target_range).count(), 1)


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
            [
                {"ip": "192.0.2.2", "is_active": True, "hostname": None, "mac_address": None},
                {"ip": "192.0.2.4", "is_active": True, "hostname": None, "mac_address": None},
                {"ip": "192.0.2.5", "is_active": True, "hostname": None, "mac_address": None},
                {"ip": "192.0.2.6", "is_active": True, "hostname": None, "mac_address": None},
                {"ip": "192.0.2.7", "is_active": True, "hostname": None, "mac_address": None},
            ],
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

    def test_responsive_hostname_updates_only_managed_status(self):
        managed = self._create_ip("192.0.2.1/29", "free")
        protected = self._create_ip("192.0.2.2/29", "reserved")

        summary = apply_scan_observations(
            self.policy,
            [
                {"ip": "192.0.2.1", "is_active": True, "hostname": "managed.example", "mac_address": None},
                {"ip": "192.0.2.2", "is_active": True, "hostname": "protected.example", "mac_address": None},
            ],
            global_settings=self.settings,
        )

        managed.refresh_from_db()
        protected.refresh_from_db()
        self.assertEqual(managed.status, "active")
        self.assertEqual(managed.dns_name, "managed.example")
        self.assertEqual(protected.status, "reserved")
        self.assertEqual(protected.dns_name, "")
        self.assertEqual(summary["skipped_protected"], 1)


class ScannerAdapterTest(TestCase):
    def setUp(self):
        self.ip_range = IPRange(
            start_address="203.0.113.0/30",
            end_address="203.0.113.3/30",
            status="active",
        )
        self.ip_range.full_clean()
        self.ip_range.save()
        self.policy = RangePolicy(name="Scanner policy", target_range=self.ip_range)
        self.policy.full_clean()
        self.policy.save()
        self.settings = GlobalSettings(
            default_discovery_mode="routed",
            deprecated_last_seen_days=2,
            deprecated_grace_period_days=14,
        )
        self.settings.full_clean()

    def test_parse_nmap_xml_normalizes_hosts(self):
        results = parse_nmap_xml(
            """<?xml version="1.0"?>
            <nmaprun>
              <host><status state="up"/><address addr="203.0.113.1" addrtype="ipv4"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Dell Inc."/>
                <hostnames><hostname name="host.example.local"/></hostnames>
              </host>
              <host><status state="down"/><address addr="203.0.113.2" addrtype="ipv4"/></host>
            </nmaprun>"""
        )

        self.assertEqual(results[0]["ip"], "203.0.113.1")
        self.assertTrue(results[0]["is_active"])
        self.assertEqual(results[0]["hostname"], "host.example.local")
        self.assertEqual(results[0]["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(results[0]["vendor"], "Dell Inc.")
        self.assertFalse(results[1]["is_active"])

        with self.assertRaises(DiscoveryError):
            parse_nmap_xml("<nmaprun>")

    def test_discovery_mode_builds_expected_commands(self):
        with patch("netbox_ipam_automation.services.os.geteuid", return_value=999):
            command, mode, _ = build_nmap_command(self.policy, self.settings)
        self.assertEqual(mode, "routed")
        self.assertIn("-PE", command)
        self.assertIn("-PS22,80,443,445,3389", command)
        self.assertNotIn("-PU53,161", command)
        self.assertIn("203.0.113.0/30", command)

        with patch("netbox_ipam_automation.services.os.geteuid", return_value=0):
            command, _, _ = build_nmap_command(self.policy, self.settings)
        self.assertIn("-PU53,161", command)

        self.policy.discovery_mode = "local_l2"
        command, mode, _ = build_nmap_command(self.policy, self.settings)
        self.assertEqual(mode, "local_l2")
        self.assertIn("-PR", command)

        self.policy.discovery_mode = "inherit"
        self.settings.default_discovery_mode = "auto"
        _, mode, _ = build_nmap_command(self.policy, self.settings)
        self.assertEqual(mode, "routed")

    def test_scan_range_reports_responsive_hosts_from_nmap_xml(self):
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '<nmaprun><host><status state="up"/><address addr="203.0.113.1" addrtype="ipv4"/></host></nmaprun>',
                "stderr": "",
            },
        )()

        with (
            patch("netbox_ipam_automation.services.subprocess.run", return_value=completed),
            patch("netbox_ipam_automation.services.reverse_dns", return_value=None),
        ):
            result = scan_range(self.policy, global_settings=self.settings)

        self.assertEqual(result["adapter"], "nmap")
        self.assertEqual(result["discovery_mode"], "routed")
        self.assertEqual(result["responsive_hosts"], ["203.0.113.1"])

    def test_scan_range_rejects_nmap_failure(self):
        completed = type("Completed", (), {"returncode": 1, "stdout": "", "stderr": "permission denied"})()
        with patch("netbox_ipam_automation.services.subprocess.run", return_value=completed):
            with self.assertRaises(DiscoveryError):
                scan_range(self.policy, global_settings=self.settings)

    @patch("netbox_ipam_automation.jobs.scan_range")
    def test_execute_scan_run_applies_observations_and_writes_summary(self, scan_range_mock):
        GlobalSettings.objects.create(
            deprecated_last_seen_days=2,
            deprecated_grace_period_days=14,
        )
        managed = IPAddress.objects.create(address="203.0.113.1/30", status="free")
        protected = IPAddress.objects.create(address="203.0.113.2/30", status="reserved")
        scan_run = ScanRun.objects.create(policy=self.policy, target_cidr=self.policy.target_cidr)
        scan_range_mock.return_value = {
            "adapter": "nmap",
            "discovery_mode": "routed",
            "command": ["nmap"],
            "scanned_hosts": 4,
            "responsive_hosts": ["203.0.113.1", "203.0.113.2"],
            "results": [
                {"ip": "203.0.113.1", "is_active": True, "hostname": "managed.example", "mac_address": None},
                {"ip": "203.0.113.2", "is_active": True, "hostname": "protected.example", "mac_address": None},
            ],
            "hostnames": {"203.0.113.1": "managed.example", "203.0.113.2": "protected.example"},
            "errors": [{"host": "203.0.113.3", "port": 22, "error": "TimeoutError"}],
            "mac_addresses": {},
        }

        execute_scan_run(scan_run.pk, job_id="test-job")
        scan_run.refresh_from_db()
        managed.refresh_from_db()
        protected.refresh_from_db()

        self.assertEqual(scan_run.status, ScanRun.StatusChoices.COMPLETED)
        self.assertEqual(scan_run.observed_hosts, 2)
        self.assertEqual(scan_run.responsive_hosts, 2)
        self.assertEqual(scan_run.error_count, 0)
        self.assertEqual(scan_run.summary["job_id"], "test-job")
        self.assertEqual(scan_run.summary["updated"], 1)
        self.assertEqual(scan_run.summary["skipped_protected"], 1)
        self.assertEqual(scan_run.summary["responsive_hosts"], ["203.0.113.1", "203.0.113.2"])
        self.assertEqual(managed.status, "active")
        self.assertEqual(managed.dns_name, "managed.example")
        self.assertEqual(protected.status, "reserved")
        self.assertEqual(protected.dns_name, "")

    @patch("netbox_ipam_automation.jobs.scan_range")
    def test_execute_scan_run_without_explicit_policy(self, scan_range_mock):
        GlobalSettings.objects.create()
        managed = IPAddress.objects.create(address="203.0.113.1/30", status="free")
        scan_run = ScanRun.objects.create(target_range=self.ip_range)
        scan_range_mock.return_value = {
            "adapter": "nmap",
            "discovery_mode": "routed",
            "command": ["nmap"],
            "scanned_hosts": 4,
            "responsive_hosts": ["203.0.113.1"],
            "results": [{"ip": "203.0.113.1", "is_active": True, "hostname": None, "mac_address": None}],
            "hostnames": {},
            "errors": [],
            "mac_addresses": {},
        }

        execute_scan_run(scan_run.pk, job_id="implicit-test")
        scan_run.refresh_from_db()
        managed.refresh_from_db()

        implicit_policy = scan_range_mock.call_args.args[0]
        self.assertEqual(implicit_policy.target_range, self.ip_range)
        self.assertEqual((implicit_policy.scan_start, implicit_policy.scan_end), ("203.0.113.0", "203.0.113.3"))
        self.assertEqual(scan_run.target_cidr, "203.0.113.0-203.0.113.3")
        self.assertEqual(managed.status, "active")

    @patch("netbox_ipam_automation.jobs.scan_range")
    def test_dry_run_does_not_mutate_ip_addresses(self, scan_range_mock):
        GlobalSettings.objects.create()
        managed = IPAddress.objects.create(address="203.0.113.1/30", status="free")
        scan_run = ScanRun.objects.create(policy=self.policy, dry_run=True)
        scan_range_mock.return_value = {
            "adapter": "nmap",
            "discovery_mode": "routed",
            "command": ["nmap"],
            "scanned_hosts": 4,
            "responsive_hosts": ["203.0.113.1", "203.0.113.2"],
            "results": [
                {"ip": "203.0.113.1", "is_active": True, "hostname": "managed.example", "mac_address": None},
                {"ip": "203.0.113.2", "is_active": True, "hostname": None, "mac_address": None},
            ],
            "hostnames": {"203.0.113.1": "managed.example"},
            "errors": [],
            "mac_addresses": {},
        }

        execute_scan_run(scan_run.pk, job_id="dry-run")
        scan_run.refresh_from_db()
        managed.refresh_from_db()

        self.assertTrue(scan_run.summary["dry_run"])
        self.assertEqual(scan_run.summary["planned_creates"], ["203.0.113.2"])
        self.assertEqual(managed.status, "free")
        self.assertFalse(IPAddress.objects.filter(address__net_host="203.0.113.2").exists())


class PermissionGateTest(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username="operator", password="password")
        self.admin = user_model.objects.create_superuser(username="admin", password="password")

    def test_global_settings_ui_is_superuser_only(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("plugins:netbox_ipam_automation:globalsettings_list")).status_code, 403)

        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse("plugins:netbox_ipam_automation:globalsettings_list")).status_code, 200)

    def test_non_admin_create_gates_default_to_disabled(self):
        GlobalSettings.objects.create()
        self.client.force_login(self.user)

        self.assertEqual(self.client.get(reverse("plugins:netbox_ipam_automation:rangepolicy_add")).status_code, 403)
        self.assertEqual(self.client.get(reverse("plugins:netbox_ipam_automation:scanrun_add")).status_code, 403)
