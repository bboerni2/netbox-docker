import django_tables2 as tables
from django.utils.timesince import timesince
from netbox.tables import NetBoxTable, columns

from .models import GlobalSettings, RangePolicy, ScanRun


class GlobalSettingsTable(NetBoxTable):
    name = tables.Column(linkify=True)
    default_scan_interval_minutes = tables.Column(verbose_name="Default scan interval")
    deprecated_last_seen_days = tables.Column(verbose_name="Deprecated last seen")
    deprecated_grace_period_days = tables.Column(verbose_name="Deprecated grace period")

    class Meta(NetBoxTable.Meta):
        model = GlobalSettings
        fields = (
            "pk",
            "name",
            "enabled",
            "scan_all_active_ranges",
            "schedule_mode",
            "default_scan_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "max_tasks_per_template",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
            "default_discovery_mode",
            "non_admin_can_create_range_policies",
            "non_admin_can_run_scans",
        )
        default_columns = (
            "name",
            "enabled",
            "scan_all_active_ranges",
            "default_scan_interval_minutes",
            "max_concurrent_scans",
            "max_tasks_per_template",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
            "default_discovery_mode",
        )


class RangePolicyTable(NetBoxTable):
    name = tables.Column(linkify=True)
    enabled = tables.BooleanColumn(verbose_name="Schedule enabled")

    class Meta(NetBoxTable.Meta):
        model = RangePolicy
        fields = (
            "pk",
            "name",
            "slug",
            "target_range",
            "target_cidr",
            "scan_start",
            "scan_end",
            "discovery_mode",
            "enabled",
            "schedule_mode",
            "interval_minutes",
            "cron_expressions",
        )
        default_columns = ("name", "target_range", "scan_start", "scan_end", "discovery_mode", "enabled", "schedule_mode")


class ScanRunTable(NetBoxTable):
    id = tables.Column(linkify=True, verbose_name="Task ID")
    policy = tables.Column(empty_values=(), orderable=False, verbose_name="Task")
    status = columns.ChoiceFieldColumn()
    duration = tables.Column(empty_values=(), orderable=False)

    def render_duration(self, record):
        if not record.started_at:
            return "—"
        end = record.finished_at or record.last_updated
        return timesince(record.started_at, end)

    def render_policy(self, record):
        target = record.policy or record.target_range
        return target if target else "—"

    class Meta(NetBoxTable.Meta):
        model = ScanRun
        fields = (
            "pk",
            "id",
            "policy",
            "target_range",
            "status",
            "requested_by",
            "trigger",
            "classification",
            "dry_run",
            "target_cidr",
            "scheduled_for",
            "started_at",
            "finished_at",
            "duration",
        )
        default_columns = ("id", "policy", "status", "requested_by", "started_at", "duration", "trigger", "target_cidr")
