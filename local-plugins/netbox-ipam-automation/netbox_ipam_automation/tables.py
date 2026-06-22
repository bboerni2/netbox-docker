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
            "schedule_mode",
            "default_scan_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
        )
        default_columns = (
            "name",
            "enabled",
            "default_scan_interval_minutes",
            "max_concurrent_scans",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
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
            "enabled",
            "schedule_mode",
            "interval_minutes",
            "cron_expressions",
        )
        default_columns = ("name", "target_range", "scan_start", "scan_end", "enabled", "schedule_mode")


class ScanRunTable(NetBoxTable):
    id = tables.Column(linkify=True, verbose_name="Task ID")
    policy = tables.Column(linkify=True, verbose_name="Task")
    status = columns.ChoiceFieldColumn()
    duration = tables.Column(empty_values=(), orderable=False)

    def render_duration(self, record):
        if not record.started_at:
            return "—"
        end = record.finished_at or record.last_updated
        return timesince(record.started_at, end)

    class Meta(NetBoxTable.Meta):
        model = ScanRun
        fields = (
            "pk",
            "id",
            "policy",
            "status",
            "requested_by",
            "trigger",
            "classification",
            "target_cidr",
            "scheduled_for",
            "started_at",
            "finished_at",
            "duration",
        )
        default_columns = ("id", "policy", "status", "requested_by", "started_at", "duration", "trigger", "target_cidr")
