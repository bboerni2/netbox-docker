import django_tables2 as tables
from netbox.tables import NetBoxTable, columns

from .models import GlobalSettings, RangePolicy, ScanRun


class GlobalSettingsTable(NetBoxTable):
    name = tables.Column(linkify=True)

    class Meta(NetBoxTable.Meta):
        model = GlobalSettings
        fields = (
            "pk",
            "name",
            "enabled",
            "schedule_mode",
            "default_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
        )
        default_columns = ("name", "enabled", "default_interval_minutes", "max_concurrent_scans")


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
    id = tables.Column(linkify=True)
    policy = tables.Column(linkify=True)

    class Meta(NetBoxTable.Meta):
        model = ScanRun
        fields = (
            "pk",
            "id",
            "policy",
            "status",
            "trigger",
            "classification",
            "target_cidr",
            "scheduled_for",
            "started_at",
            "finished_at",
        )
        default_columns = ("id", "policy", "status", "trigger", "classification", "target_cidr", "scheduled_for")
