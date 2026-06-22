from netbox.api.serializers import NetBoxModelSerializer

from ..models import GlobalSettings, RangePolicy, ScanRun


class GlobalSettingsSerializer(NetBoxModelSerializer):
    class Meta:
        model = GlobalSettings
        fields = (
            "id",
            "url",
            "display",
            "name",
            "enabled",
            "schedule_mode",
            "default_scan_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
            "default_tcp_ports",
            "tcp_timeout_seconds",
            "tcp_worker_count",
            "reverse_dns_enabled",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name")


class RangePolicySerializer(NetBoxModelSerializer):
    class Meta:
        model = RangePolicy
        fields = (
            "id",
            "url",
            "display",
            "name",
            "slug",
            "target_range",
            "target_cidr",
            "scan_start",
            "scan_end",
            "tcp_ports",
            "enabled",
            "schedule_mode",
            "interval_minutes",
            "cron_expressions",
            "description",
            "comments",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "slug", "target_range", "target_cidr")
        read_only_fields = ("slug", "target_cidr")


class ScanRunSerializer(NetBoxModelSerializer):
    def create(self, validated_data):
        from ..jobs import submit_manual_scan_run

        request = self.context.get("request")
        requested_by = request.user if request and request.user.is_authenticated else None
        return submit_manual_scan_run(ScanRun(**validated_data), requested_by=requested_by)

    class Meta:
        model = ScanRun
        fields = (
            "id",
            "url",
            "display",
            "policy",
            "requested_by",
            "status",
            "trigger",
            "classification",
            "target_cidr",
            "scheduled_for",
            "started_at",
            "finished_at",
            "observed_hosts",
            "responsive_hosts",
            "error_count",
            "summary",
            "message",
            "description",
            "comments",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "status", "classification", "target_cidr")
        read_only_fields = (
            "requested_by",
            "status",
            "trigger",
            "classification",
            "target_cidr",
            "scheduled_for",
            "started_at",
            "finished_at",
            "observed_hosts",
            "responsive_hosts",
            "error_count",
            "summary",
            "message",
        )
