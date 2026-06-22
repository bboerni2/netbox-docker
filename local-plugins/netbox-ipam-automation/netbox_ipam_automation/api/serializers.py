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
            "default_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "classification_mode",
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
            "enabled",
            "interval_minutes",
            "cron_expressions",
            "classification_mode",
            "description",
            "comments",
            "created",
            "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "slug", "target_range", "target_cidr")
        read_only_fields = ("target_cidr",)


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
