from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet
from utilities.filtersets import register_filterset

from .models import GlobalSettings, RangePolicy, ScanRun


@register_filterset
class GlobalSettingsFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = GlobalSettings
        fields = (
            "name",
            "enabled",
            "schedule_mode",
            "default_scan_interval_minutes",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
            "default_tcp_ports",
            "tcp_timeout_seconds",
            "tcp_worker_count",
            "reverse_dns_enabled",
        )

    def search(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(name__icontains=value)


@register_filterset
class RangePolicyFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = RangePolicy
        fields = ("name", "slug", "target_range", "target_cidr", "tcp_ports", "enabled", "schedule_mode")

    def search(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(slug__icontains=value) | Q(target_cidr__icontains=value)
        )


@register_filterset
class ScanRunFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = ScanRun
        fields = ("policy", "status", "trigger", "classification", "target_cidr")

    def search(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(target_cidr__icontains=value)
            | Q(message__icontains=value)
            | Q(policy__name__icontains=value)
        )
