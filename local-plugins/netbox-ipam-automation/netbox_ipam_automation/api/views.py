from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework.exceptions import PermissionDenied

from ..filtersets import GlobalSettingsFilterSet, RangePolicyFilterSet, ScanRunFilterSet
from ..models import GlobalSettings, RangePolicy, ScanRun
from .serializers import GlobalSettingsSerializer, RangePolicySerializer, ScanRunSerializer


def get_global_settings():
    return GlobalSettings.objects.order_by("pk").first() or GlobalSettings()


class GlobalSettingsViewSet(NetBoxModelViewSet):
    queryset = GlobalSettings.objects.all()
    serializer_class = GlobalSettingsSerializer
    filterset_class = GlobalSettingsFilterSet

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not request.user.is_superuser:
            raise PermissionDenied("Global settings are restricted to NetBox administrators.")


class RangePolicyViewSet(NetBoxModelViewSet):
    queryset = RangePolicy.objects.all()
    serializer_class = RangePolicySerializer
    filterset_class = RangePolicyFilterSet

    def create(self, request, *args, **kwargs):
        if not request.user.is_superuser and not get_global_settings().non_admin_can_create_range_policies:
            raise PermissionDenied("Non-admin range policy creation is disabled.")
        return super().create(request, *args, **kwargs)


class ScanRunViewSet(NetBoxModelViewSet):
    queryset = ScanRun.objects.all()
    serializer_class = ScanRunSerializer
    filterset_class = ScanRunFilterSet

    def create(self, request, *args, **kwargs):
        if not request.user.is_superuser and not get_global_settings().non_admin_can_run_scans:
            raise PermissionDenied("Non-admin scan execution is disabled.")
        return super().create(request, *args, **kwargs)
