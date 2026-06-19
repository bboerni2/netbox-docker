from netbox.api.viewsets import NetBoxModelViewSet

from ..filtersets import GlobalSettingsFilterSet, RangePolicyFilterSet, ScanRunFilterSet
from ..models import GlobalSettings, RangePolicy, ScanRun
from .serializers import GlobalSettingsSerializer, RangePolicySerializer, ScanRunSerializer


class GlobalSettingsViewSet(NetBoxModelViewSet):
    queryset = GlobalSettings.objects.all()
    serializer_class = GlobalSettingsSerializer
    filterset_class = GlobalSettingsFilterSet


class RangePolicyViewSet(NetBoxModelViewSet):
    queryset = RangePolicy.objects.all()
    serializer_class = RangePolicySerializer
    filterset_class = RangePolicyFilterSet


class ScanRunViewSet(NetBoxModelViewSet):
    queryset = ScanRun.objects.all()
    serializer_class = ScanRunSerializer
    filterset_class = ScanRunFilterSet
