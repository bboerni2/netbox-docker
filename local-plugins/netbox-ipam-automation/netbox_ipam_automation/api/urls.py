from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.register("global-settings", views.GlobalSettingsViewSet)
router.register("range-policies", views.RangePolicyViewSet)
router.register("scan-runs", views.ScanRunViewSet)

urlpatterns = router.urls
