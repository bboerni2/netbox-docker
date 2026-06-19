from django.urls import include, path
from utilities.urls import get_model_urls

from . import views  # noqa: F401

app_name = "netbox_ipam_automation"

urlpatterns = (
    path(
        "global-settings/",
        include(get_model_urls("netbox_ipam_automation", "globalsettings", detail=False)),
    ),
    path(
        "global-settings/<int:pk>/",
        include(get_model_urls("netbox_ipam_automation", "globalsettings")),
    ),
    path(
        "range-policies/",
        include(get_model_urls("netbox_ipam_automation", "rangepolicy", detail=False)),
    ),
    path(
        "range-policies/<int:pk>/",
        include(get_model_urls("netbox_ipam_automation", "rangepolicy")),
    ),
    path(
        "scan-runs/",
        include(get_model_urls("netbox_ipam_automation", "scanrun", detail=False)),
    ),
    path(
        "scan-runs/<int:pk>/",
        include(get_model_urls("netbox_ipam_automation", "scanrun")),
    ),
)
