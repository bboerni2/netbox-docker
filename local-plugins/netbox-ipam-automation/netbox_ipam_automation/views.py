from netbox.ui import attrs, layout
from netbox.ui.panels import CommentsPanel, ObjectAttributesPanel, TemplatePanel
from netbox.object_actions import CloneObject, DeleteObject, EditObject, ObjectAction
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib import messages
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from netbox.context_managers import event_tracking
from netbox.views.generic import ObjectDeleteView, ObjectEditView, ObjectListView, ObjectView
from utilities.views import register_model_view

from .filtersets import GlobalSettingsFilterSet, RangePolicyFilterSet, ScanRunFilterSet
from .forms import GlobalSettingsForm, RangePolicyForm, RangePolicyInitializeForm, ScanRunCreateForm, ScanRunForm
from .models import GlobalSettings, RangePolicy, ScanRun
from .services import initialize_range_policy, preview_range_policy_initialization
from .tables import GlobalSettingsTable, RangePolicyTable, ScanRunTable


class GlobalSettingsPanel(ObjectAttributesPanel):
    name = attrs.TextAttr("name", label="Name")
    enabled = attrs.BooleanAttr("enabled", label="Enabled")
    scan_all_active_ranges = attrs.BooleanAttr("scan_all_active_ranges", label="Scan all active IP ranges")
    schedule_mode = attrs.ChoiceAttr("schedule_mode", label="Schedule mode")
    default_scan_interval_minutes = attrs.NumericAttr("default_scan_interval_minutes", label="Default scan interval")
    default_cron_expressions = attrs.TextAttr("default_cron_expressions", label="Default cron expressions")
    max_concurrent_scans = attrs.NumericAttr("max_concurrent_scans", label="Max concurrent scans")
    deprecated_last_seen_days = attrs.NumericAttr("deprecated_last_seen_days", label="Deprecated last seen")
    deprecated_grace_period_days = attrs.NumericAttr("deprecated_grace_period_days", label="Deprecated grace period")
    default_tcp_ports = attrs.TextAttr("default_tcp_ports", label="Default TCP ports")
    tcp_timeout_seconds = attrs.NumericAttr("tcp_timeout_seconds", label="TCP timeout")
    tcp_worker_count = attrs.NumericAttr("tcp_worker_count", label="TCP workers")
    reverse_dns_enabled = attrs.BooleanAttr("reverse_dns_enabled", label="Reverse DNS enabled")


class RangePolicyPanel(ObjectAttributesPanel):
    name = attrs.TextAttr("name", label="Name")
    slug = attrs.TextAttr("slug", label="Slug")
    target_range = attrs.RelatedObjectAttr("target_range", label="Target IP range", linkify=True)
    target_cidr = attrs.TextAttr("target_cidr", label="Target CIDR")
    scan_start = attrs.TextAttr("scan_start", label="Scan start")
    scan_end = attrs.TextAttr("scan_end", label="Scan end")
    tcp_ports = attrs.TextAttr("tcp_ports", label="TCP ports")
    enabled = attrs.BooleanAttr("enabled", label="Schedule enabled")
    schedule_mode = attrs.ChoiceAttr("schedule_mode", label="Schedule mode")
    interval_minutes = attrs.NumericAttr("interval_minutes", label="Interval")
    cron_expressions = attrs.TextAttr("cron_expressions", label="Cron expressions")
    description = attrs.TextAttr("description", label="Description")


class ScanRunPanel(ObjectAttributesPanel):
    policy = attrs.RelatedObjectAttr("policy", label="Policy", linkify=True)
    target_range = attrs.RelatedObjectAttr("target_range", label="Target IP range", linkify=True)
    requested_by = attrs.RelatedObjectAttr("requested_by", label="Requested by", linkify=True)
    status = attrs.ChoiceAttr("status", label="Status")
    trigger = attrs.ChoiceAttr("trigger", label="Trigger")
    classification = attrs.ChoiceAttr("classification", label="Classification")
    target_cidr = attrs.TextAttr("target_cidr", label="Target CIDR")
    scheduled_for = attrs.DateTimeAttr("scheduled_for", label="Scheduled for", spec="minutes")
    started_at = attrs.DateTimeAttr("started_at", label="Started at", spec="minutes")
    finished_at = attrs.DateTimeAttr("finished_at", label="Finished at", spec="minutes")
    observed_hosts = attrs.NumericAttr("observed_hosts", label="Observed hosts")
    responsive_hosts = attrs.NumericAttr("responsive_hosts", label="Responsive hosts")
    error_count = attrs.NumericAttr("error_count", label="Errors")
    message = attrs.TextAttr("message", label="Message")


@register_model_view(GlobalSettings, "list", detail=False)
class GlobalSettingsListView(ObjectListView):
    queryset = GlobalSettings.objects.all()
    table = GlobalSettingsTable
    filterset = GlobalSettingsFilterSet


@register_model_view(GlobalSettings)
class GlobalSettingsView(ObjectView):
    queryset = GlobalSettings.objects.all()
    template_name = "generic/object.html"
    layout = layout.SimpleLayout(left_panels=[GlobalSettingsPanel()])


@register_model_view(GlobalSettings, "add", path="add", detail=False)
@register_model_view(GlobalSettings, "edit")
class GlobalSettingsEditView(ObjectEditView):
    queryset = GlobalSettings.objects.all()
    form = GlobalSettingsForm


@register_model_view(GlobalSettings, "delete")
class GlobalSettingsDeleteView(ObjectDeleteView):
    queryset = GlobalSettings.objects.all()


@register_model_view(RangePolicy, "list", detail=False)
class RangePolicyListView(ObjectListView):
    queryset = RangePolicy.objects.all()
    table = RangePolicyTable
    filterset = RangePolicyFilterSet


@register_model_view(RangePolicy)
class RangePolicyView(ObjectView):
    queryset = RangePolicy.objects.all()
    template_name = "generic/object.html"
    layout = layout.SimpleLayout(left_panels=[RangePolicyPanel(), CommentsPanel()])

    class InitializeAction(ObjectAction):
        name = "initialize"
        label = "Initialize"
        permissions_required = {"initialize_rangepolicy"}
        url_kwargs = ["pk"]
        template_name = "netbox_ipam_automation/buttons/initialize.html"

    actions = (InitializeAction, CloneObject, EditObject, DeleteObject)


@register_model_view(RangePolicy, "initialize")
class RangePolicyInitializeView(PermissionRequiredMixin, View):
    permission_required = (
        "netbox_ipam_automation.view_rangepolicy",
        "netbox_ipam_automation.initialize_rangepolicy",
        "ipam.add_ipaddress",
    )
    raise_exception = True
    template_name = "netbox_ipam_automation/rangepolicy_initialize.html"

    def dispatch(self, request, pk, *args, **kwargs):
        self.object = get_object_or_404(RangePolicy.objects.select_related("target_range"), pk=pk)
        return super().dispatch(request, pk, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, {"object": self.object, "form": RangePolicyInitializeForm()})

    def post(self, request, *args, **kwargs):
        form = RangePolicyInitializeForm(request.POST)
        preview = None
        if form.is_valid():
            try:
                preview = preview_range_policy_initialization(self.object, form.cleaned_data["gateway"])
                if "_confirm" in request.POST:
                    with event_tracking(request), transaction.atomic():
                        created = initialize_range_policy(self.object, form.cleaned_data["gateway"])
                    messages.success(request, f"Created {created} missing IP address record(s).")
                    return redirect(self.object.get_absolute_url())
            except ValueError as exc:
                form.add_error("gateway", str(exc))
        return render(request, self.template_name, {"object": self.object, "form": form, "preview": preview})


@register_model_view(RangePolicy, "add", path="add", detail=False)
@register_model_view(RangePolicy, "edit")
class RangePolicyEditView(ObjectEditView):
    queryset = RangePolicy.objects.all()
    form = RangePolicyForm


@register_model_view(RangePolicy, "delete")
class RangePolicyDeleteView(ObjectDeleteView):
    queryset = RangePolicy.objects.all()


@register_model_view(ScanRun, "list", detail=False)
class ScanRunListView(ObjectListView):
    queryset = ScanRun.objects.all()
    table = ScanRunTable
    filterset = ScanRunFilterSet


@register_model_view(ScanRun)
class ScanRunView(ObjectView):
    queryset = ScanRun.objects.all()
    template_name = "generic/object.html"
    layout = layout.SimpleLayout(
        left_panels=[ScanRunPanel(), CommentsPanel()],
        right_panels=[TemplatePanel("netbox_ipam_automation/panels/scanrun_summary.html", title="Summary")],
    )


@register_model_view(ScanRun, "add", path="add", detail=False)
class ScanRunCreateView(ObjectEditView):
    queryset = ScanRun.objects.all()
    form = ScanRunCreateForm

    def alter_object(self, obj, request, url_args, url_kwargs):
        if not obj.pk:
            obj.requested_by = request.user
        return obj


@register_model_view(ScanRun, "edit")
class ScanRunEditView(ObjectEditView):
    queryset = ScanRun.objects.all()
    form = ScanRunForm


@register_model_view(ScanRun, "delete")
class ScanRunDeleteView(ObjectDeleteView):
    queryset = ScanRun.objects.all()
