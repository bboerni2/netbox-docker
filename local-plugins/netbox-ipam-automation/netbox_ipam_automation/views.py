from netbox.ui import attrs, layout
from netbox.ui.panels import CommentsPanel, JSONPanel, ObjectAttributesPanel
from netbox.views.generic import ObjectDeleteView, ObjectEditView, ObjectListView, ObjectView
from utilities.views import register_model_view

from .filtersets import GlobalSettingsFilterSet, RangePolicyFilterSet, ScanRunFilterSet
from .forms import GlobalSettingsForm, RangePolicyForm, ScanRunCreateForm, ScanRunForm
from .models import GlobalSettings, RangePolicy, ScanRun
from .tables import GlobalSettingsTable, RangePolicyTable, ScanRunTable


class GlobalSettingsPanel(ObjectAttributesPanel):
    name = attrs.TextAttr("name", label="Name")
    enabled = attrs.BooleanAttr("enabled", label="Enabled")
    default_interval_minutes = attrs.NumericAttr("default_interval_minutes", label="Default interval")
    default_cron_expressions = attrs.TextAttr("default_cron_expressions", label="Default cron expressions")
    max_concurrent_scans = attrs.NumericAttr("max_concurrent_scans", label="Max concurrent scans")
    classification_mode = attrs.ChoiceAttr("classification_mode", label="Classification mode")


class RangePolicyPanel(ObjectAttributesPanel):
    name = attrs.TextAttr("name", label="Name")
    slug = attrs.TextAttr("slug", label="Slug")
    target_range = attrs.RelatedObjectAttr("target_range", label="Target IP range", linkify=True)
    target_cidr = attrs.TextAttr("target_cidr", label="Target CIDR")
    enabled = attrs.BooleanAttr("enabled", label="Enabled")
    interval_minutes = attrs.NumericAttr("interval_minutes", label="Interval")
    cron_expressions = attrs.TextAttr("cron_expressions", label="Cron expressions")
    classification_mode = attrs.ChoiceAttr("classification_mode", label="Classification mode")
    description = attrs.TextAttr("description", label="Description")


class ScanRunPanel(ObjectAttributesPanel):
    policy = attrs.RelatedObjectAttr("policy", label="Policy", linkify=True)
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
        right_panels=[JSONPanel("summary", title="Summary")],
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
