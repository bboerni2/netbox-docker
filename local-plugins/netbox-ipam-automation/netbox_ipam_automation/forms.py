from netbox.forms import NetBoxModelForm
from ipam.models import IPRange
from utilities.forms.fields import DynamicModelChoiceField
from utilities.forms.rendering import FieldSet

from .models import GlobalSettings, RangePolicy, ScanRun


class GlobalSettingsForm(NetBoxModelForm):
    fieldsets = (
        FieldSet(
            "name",
            "enabled",
            "default_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "classification_mode",
        ),
    )

    class Meta:
        model = GlobalSettings
        fields = (
            "name",
            "enabled",
            "default_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "classification_mode",
        )


class RangePolicyForm(NetBoxModelForm):
    target_range = DynamicModelChoiceField(
        queryset=IPRange.objects.all(),
        required=False,
        label="IP range",
        selector=True,
    )

    fieldsets = (
        FieldSet(
            "name",
            "slug",
            "target_range",
            "target_cidr",
            name="Target",
        ),
        FieldSet(
            "enabled",
            "interval_minutes",
            "cron_expressions",
            name="Schedule",
        ),
        FieldSet(
            "classification_mode",
            "description",
            name="Classification",
        ),
        FieldSet("comments", name="Comments"),
    )

    class Meta:
        model = RangePolicy
        fields = (
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
        )


class ScanRunCreateForm(NetBoxModelForm):
    fieldsets = (
        FieldSet(
            "policy",
            name="Scan request",
        ),
        FieldSet("description", "comments", name="Notes"),
    )

    class Meta:
        model = ScanRun
        fields = (
            "policy",
            "description",
            "comments",
        )

    def save(self, commit=True):
        from .jobs import submit_manual_scan_run

        instance = super().save(commit=False)
        if commit:
            instance = submit_manual_scan_run(instance)
            self.save_m2m()
        return instance


class ScanRunForm(NetBoxModelForm):
    fieldsets = (
        FieldSet("description", "comments", name="Notes"),
    )

    class Meta:
        model = ScanRun
        fields = (
            "description",
            "comments",
        )
