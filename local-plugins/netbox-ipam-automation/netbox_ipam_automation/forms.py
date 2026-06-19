from netbox.forms import NetBoxModelForm
from ipam.models import IPRange
from utilities.forms.fields import DynamicModelChoiceField
from utilities.forms.rendering import FieldSet

from .models import GlobalSettings, RangePolicy, ScanRun, ip_range_to_target


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
        required=True,
        label="IP range",
        selector=True,
    )

    fieldsets = (
        FieldSet(
            "name",
            "slug",
            "target_range",
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
        instance = super().save(commit=False)
        instance.status = ScanRun.StatusChoices.QUEUED
        instance.trigger = ScanRun.TriggerChoices.MANUAL
        instance.classification = ScanRun.ClassificationChoices.PENDING
        if instance.policy:
            instance.target_cidr = instance.policy.target_cidr or ip_range_to_target(instance.policy.target_range)
        if commit:
            instance.save()
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
