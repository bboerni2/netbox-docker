from django import forms
from netbox.forms import NetBoxModelForm
from ipam.models import IPRange
from utilities.forms.fields import DynamicModelChoiceField
from utilities.forms.rendering import FieldSet, InlineFields

from .models import GlobalSettings, RangePolicy, ScanRun
from .services import interval_parts_to_minutes, minutes_to_interval_parts


INTERVAL_UNITS = (("minutes", "Minutes"), ("hours", "Hours"), ("days", "Days"), ("weeks", "Weeks"))
CRON_HELP_TEXT = (
    "Enter one five-field cron expression per line: minute, hour, day of month, month, day of week.\n"
    "Example: 0 2 * * * runs daily at 02:00 in the NetBox timezone."
)


class IntervalFieldsMixin:
    def _set_interval_initial(self, minutes):
        value, unit = minutes_to_interval_parts(minutes)
        self.fields["interval_value"].initial = value
        self.fields["interval_unit"].initial = unit

    def _clean_interval(self, mode, interval_field, *, preserve_when_inactive=False):
        if mode == "interval":
            try:
                self.cleaned_data[interval_field] = interval_parts_to_minutes(
                    self.cleaned_data.get("interval_value"), self.cleaned_data.get("interval_unit")
                )
            except ValueError as exc:
                self.add_error("interval_value", str(exc))
        elif preserve_when_inactive:
            self.cleaned_data[interval_field] = getattr(self.instance, interval_field)
        else:
            self.cleaned_data[interval_field] = None


class GlobalSettingsForm(IntervalFieldsMixin, NetBoxModelForm):
    interval_value = forms.IntegerField(min_value=1, required=False, label="Interval")
    interval_unit = forms.ChoiceField(choices=INTERVAL_UNITS, required=False, initial="minutes", label="Unit")
    default_scan_interval_minutes = forms.IntegerField(required=False)

    fieldsets = (
        FieldSet(
            "name",
            "enabled",
            "scan_all_active_ranges",
            "schedule_mode",
            InlineFields("interval_value", "interval_unit", label="Default scan interval"),
            "default_cron_expressions",
            "max_concurrent_scans",
            "max_tasks_per_template",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
            "default_tcp_ports",
            "tcp_timeout_seconds",
            "tcp_worker_count",
            "reverse_dns_enabled",
        ),
    )

    class Meta:
        model = GlobalSettings
        fields = (
            "name",
            "enabled",
            "scan_all_active_ranges",
            "schedule_mode",
            "default_scan_interval_minutes",
            "default_cron_expressions",
            "max_concurrent_scans",
            "max_tasks_per_template",
            "deprecated_last_seen_days",
            "deprecated_grace_period_days",
            "default_tcp_ports",
            "tcp_timeout_seconds",
            "tcp_worker_count",
            "reverse_dns_enabled",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._set_interval_initial(self.instance.default_scan_interval_minutes)
        self.fields["default_scan_interval_minutes"].label = "Default scan interval"
        self.fields["scan_all_active_ranges"].label = "Scan all active IP ranges"
        self.fields["scan_all_active_ranges"].help_text = (
            "Automatically scan active IP ranges without a range policy using the default scan interval."
        )
        self.fields["max_tasks_per_template"].label = "Max tasks per template"
        self.fields["max_tasks_per_template"].help_text = (
            "Maximum terminal scan runs retained per IP range. Active runs do not count."
        )
        self.fields["deprecated_last_seen_days"].label = "Deprecated last seen"
        self.fields["deprecated_last_seen_days"].help_text = (
            "Days an active IP must be unseen before it is marked deprecated."
        )
        self.fields["deprecated_grace_period_days"].label = "Deprecated grace period"
        self.fields["deprecated_grace_period_days"].help_text = (
            "Days a deprecated IP remains reserved before it can be marked free."
        )
        self.fields["default_cron_expressions"].help_text = CRON_HELP_TEXT
        self.fields["default_tcp_ports"].label = "Default TCP ports"
        self.fields["default_tcp_ports"].help_text = "Comma-separated TCP ports, for example 22,80,443,3389."
        self.fields["tcp_timeout_seconds"].label = "TCP timeout"
        self.fields["tcp_timeout_seconds"].help_text = "Seconds to wait for each TCP connection attempt."
        self.fields["tcp_worker_count"].label = "TCP workers"
        self.fields["tcp_worker_count"].help_text = "Maximum concurrent TCP probes per scan."
        self.fields["reverse_dns_enabled"].label = "Reverse DNS enabled"

    def clean(self):
        super().clean()
        cleaned_data = self.cleaned_data
        self._clean_interval(
            cleaned_data.get("schedule_mode"),
            "default_scan_interval_minutes",
            preserve_when_inactive=True,
        )
        return cleaned_data


class RangePolicyForm(IntervalFieldsMixin, NetBoxModelForm):
    interval_value = forms.IntegerField(min_value=1, required=False, label="Interval")
    interval_unit = forms.ChoiceField(choices=INTERVAL_UNITS, required=False, initial="minutes", label="Unit")
    target_range = DynamicModelChoiceField(
        queryset=IPRange.objects.all(),
        required=True,
        label="IP range",
        selector=True,
    )

    fieldsets = (
        FieldSet(
            "name",
            "target_range",
            "scan_start",
            "scan_end",
            "tcp_ports",
            name="Target",
        ),
        FieldSet(
            "enabled",
            "schedule_mode",
            InlineFields("interval_value", "interval_unit", label="Interval"),
            "cron_expressions",
            name="Schedule",
        ),
        FieldSet(
            "description",
            name="Details",
        ),
    )

    class Meta:
        model = RangePolicy
        fields = (
            "name",
            "target_range",
            "scan_start",
            "scan_end",
            "tcp_ports",
            "enabled",
            "schedule_mode",
            "interval_minutes",
            "cron_expressions",
            "description",
            "comments",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._set_interval_initial(self.instance.interval_minutes)
        self.fields["enabled"].label = "Schedule enabled"
        self.fields["enabled"].help_text = "Disable this to stop automatic scans for this policy."
        self.fields["schedule_mode"].choices = (
            (RangePolicy.ScheduleModeChoices.INHERIT, "Global default"),
            (RangePolicy.ScheduleModeChoices.INTERVAL, "Interval"),
            (RangePolicy.ScheduleModeChoices.CRON, "Cron"),
        )
        self.fields["scan_start"].help_text = (
            "Optional IPv4 address. Leave blank to auto-select the first address."
        )
        self.fields["scan_end"].help_text = (
            "Optional IPv4 address. Leave blank to auto-select the last address."
        )
        self.fields["tcp_ports"].label = "TCP ports"
        self.fields["tcp_ports"].help_text = (
            "Optional comma-separated TCP ports, for example 22,80,443,3389. Leave blank to use the global default."
        )
        self.fields["cron_expressions"].help_text = CRON_HELP_TEXT

    def clean(self):
        super().clean()
        cleaned_data = self.cleaned_data
        self._clean_interval(cleaned_data.get("schedule_mode"), "interval_minutes")
        return cleaned_data


class RangePolicyInitializeForm(forms.Form):
    gateway = forms.GenericIPAddressField(protocol="IPv4", required=True)


class ScanRunCreateForm(NetBoxModelForm):
    fieldsets = (
        FieldSet(
            "policy",
            name="Scan request",
        ),
        FieldSet("description", name="Notes"),
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
        FieldSet("description", name="Notes"),
    )

    class Meta:
        model = ScanRun
        fields = (
            "description",
            "comments",
        )
