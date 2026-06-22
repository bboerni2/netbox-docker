from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.text import slugify
from netbox.models import NetBoxModel, OrganizationalModel, PrimaryModel
from netbox.models.features import JobsMixin

from .services import as_ipv4_address, ip_range_to_network, normalize_cidr, normalize_cron_expressions, normalize_tcp_ports


def ip_range_to_target(value) -> str:
    if not value:
        return ""
    return f"{value.start_address.ip}-{value.end_address.ip}"


class GlobalSettings(NetBoxModel):
    class ScheduleModeChoices(models.TextChoices):
        INTERVAL = "interval", "Interval"
        CRON = "cron", "Cron"

    name = models.CharField(max_length=100, unique=True, default="default")
    enabled = models.BooleanField(default=True)
    scan_all_active_ranges = models.BooleanField(default=False)
    schedule_mode = models.CharField(max_length=16, choices=ScheduleModeChoices, default=ScheduleModeChoices.INTERVAL)
    default_scan_interval_minutes = models.PositiveIntegerField(default=60)
    default_cron_expressions = models.TextField(default="0 * * * *")
    max_concurrent_scans = models.PositiveIntegerField(default=1)
    deprecated_last_seen_days = models.PositiveIntegerField(default=2)
    deprecated_grace_period_days = models.PositiveIntegerField(default=14)
    default_tcp_ports = models.CharField(max_length=255, default="22,80,443,3389")
    tcp_timeout_seconds = models.PositiveIntegerField(default=1)
    tcp_worker_count = models.PositiveIntegerField(default=64)
    reverse_dns_enabled = models.BooleanField(default=True)

    class Meta:
        ordering = ("name",)
        verbose_name = "Global settings"
        verbose_name_plural = "Global settings"

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.default_scan_interval_minutes < 1:
            raise ValidationError("default_scan_interval_minutes must be >= 1.")
        if self.max_concurrent_scans < 1:
            raise ValidationError("max_concurrent_scans must be >= 1.")
        if self.deprecated_last_seen_days < 1:
            raise ValidationError("deprecated_last_seen_days must be >= 1.")
        if self.deprecated_grace_period_days < 1:
            raise ValidationError("deprecated_grace_period_days must be >= 1.")
        if self.tcp_timeout_seconds < 1:
            raise ValidationError("tcp_timeout_seconds must be >= 1.")
        if self.tcp_worker_count < 1:
            raise ValidationError("tcp_worker_count must be >= 1.")
        try:
            self.default_tcp_ports = normalize_tcp_ports(self.default_tcp_ports)
        except ValueError as exc:
            raise ValidationError({"default_tcp_ports": str(exc)}) from exc
        try:
            self.default_cron_expressions = normalize_cron_expressions(self.default_cron_expressions)
        except ValueError as exc:
            raise ValidationError({"default_cron_expressions": str(exc)}) from exc
        if self.schedule_mode == self.ScheduleModeChoices.CRON and not self.default_cron_expressions:
            raise ValidationError({"default_cron_expressions": "At least one cron expression is required."})
        queryset = type(self).objects.exclude(pk=self.pk)
        if queryset.exists():
            raise ValidationError("Only one global settings object is supported.")

    def get_absolute_url(self):
        return reverse(f"plugins:netbox_ipam_automation:{self._meta.model_name}", args=[self.pk])


class RangePolicy(OrganizationalModel):
    class ScheduleModeChoices(models.TextChoices):
        INHERIT = "inherit", "Inherit"
        INTERVAL = "interval", "Interval"
        CRON = "cron", "Cron"

    target_cidr = models.CharField(max_length=64, unique=True, null=True, blank=True)
    target_range = models.OneToOneField(
        to="ipam.IPRange",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="%(app_label)s_policies",
    )
    enabled = models.BooleanField(default=True)
    scan_start = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    scan_end = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    schedule_mode = models.CharField(max_length=16, choices=ScheduleModeChoices, default=ScheduleModeChoices.INHERIT)
    interval_minutes = models.PositiveIntegerField(null=True, blank=True)
    cron_expressions = models.TextField(blank=True)
    tcp_ports = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("name",)
        permissions = (("initialize_rangepolicy", "Can initialize range policies"),)

    def __str__(self) -> str:
        return self.name

    def full_clean(self, *args, **kwargs):
        self.slug = slugify(self.name)
        return super().full_clean(*args, **kwargs)

    def clean(self) -> None:
        super().clean()
        self.slug = slugify(self.name)
        if self.interval_minutes is not None and self.interval_minutes < 1:
            raise ValidationError("interval_minutes must be >= 1.")
        if not self.target_range:
            raise ValidationError({"target_range": "A target IP range is required."})
        try:
            network = ip_range_to_network(self.target_range.start_address, self.target_range.end_address)
        except ValueError as exc:
            raise ValidationError({"target_range": str(exc)}) from exc
        try:
            scan_start = as_ipv4_address(self.scan_start, field_name="Scan start") or network.network_address
            scan_end = as_ipv4_address(self.scan_end, field_name="Scan end") or network.broadcast_address
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        if scan_start not in network:
            raise ValidationError({"scan_start": f"Scan start must be inside {network}."})
        if scan_end not in network:
            raise ValidationError({"scan_end": f"Scan end must be inside {network}."})
        if scan_start > scan_end:
            raise ValidationError("Scan start must not be after scan end.")
        self.scan_start, self.scan_end = str(scan_start), str(scan_end)
        self.target_cidr = f"{scan_start}-{scan_end}"
        try:
            self.cron_expressions = normalize_cron_expressions(self.cron_expressions)
        except ValueError as exc:
            raise ValidationError({"cron_expressions": str(exc)}) from exc
        try:
            self.tcp_ports = normalize_tcp_ports(self.tcp_ports, allow_blank=True)
        except ValueError as exc:
            raise ValidationError({"tcp_ports": str(exc)}) from exc
        if self.schedule_mode == self.ScheduleModeChoices.INTERVAL and not self.interval_minutes:
            raise ValidationError({"interval_minutes": "An interval is required for interval scheduling."})
        if self.schedule_mode == self.ScheduleModeChoices.CRON and not self.cron_expressions:
            raise ValidationError({"cron_expressions": "At least one cron expression is required."})

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        return super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse(f"plugins:netbox_ipam_automation:{self._meta.model_name}", args=[self.pk])


class ScanRun(JobsMixin, PrimaryModel):
    class StatusChoices(models.TextChoices):
        QUEUED = "queued", "Starting"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Success"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class TriggerChoices(models.TextChoices):
        MANUAL = "manual", "Manual"
        SCHEDULED = "scheduled", "Scheduled"

    class ClassificationChoices(models.TextChoices):
        PENDING = "pending", "Pending"
        RESPONSIVE = "responsive", "Responsive"
        QUIET = "quiet", "Quiet"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"

    policy = models.ForeignKey(
        to="netbox_ipam_automation.RangePolicy",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_scan_runs",
    )
    target_range = models.ForeignKey(
        to="ipam.IPRange",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_scan_runs",
    )
    requested_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_scan_runs",
    )
    status = models.CharField(max_length=16, choices=StatusChoices, default=StatusChoices.QUEUED)
    trigger = models.CharField(max_length=16, choices=TriggerChoices, default=TriggerChoices.MANUAL)
    classification = models.CharField(
        max_length=16,
        choices=ClassificationChoices,
        default=ClassificationChoices.PENDING,
    )
    target_cidr = models.CharField(max_length=64, blank=True)
    scheduled_for = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    observed_hosts = models.PositiveIntegerField(default=0)
    responsive_hosts = models.PositiveIntegerField(default=0)
    error_count = models.PositiveIntegerField(default=0)
    summary = models.JSONField(default=dict, blank=True)
    message = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("-created",)
        permissions = (
            ("schedule_scanrun", "Can schedule scan runs"),
            ("classify_scanrun", "Can classify scan runs"),
        )

    def __str__(self) -> str:
        label = self.target_cidr or getattr(self.policy, "target_cidr", "unspecified")
        return f"Scan run {self.pk or 'new'} ({label})"

    def clean(self) -> None:
        super().clean()
        if not self.target_range and self.policy:
            self.target_range = self.policy.target_range
        if not self.target_cidr and self.policy:
            self.target_cidr = self.policy.target_cidr or ip_range_to_target(self.policy.target_range)
        if not self.target_cidr and self.target_range:
            self.target_cidr = ip_range_to_target(self.target_range)
        if self.target_cidr:
            if "-" not in self.target_cidr:
                self.target_cidr = normalize_cidr(self.target_cidr)
        if self.observed_hosts and self.responsive_hosts > self.observed_hosts:
            raise ValidationError("responsive_hosts cannot exceed observed_hosts.")

    @property
    def duration(self):
        if not self.started_at:
            return None
        from django.utils import timezone

        return (self.finished_at or timezone.now()) - self.started_at

    def get_absolute_url(self):
        return reverse(f"plugins:netbox_ipam_automation:{self._meta.model_name}", args=[self.pk])
