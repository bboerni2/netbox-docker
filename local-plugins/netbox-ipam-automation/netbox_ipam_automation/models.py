from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel, OrganizationalModel, PrimaryModel
from netbox.models.features import JobsMixin

from .services import normalize_cidr


def ip_range_to_target(value) -> str:
    if not value:
        return ""
    return f"{value.start_address}-{value.end_address}"


class GlobalSettings(NetBoxModel):
    class ClassificationModeChoices(models.TextChoices):
        STRICT = "strict", "Strict"
        LENIENT = "lenient", "Lenient"

    name = models.CharField(max_length=100, unique=True, default="default")
    enabled = models.BooleanField(default=True)
    default_interval_minutes = models.PositiveIntegerField(default=60)
    default_cron_expressions = models.TextField(default="0 * * * *")
    max_concurrent_scans = models.PositiveIntegerField(default=1)
    classification_mode = models.CharField(
        max_length=16,
        choices=ClassificationModeChoices,
        default=ClassificationModeChoices.LENIENT,
    )

    class Meta:
        ordering = ("name",)
        verbose_name = "Global settings"
        verbose_name_plural = "Global settings"

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.default_interval_minutes < 1:
            raise ValidationError("default_interval_minutes must be >= 1.")
        if self.max_concurrent_scans < 1:
            raise ValidationError("max_concurrent_scans must be >= 1.")
        queryset = type(self).objects.exclude(pk=self.pk)
        if queryset.exists():
            raise ValidationError("Only one global settings object is supported.")

    def get_absolute_url(self):
        return reverse(f"plugins:netbox_ipam_automation:{self._meta.model_name}", args=[self.pk])


class RangePolicy(OrganizationalModel):
    class ClassificationModeChoices(models.TextChoices):
        INHERIT = "inherit", "Inherit"
        STRICT = "strict", "Strict"
        LENIENT = "lenient", "Lenient"

    target_cidr = models.CharField(max_length=64, unique=True, null=True, blank=True)
    target_range = models.OneToOneField(
        to="ipam.IPRange",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="%(app_label)s_policies",
    )
    enabled = models.BooleanField(default=True)
    interval_minutes = models.PositiveIntegerField(null=True, blank=True)
    cron_expressions = models.TextField(blank=True)
    classification_mode = models.CharField(
        max_length=16,
        choices=ClassificationModeChoices,
        default=ClassificationModeChoices.INHERIT,
    )

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name

    def clean(self) -> None:
        super().clean()
        if self.interval_minutes is not None and self.interval_minutes < 1:
            raise ValidationError("interval_minutes must be >= 1.")
        if self.target_range:
            self.target_cidr = ip_range_to_target(self.target_range)
        elif self.target_cidr:
            self.target_cidr = normalize_cidr(self.target_cidr)
        else:
            raise ValidationError("A range policy needs an IP range.")

    def get_absolute_url(self):
        return reverse(f"plugins:netbox_ipam_automation:{self._meta.model_name}", args=[self.pk])


class ScanRun(JobsMixin, PrimaryModel):
    class StatusChoices(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
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
        if not self.target_cidr and self.policy:
            self.target_cidr = self.policy.target_cidr or ip_range_to_target(self.policy.target_range)
        if self.target_cidr:
            if "-" not in self.target_cidr:
                self.target_cidr = normalize_cidr(self.target_cidr)
        if self.observed_hosts and self.responsive_hosts > self.observed_hosts:
            raise ValidationError("responsive_hosts cannot exceed observed_hosts.")

    def get_absolute_url(self):
        return reverse(f"plugins:netbox_ipam_automation:{self._meta.model_name}", args=[self.pk])
