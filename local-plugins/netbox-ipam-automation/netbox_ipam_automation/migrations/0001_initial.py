from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("ipam", "0047_squashed_0053"),
    ]

    operations = [
        migrations.CreateModel(
            name="GlobalSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("name", models.CharField(default="default", max_length=100, unique=True)),
                ("enabled", models.BooleanField(default=True)),
                ("default_interval_minutes", models.PositiveIntegerField(default=60)),
                ("default_cron_expressions", models.TextField(default="0 * * * *")),
                ("max_concurrent_scans", models.PositiveIntegerField(default=1)),
                (
                    "classification_mode",
                    models.CharField(
                        choices=[("strict", "Strict"), ("lenient", "Lenient")],
                        default="lenient",
                        max_length=16,
                    ),
                ),
            ],
            options={
                "verbose_name": "Global settings",
                "verbose_name_plural": "Global settings",
                "ordering": ("name",),
            },
        ),
        migrations.CreateModel(
            name="RangePolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("name", models.CharField(max_length=100)),
                ("slug", models.SlugField(max_length=100)),
                ("description", models.CharField(blank=True, max_length=200)),
                ("comments", models.TextField(blank=True)),
                ("target_cidr", models.CharField(blank=True, max_length=64, null=True, unique=True)),
                ("enabled", models.BooleanField(default=True)),
                ("interval_minutes", models.PositiveIntegerField(blank=True, null=True)),
                ("cron_expressions", models.TextField(blank=True)),
                (
                    "classification_mode",
                    models.CharField(
                        choices=[("inherit", "Inherit"), ("strict", "Strict"), ("lenient", "Lenient")],
                        default="inherit",
                        max_length=16,
                    ),
                ),
                (
                    "target_range",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="netbox_ipam_automation_policies",
                        to="ipam.iprange",
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
            },
        ),
        migrations.CreateModel(
            name="ScanRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("description", models.CharField(blank=True, max_length=200)),
                ("comments", models.TextField(blank=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("completed", "Completed"),
                            ("partial", "Partial"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                        ],
                        default="queued",
                        max_length=16,
                    ),
                ),
                (
                    "trigger",
                    models.CharField(
                        choices=[("manual", "Manual"), ("scheduled", "Scheduled")],
                        default="manual",
                        max_length=16,
                    ),
                ),
                (
                    "classification",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("responsive", "Responsive"),
                            ("quiet", "Quiet"),
                            ("partial", "Partial"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("target_cidr", models.CharField(blank=True, max_length=64)),
                ("scheduled_for", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("observed_hosts", models.PositiveIntegerField(default=0)),
                ("responsive_hosts", models.PositiveIntegerField(default=0)),
                ("error_count", models.PositiveIntegerField(default=0)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("message", models.CharField(blank=True, max_length=255)),
                (
                    "policy",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="netbox_ipam_automation_scan_runs",
                        to="netbox_ipam_automation.rangepolicy",
                    ),
                ),
                (
                    "requested_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="netbox_ipam_automation_scan_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ("-created",),
                "permissions": (
                    ("schedule_scanrun", "Can schedule scan runs"),
                    ("classify_scanrun", "Can classify scan runs"),
                ),
            },
        ),
    ]
