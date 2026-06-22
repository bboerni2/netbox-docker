from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_ipam_automation", "0004_range_policy_schedule_and_hitl")]

    operations = [
        migrations.RenameField(
            model_name="globalsettings",
            old_name="default_interval_minutes",
            new_name="default_scan_interval_minutes",
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="deprecated_last_seen_days",
            field=models.PositiveIntegerField(default=2),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="deprecated_grace_period_days",
            field=models.PositiveIntegerField(default=14),
        ),
        migrations.AlterField(
            model_name="scanrun",
            name="status",
            field=models.CharField(
                choices=[
                    ("queued", "Starting"),
                    ("running", "Running"),
                    ("completed", "Success"),
                    ("partial", "Partial"),
                    ("failed", "Failed"),
                    ("cancelled", "Cancelled"),
                ],
                default="queued",
                max_length=16,
            ),
        ),
    ]
