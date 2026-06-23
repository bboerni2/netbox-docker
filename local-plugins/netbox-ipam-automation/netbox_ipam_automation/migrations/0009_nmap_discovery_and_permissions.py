from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ipam_automation", "0008_globalsettings_max_tasks_per_template"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="globalsettings",
            name="default_tcp_ports",
        ),
        migrations.RemoveField(
            model_name="globalsettings",
            name="tcp_timeout_seconds",
        ),
        migrations.RemoveField(
            model_name="globalsettings",
            name="tcp_worker_count",
        ),
        migrations.RemoveField(
            model_name="globalsettings",
            name="reverse_dns_enabled",
        ),
        migrations.RemoveField(
            model_name="rangepolicy",
            name="tcp_ports",
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="default_discovery_mode",
            field=models.CharField(
                choices=[("auto", "Auto"), ("routed", "Routed"), ("local_l2", "Local L2")],
                default="routed",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="non_admin_can_create_range_policies",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="non_admin_can_run_scans",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="discovery_mode",
            field=models.CharField(
                choices=[("inherit", "Inherit"), ("routed", "Routed"), ("local_l2", "Local L2")],
                default="inherit",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="scanrun",
            name="dry_run",
            field=models.BooleanField(default=False),
        ),
    ]
