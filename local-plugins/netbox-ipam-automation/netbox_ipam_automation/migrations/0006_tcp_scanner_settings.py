from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_ipam_automation", "0005_scan_defaults_and_deprecation_policy")]

    operations = [
        migrations.AddField(
            model_name="globalsettings",
            name="default_tcp_ports",
            field=models.CharField(default="22,80,443,3389", max_length=255),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="tcp_timeout_seconds",
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="tcp_worker_count",
            field=models.PositiveIntegerField(default=64),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="reverse_dns_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="tcp_ports",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
