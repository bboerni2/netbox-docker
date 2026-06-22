from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("ipam", "0092_iprange_host_indexes"),
        ("netbox_ipam_automation", "0006_tcp_scanner_settings"),
    ]

    operations = [
        migrations.AddField(
            model_name="globalsettings",
            name="scan_all_active_ranges",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="scanrun",
            name="target_range",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(app_label)s_scan_runs",
                to="ipam.iprange",
            ),
        ),
    ]
