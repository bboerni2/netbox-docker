from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_ipam_automation", "0007_scan_all_active_ranges")]

    operations = [
        migrations.AddField(
            model_name="globalsettings",
            name="max_tasks_per_template",
            field=models.PositiveIntegerField(default=100),
        ),
    ]
