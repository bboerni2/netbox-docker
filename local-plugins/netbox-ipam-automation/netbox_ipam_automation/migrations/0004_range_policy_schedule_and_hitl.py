from django.db import migrations, models


def populate_policy_targets(apps, schema_editor):
    RangePolicy = apps.get_model("netbox_ipam_automation", "RangePolicy")
    for policy in RangePolicy.objects.select_related("target_range"):
        if not policy.target_range_id:
            policy.enabled = False
            policy.save(update_fields=("enabled",))
            continue
        start = str(policy.target_range.start_address).split("/", 1)[0]
        end = str(policy.target_range.end_address).split("/", 1)[0]
        policy.scan_start = start
        policy.scan_end = end
        policy.target_cidr = f"{start}-{end}"
        policy.save(update_fields=("scan_start", "scan_end", "target_cidr"))


class Migration(migrations.Migration):
    dependencies = [("netbox_ipam_automation", "0003_tags_and_related_names")]

    operations = [
        migrations.RemoveField(model_name="globalsettings", name="classification_mode"),
        migrations.RemoveField(model_name="rangepolicy", name="classification_mode"),
        migrations.AddField(
            model_name="globalsettings",
            name="schedule_mode",
            field=models.CharField(choices=[("interval", "Interval"), ("cron", "Cron")], default="interval", max_length=16),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="scan_start",
            field=models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="scan_end",
            field=models.GenericIPAddressField(blank=True, null=True, protocol="IPv4"),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="schedule_mode",
            field=models.CharField(choices=[("inherit", "Inherit"), ("interval", "Interval"), ("cron", "Cron")], default="inherit", max_length=16),
        ),
        migrations.RunPython(populate_policy_targets, migrations.RunPython.noop),
        migrations.AlterModelOptions(
            name="rangepolicy",
            options={"ordering": ("name",), "permissions": (("initialize_rangepolicy", "Can initialize range policies"),)},
        ),
    ]
