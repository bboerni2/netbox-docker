from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import taggit.managers


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0139_alter_customfieldchoiceset_extra_choices"),
        ("ipam", "0047_squashed_0053"),
        ("netbox_ipam_automation", "0002_netbox_model_base_fields"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="globalsettings",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AddField(
            model_name="scanrun",
            name="tags",
            field=taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag"),
        ),
        migrations.AlterField(
            model_name="rangepolicy",
            name="target_range",
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="%(app_label)s_policies",
                to="ipam.iprange",
            ),
        ),
        migrations.AlterField(
            model_name="scanrun",
            name="policy",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(app_label)s_scan_runs",
                to="netbox_ipam_automation.rangepolicy",
            ),
        ),
        migrations.AlterField(
            model_name="scanrun",
            name="requested_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="%(app_label)s_scan_runs",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
