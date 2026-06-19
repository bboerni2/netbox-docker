from django.db import migrations, models
import django.db.models.deletion
import utilities.json


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_ipam_automation", "0001_initial"),
        ("users", "0015_owner"),
    ]

    operations = [
        migrations.AlterField(
            model_name="globalsettings",
            name="created",
            field=models.DateTimeField(auto_now_add=True, blank=True, null=True, verbose_name="created"),
        ),
        migrations.AlterField(
            model_name="globalsettings",
            name="last_updated",
            field=models.DateTimeField(auto_now=True, blank=True, null=True, verbose_name="last updated"),
        ),
        migrations.AddField(
            model_name="globalsettings",
            name="custom_field_data",
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AlterField(
            model_name="rangepolicy",
            name="created",
            field=models.DateTimeField(auto_now_add=True, blank=True, null=True, verbose_name="created"),
        ),
        migrations.AlterField(
            model_name="rangepolicy",
            name="last_updated",
            field=models.DateTimeField(auto_now=True, blank=True, null=True, verbose_name="last updated"),
        ),
        migrations.AlterField(
            model_name="rangepolicy",
            name="name",
            field=models.CharField(max_length=100, unique=True, verbose_name="name"),
        ),
        migrations.AlterField(
            model_name="rangepolicy",
            name="slug",
            field=models.SlugField(max_length=100, unique=True, verbose_name="slug"),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="custom_field_data",
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AddField(
            model_name="rangepolicy",
            name="owner",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="users.owner",
            ),
        ),
        migrations.AlterField(
            model_name="scanrun",
            name="created",
            field=models.DateTimeField(auto_now_add=True, blank=True, null=True, verbose_name="created"),
        ),
        migrations.AlterField(
            model_name="scanrun",
            name="last_updated",
            field=models.DateTimeField(auto_now=True, blank=True, null=True, verbose_name="last updated"),
        ),
        migrations.AddField(
            model_name="scanrun",
            name="custom_field_data",
            field=models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder),
        ),
        migrations.AddField(
            model_name="scanrun",
            name="owner",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="users.owner",
            ),
        ),
    ]
