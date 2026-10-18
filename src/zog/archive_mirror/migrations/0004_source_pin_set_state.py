from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('archive_mirror', '0003_reviewed_sources')]

    operations = [
        migrations.AddConstraint(
            model_name='sourcepinset',
            constraint=models.CheckConstraint(
                condition=models.Q(active=False) | models.Q(complete=True),
                name='mirror_active_source_pin_set_complete',
            ),
        ),
    ]
