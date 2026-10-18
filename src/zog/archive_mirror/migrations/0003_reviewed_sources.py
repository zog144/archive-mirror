# Generated manually for reviewed source pin sets.
import django.db.models.deletion
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [('archive_mirror', '0002_collectionstatus')]
    operations = [
        migrations.CreateModel(
            name='SourcePinSet',
            fields=[
                ('identity', models.CharField(max_length=180, primary_key=True, serialize=False)),
                ('pin_date', models.DateField()),
                ('manifest_sha256', models.CharField(max_length=64)),
                ('complete', models.BooleanField(default=False)),
                ('active', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='ReviewedSource',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('package', models.CharField(blank=True, max_length=200)),
                ('source', models.CharField(blank=True, max_length=200)),
                ('canonical_url', models.TextField()),
                ('archive', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reviewed_sources', to='archive_mirror.archive')),
                ('pin_set', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sources', to='archive_mirror.sourcepinset')),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('pin_set','archive','package','source','canonical_url'), name='mirror_reviewed_source_identity')],
            },
        ),
    ]
