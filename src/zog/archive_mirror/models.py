from django.db import models

class Archive(models.Model):
    collection = models.CharField(max_length=64)
    digest = models.CharField(max_length=64)
    size = models.PositiveBigIntegerField()
    kind = models.CharField(max_length=32)
    managed = models.BooleanField(default=False)
    provenance = models.JSONField(default=dict)
    created = models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints = [models.UniqueConstraint(fields=['collection','digest'], name='mirror_collection_digest')]

class Snapshot(models.Model):
    source = models.CharField(max_length=128)
    month = models.CharField(max_length=7)
    archive = models.ForeignKey(Archive, on_delete=models.PROTECT)
    commit = models.CharField(max_length=64)
    class Meta:
        constraints = [models.UniqueConstraint(fields=['source','month'], name='mirror_source_month')]

class Pin(models.Model):
    archive = models.ForeignKey(Archive, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    class Meta:
        constraints = [models.UniqueConstraint(fields=['archive','name'], name='mirror_archive_pin')]

class CollectionStatus(models.Model):
    source = models.CharField(max_length=128, primary_key=True)
    last_attempt = models.DateTimeField()
    last_success = models.DateTimeField(null=True)
    error = models.CharField(max_length=100, blank=True)

class SourcePinSet(models.Model):
    identity = models.CharField(max_length=180, primary_key=True)
    pin_date = models.DateField()
    manifest_sha256 = models.CharField(max_length=64)
    complete = models.BooleanField(default=False)
    active = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints = [models.CheckConstraint(
            condition=models.Q(active=False) | models.Q(complete=True),
            name='mirror_active_source_pin_set_complete')]

class ReviewedSource(models.Model):
    pin_set = models.ForeignKey(SourcePinSet, on_delete=models.CASCADE, related_name='sources')
    archive = models.ForeignKey(Archive, on_delete=models.CASCADE, related_name='reviewed_sources')
    package = models.CharField(max_length=200, blank=True)
    source = models.CharField(max_length=200, blank=True)
    canonical_url = models.TextField()
    class Meta:
        constraints = [models.UniqueConstraint(
            fields=['pin_set','archive','package','source','canonical_url'],
            name='mirror_reviewed_source_identity')]
