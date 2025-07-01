import hashlib
from django.db import models
from django.utils.functional import cached_property

FIRST_HASH = "00" * 32


class Commitment(models.Model):
    id: int
    commitment = models.CharField(max_length=64, unique=True)
    hash = models.CharField(max_length=64)

    @cached_property
    def previous_entry(self):
        return self.objects.order_by("id").filter(id__lt=self.id).last() or Commitment(0)

    @staticmethod
    def make_hash(commitment: str):
        previous_entry = Commitment.objects.order_by("-id").first()
        return hashlib.sha256(
            f"{commitment}-{previous_entry.hash if previous_entry else FIRST_HASH}".encode()
        ).hexdigest()
    
    class Meta:
        indexes = [
            models.Index(models.F("id").asc(), name="id_order_idx")
        ]
