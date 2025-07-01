import hashlib
from typing import Any
from django.core.management.base import BaseCommand

from ...models import Commitment, FIRST_HASH


class Command(BaseCommand):
    help = "Verifies the entire blockchain"

    def handle(self, *args: Any, **options: Any):
        prev_hash = FIRST_HASH
        i = 0
        for commitment in Commitment.objects.all().order_by("id"):
            if commitment.hash != hashlib.sha256(f"{commitment.commitment}-{prev_hash}".encode()).hexdigest():
                self.stdout.write(self.style.ERROR(f"Mismatch at object {commitment.id}"))
                return
            prev_hash = commitment.hash
            i += 1
        self.stdout.write(self.style.SUCCESS(f"Successfully validated {i} items"))
