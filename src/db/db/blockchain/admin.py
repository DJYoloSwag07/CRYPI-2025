from django.contrib import admin

from .models import Commitment


@admin.register(Commitment)
class CommitmentAdmin(admin.ModelAdmin):
    pass
