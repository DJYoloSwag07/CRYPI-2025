# Generated by Django 5.2.3 on 2025-06-30 20:35

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Commitment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('commitment', models.CharField(max_length=64, unique=True)),
                ('hash', models.CharField(max_length=64)),
            ],
        ),
    ]
