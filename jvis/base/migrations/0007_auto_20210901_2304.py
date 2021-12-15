# Generated by Django 3.2 on 2021-09-01 23:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0006_auto_20210901_0401'),
    ]

    operations = [
        migrations.AlterField(
            model_name='box',
            name='hostname',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='box',
            name='up',
            field=models.BooleanField(blank=True, default=False),
        ),
        migrations.AlterField(
            model_name='box',
            name='version',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]