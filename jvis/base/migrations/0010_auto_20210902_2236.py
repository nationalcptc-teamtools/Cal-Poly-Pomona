# Generated by Django 3.2 on 2021-09-02 22:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0009_auto_20210902_0819'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='boxservice',
            name='os',
        ),
        migrations.AddField(
            model_name='box',
            name='os',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
