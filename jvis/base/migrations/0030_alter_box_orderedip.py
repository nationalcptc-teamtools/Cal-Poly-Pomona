# Generated by Django 3.2 on 2021-09-19 04:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0029_auto_20210919_0449'),
    ]

    operations = [
        migrations.AlterField(
            model_name='box',
            name='orderedip',
            field=models.BigIntegerField(blank=True, default=0, null=True),
        ),
    ]
