# Generated by Django 3.2 on 2021-09-04 21:23

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0010_auto_20210902_2236'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='box',
            options={'ordering': ['ip']},
        ),
        migrations.AlterModelOptions(
            name='boxservice',
            options={'ordering': ['port']},
        ),
    ]
