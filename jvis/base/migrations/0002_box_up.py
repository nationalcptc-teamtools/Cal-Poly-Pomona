# Generated by Django 3.2 on 2021-08-31 20:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='box',
            name='up',
            field=models.BooleanField(default=False),
        ),
    ]