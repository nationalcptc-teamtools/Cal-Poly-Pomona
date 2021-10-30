# Generated by Django 3.2 on 2021-09-23 19:46

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    replaces = [('base', '0001_initial'), ('base', '0002_box_up'), ('base', '0003_box_group'), ('base', '0004_auto_20210901_0253'), ('base', '0005_alter_box_ip'), ('base', '0006_auto_20210901_0401'), ('base', '0007_auto_20210901_2304'), ('base', '0008_boxservice'), ('base', '0009_auto_20210902_0819'), ('base', '0010_auto_20210902_2236'), ('base', '0011_auto_20210904_2123'), ('base', '0012_alter_boxservice_options'), ('base', '0013_auto_20210904_2306'), ('base', '0014_alter_boxservice_port'), ('base', '0015_alter_boxservice_port'), ('base', '0016_boxservice_script'), ('base', '0017_box_pwned'), ('base', '0018_auto_20210905_0453'), ('base', '0019_auto_20210910_2240'), ('base', '0020_auto_20210911_0311'), ('base', '0021_alter_boxservice_updated'), ('base', '0022_alter_boxservice_updated'), ('base', '0023_alter_boxservice_updated'), ('base', '0024_alter_boxservice_updated'), ('base', '0025_auto_20210911_2025'), ('base', '0026_auto_20210911_2311'), ('base', '0027_box_cidr'), ('base', '0028_box_orderedip'), ('base', '0029_auto_20210919_0449'), ('base', '0030_alter_box_orderedip'), ('base', '0031_auto_20210919_2047')]

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Box',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.GenericIPAddressField()),
                ('hostname', models.CharField(blank=True, max_length=200, null=True)),
                ('active', models.BooleanField(default=False)),
                ('comments', models.TextField(blank=True, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('state', models.CharField(blank=True, max_length=200, null=True)),
                ('os', models.CharField(blank=True, max_length=200, null=True)),
                ('pwned', models.BooleanField(default=False)),
                ('new', models.BooleanField(default=True)),
                ('updated', models.BooleanField(default=False)),
                ('cidr', models.CharField(blank=True, default='/24', max_length=200, null=True)),
                ('orderedip', models.BigIntegerField(blank=True, default=0, null=True)),
                ('comeback', models.BooleanField(default=False, verbose_name='Come back to this box')),
                ('unrelated', models.BooleanField(default=False)),
            ],
            options={
                'ordering': ['orderedip'],
            },
        ),
        migrations.CreateModel(
            name='BoxService',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('port', models.IntegerField(blank=True)),
                ('cBox', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.box')),
                ('name', models.TextField(blank=True, null=True)),
                ('protocol', models.CharField(blank=True, max_length=200)),
                ('state', models.TextField(blank=True, null=True)),
                ('version', models.TextField(blank=True, null=True)),
                ('script', models.TextField(blank=True, null=True)),
                ('new', models.BooleanField(default=True)),
                ('updated', models.TextField(blank=True, default=None, null=True)),
            ],
            options={
                'ordering': ['port'],
            },
        ),
    ]
