# Generated by Django 5.0.8 on 2024-08-21 13:43

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App1', '0004_superadmin_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CommGroup',
            fields=[
                ('CommGroup_name', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('CommGroup_code', models.CharField(max_length=10, unique=True)),
                ('soft_key', models.CharField(max_length=50)),
                ('activation_key', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('phoneNo', models.CharField(max_length=15)),
                ('address', models.TextField()),
                ('logo', models.ImageField(blank=True, null=True, upload_to='')),
            ],
        ),
        migrations.CreateModel(
            name='Department',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('department_name', models.CharField(max_length=50)),
                ('header_note', models.CharField(max_length=100)),
                ('footer_note', models.CharField(max_length=100)),
                ('commGroup', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='App1.commgroup')),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=30, unique=True)),
                ('login_name', models.CharField(max_length=50)),
                ('password', models.CharField(max_length=255)),
                ('password_duration', models.PositiveIntegerField(default=30)),
                ('role', models.CharField(max_length=50)),
                ('status', models.CharField(choices=[('Active', 'Active'), ('Inactive', 'Inactive')], default='Active', max_length=10)),
                ('accessible_departments', models.ManyToManyField(blank=True, related_name='accessible_departments', to='App1.department')),
                ('commGroup', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='App1.commgroup')),
                ('department', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='App1.department')),
            ],
        ),
    ]