# Generated by Django 3.1.3 on 2021-05-04 14:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('mysite', '0002_auto_20210504_1741'),
    ]

    operations = [
        migrations.RenameField(
            model_name='menu',
            old_name='dish',
            new_name='list_of_dishes',
        ),
        migrations.RenameField(
            model_name='menu',
            old_name='price',
            new_name='total_price',
        ),
    ]
