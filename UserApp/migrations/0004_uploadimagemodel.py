# Generated by Django 5.1.6 on 2025-02-12 12:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('UserApp', '0003_medicalimage_encryption_duration_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='UploadImageModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(upload_to='static\\MedicalImages')),
                ('image_name', models.CharField(max_length=255)),
                ('encrypted_image', models.BinaryField()),
                ('private_key', models.BinaryField()),
                ('public_key', models.BinaryField()),
                ('username', models.BinaryField()),
                ('email', models.EmailField(max_length=254)),
                ('imgtype', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'UploadImageModel',
            },
        ),
    ]
