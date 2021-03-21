from django.db import models
# Create your models here.


class Device(models.Model):
    TYPE_CHOICES = (
        ('dht11', 'DHT11'),
        ('light', 'Light'),
        ('pir_sensor', 'PIR Sensor'),
    )
    ALGORITHMS_CHOICES = (
        ('aead', 'AEAD'),
        ('fernet', 'Fernet'),
    )
    type = models.CharField(max_length=16, choices=TYPE_CHOICES, blank=True, null=True)
    algorithm = models.CharField(max_length=16, choices=ALGORITHMS_CHOICES, blank=True, null=True)
    name = models.CharField(max_length=16, blank=True, null=False, unique=True)
    ip = models.CharField(max_length=16, blank=True, null=True)
    key_public = models.CharField(max_length=512, blank=True, null=False)
    visible = models.BooleanField()


class Information(models.Model):
    device = models.ForeignKey(Device, models.DO_NOTHING, blank=True, null=True)
    temperature = models.CharField(max_length=8, blank=True, null=True)
    humidity = models.CharField(max_length=4, blank=True, null=True)
    led_status = models.BooleanField(default=False)
    pir_sensor_status = models.BooleanField(default=False)
    created_at = models.DateTimeField()
    visible = models.BooleanField(default=True)

