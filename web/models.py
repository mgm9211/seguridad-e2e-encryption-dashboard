from django.db import models
# Create your models here.


# class AuthUser(models.Model):
#     password = models.CharField(max_length=128)
#     last_login = models.DateTimeField(blank=True, null=True)
#     is_superuser = models.IntegerField()
#     username = models.CharField(unique=True, max_length=150)
#     first_name = models.CharField(max_length=30)
#     last_name = models.CharField(max_length=150)
#     email = models.CharField(max_length=254)
#     is_staff = models.IntegerField()
#     is_active = models.IntegerField()
#     date_joined = models.DateTimeField()


class Device(models.Model):
    # user = models.ForeignKey(AuthUser, models.DO_NOTHING, blank=True, null=True)
    TYPE_CHOICES = (
        ('dht11', 'DHT11'),
        ('light', 'Light'),
        ('pir_sensor', 'PIR Sensor'),
    )
    type = models.CharField(max_length=16, choices=TYPE_CHOICES, blank=True, null=True)
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
