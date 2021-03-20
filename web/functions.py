import datetime
from web.models import Device, Information


# Datos recibidos por MQTT
def check_device(data_dic):
    name = data_dic['Identifier']
    type = data_dic['DeviceType']
    ip = data_dic['IP']
    if not Device.objects.filter(name=name, visible=True).exists():
        add_device(name, type, ip)
    else:
        update_device(name, type, ip)


def save_sensor_data(data_dic):
    name = data_dic['Identifier']
    temperature = data_dic['Temperature']
    humidity = data_dic['Humidity']
    if Device.objects.filter(name=name, visible=True).exists():
        device = Device.objects.get(name=name)
        now = datetime.datetime.now()
        Information.objects.create(device=device, temperature=temperature, humidity=humidity,
                                   created_at=now)


def save_light_data(data_dic):
    name = data_dic['Identifier']
    status = data_dic['Status']
    if Device.objects.filter(name=name, visible=True).exists():
        device = Device.objects.get(name=name)
        now = datetime.datetime.now()
        Information.objects.create(device=device, led_status=status,
                                   created_at=now)


def save_pir_sensor_data(data_dic):
    name = data_dic['Identifier']
    detection = data_dic['Detection']
    if Device.objects.filter(name=name, visible=True).exists():
        device = Device.objects.get(name=name)
        now = datetime.datetime.now()
        Information.objects.create(device=device, pir_sensor_status=detection,
                                   created_at=now)


def add_device(name, type, ip=None):
    if not Device.objects.filter(name=name).exists():
        if not ip:
            ip = None
        Device.objects.create(name=name, type=type, ip=ip, visible=True)


def update_device(name, type, public_key, ip=None):
    Device.objects.filter(name=name).update(type=type, ip=ip, key_public=public_key)


def delete_device(name):
    Device.objects.filter(name=name).update(visible=False)


def generate_key(name):
    if Device.objects.filter(name=name).exists():
        pass
