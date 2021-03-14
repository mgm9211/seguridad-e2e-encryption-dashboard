from web.models import Device


def add_device(name, ip, type):
    print('----------creamos dispo')
    if not Device.objects.filter(name=name).exists():

        Device.objects.create(name=name, ip=ip, type=type, visible=True)