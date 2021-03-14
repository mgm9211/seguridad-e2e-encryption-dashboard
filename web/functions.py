from web.models import Device


def add_device(name, type):
    if not Device.objects.filter(name=name).exists():
        Device.objects.create(name=name, type=type, visible=True)