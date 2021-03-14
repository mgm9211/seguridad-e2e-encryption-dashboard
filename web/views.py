from django.shortcuts import render
from web.models import Device, Information
from web.functions import add_device


def index(request):
    context = {}

    all_devices = None
    if Device.objects.filter(visible=True):
        all_devices = Device.objects.filter(visible=True)
    context['all_devices'] = all_devices

    last_information = None
    if Information.objects.all():
        last_information = Information.objects.all().order_by('created_at')[:15]
    context['last_information'] = last_information

    all_types_device = {
        'dht11': 'DHT11',
        'light': 'Light',
        'pir_sensor': 'PIR Sensor',
    }
    context['all_types_device'] = all_types_device

    if request.POST:
        if 'add_device' in request.POST:
            name = None
            if 'name_device' in request.POST and request.POST['name_device']:
                name = request.POST['name_device']
            ip = None
            if 'ip_device' in request.POST and request.POST['ip_device']:
                ip = request.POST['ip_device']
            type_device = None
            if 'type_device' in request.POST and request.POST['type_device']:
                type_device = request.POST['type_device']
            add_device(name, ip, type_device)

    return render(request, "dashboard.html", context)


def tables(request):
    context = {}


    return render(request, "tables.html", context)