from django.shortcuts import render, redirect
from web.mqtt_functions import connection, on_message
from web.models import Device, Information
from web.functions import add_device, delete_device
import paho.mqtt.client as mqtt


connected = False


def index(request):
    context = {}

    if not connected:
        # Defining MQTT Client, using paho library
        clientMQTT = mqtt.Client()
        # On Connection callbacks, function that execute when the connection to Client is completed
        clientMQTT.on_connect = connection
        # Setting username and password
        clientMQTT.username_pw_set(username="translucentchopper874", password="QaZzAG8uYP06L8Dk")
        # Connect to shiftr.io MQTT Client, using the url of the instace
        clientMQTT.connect("translucentchopper874.cloud.shiftr.io", 1883, 60)
        clientMQTT.loop_start()
        # On Message callbacks, function that execute when a message in subscribed topic is received
        clientMQTT.on_message = on_message

    all_devices = None
    if Device.objects.filter(visible=True):
        all_devices = Device.objects.filter(visible=True)
    context['all_devices'] = all_devices

    last_information = None
    if Information.objects.all():
        last_information = Information.objects.filter(device__visible=True).order_by('created_at')[:15]
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
            type_device = None
            if 'type_device' in request.POST and request.POST['type_device']:
                type_device = request.POST['type_device']
            add_device(name, type_device)
            return redirect('index')
        elif 'delete_device' in request.POST:
            name = request.POST['delete_device']
            delete_device(name)
            return redirect('index')

    return render(request, "dashboard.html", context)


def tables(request):
    context = {}


    return render(request, "tables.html", context)