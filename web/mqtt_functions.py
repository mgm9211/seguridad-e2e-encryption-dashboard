import json
from cryptography.fernet import Fernet
from web.functions import check_device, save_sensor_data


def connection(client, userdata, flags, rc):
    """
    Method to subcribe to given topic
    :param client: MQTT client created with paho
    :param userdata:
    :param flags:
    :param rc:
    :return:
    """
    # Suscripcion a todos los topic de SPEA
    client.subscribe('SPEA/*/*')


def on_message(client, userdata, msg):
    """
    Logic to apply when message is received
    :param client:
    :param userdata:
    :param msg:
    :return:
    """
    received_message = json.loads(msg.payload)
    topic = msg.topic
    received_data = {}
    received_sensor_data = {}
    if topic == 'SPEA/DHT11/device_sync':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))
    elif topic == 'SPEA/PIR/device_sync':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))
    elif topic == 'SPEA/LIGHT/device_sync':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))
    elif topic == 'SPEA/DHT11/sensor_data':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_sensor_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))
    if received_data:
        check_device(received_data)
    elif received_sensor_data:
        save_sensor_data(received_sensor_data)