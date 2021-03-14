import paho.mqtt.client as mqtt
from cryptography.fernet import Fernet
import time
import logging
import json
import random
import socket


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
    client.subscribe(f'SPEA/*/*')
    print('-----------------suscrito a los topic de SPEA')


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
    print('------------- MESSAGE RECEIVED OVER TOPIC ', topic)
    if topic == f'SPEA/DHT11/device_sync':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))
    elif topic == f'SPEA/PIR/device_sync':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))
    elif topic == f'SPEA/LIGHT/device_sync':
        key_file = open('encryption_files/key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message['Message'].encode("UTF-8")).decode("UTF-8"))


# Defining MQTT Client, using paho library
clientMQTT = mqtt.Client()
# On Connection callbacks, function that execute when the connection to Client is completed
clientMQTT.on_connect = connection
# On Message callbacks, function that execute when a message in subscribed topic is received
clientMQTT.on_message = on_message

# Setting username and password
clientMQTT.username_pw_set(username="translucentchopper874", password="QaZzAG8uYP06L8Dk")
# Connect to shiftr.io MQTT Client, using the url of the instace
clientMQTT.connect("translucentchopper874.cloud.shiftr.io", 1883, 60)
clientMQTT.loop_start()