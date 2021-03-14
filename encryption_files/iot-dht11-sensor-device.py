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
    logging.info(f'CONNECTED FLAGS {str(flags)} RESULT CODE {str(rc)} CLIENT1_ID')
    global identifier
    client.subscribe(f'SPEA/{identifier}/config')
    logging.info('SUBSCRIBED TO TOPICS:')
    logging.info(f'SPEA/{identifier}/config')


def on_message(client, userdata, msg):
    """
    Logic to apply when message is received
    :param client:
    :param userdata:
    :param msg:
    :return:
    """
    received_message = msg.payload
    topic = msg.topic
    logging.info(f'MESSAGE RECEIVED OVER TOPIC {topic}')
    global identifier
    if topic == f'SPEA/{identifier}/config':
        key_file = open('key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message).decode("UTF-8"))
        global time_sleep
        time_sleep = received_data['TimeInterval']
        logging.info(f'CONFIG MESSAGE ARRIVED: {received_data["TimeInterval"]}')


def encrypt_json(json_data, key_name):
    """
    Function to encrypt a dictionary object, transforming it to string
    :param json_data: dict with data to encrypt.
    :param key_name: string with key file name.
    :return: encrypted json in bytes.
    """
    # Transform json object to string, this is necessary to encrypt it.
    bytes_json = json.dumps(json_data).encode('utf-8')
    # Encrypt message using key file
    key_file = open(key_name, 'rb')  # Open the file as wb to read bytes
    fernet_instance = Fernet(key_file.read())
    return fernet_instance.encrypt(bytes_json)


# Read device identifier by promp input. Must be in IoT platform or data send by this device will be ignored
identifier = input("Please enter DHT11 identifier (must be unique in IoT Platform): ")
# Sleep time, interval between reads
time_sleep = 60
# Setting up logger to show info in terminal
logging.basicConfig(level=logging.INFO, format="%(asctime)s%(process)d: %(message)s")
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
logging.info(f'DEVICE IDENTIFIER: {identifier}, DEVICE IP: {host_ip}')
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

# Register message is send to synchronize with IoT platform
sync_data = {
    'DeviceType': 'DHT11',
    'Identifier': identifier,
    'IP': host_ip
}
sync_message = encrypt_json(json_data=sync_data, key_name='key.key')
# Publish synchronize message, this is necessary to complete IoT platform registration
sync_message_json = {
    'Message': sync_message.decode('UTF-8'),
    'Timestamp': time.ctime()
}
clientMQTT.publish(topic='SPEA/DHT11/device_sync', payload=json.dumps(sync_message_json), qos=1)
# Infinite loop simulating DHT11 sensor behaviour
while True:
    # Create json with simulated sensor data. This json will be encrypted and send through MQTT message
    data = {
        'Identifier': identifier,
        'Temperature': random.randint(30, 40),
        'Humidity': random.randint(30, 80)
    }
    # Transform json object to string, this is necessary to encrypt it.
    message = encrypt_json(json_data=data, key_name='key.key')
    payload = {
        'Message': message.decode('utf-8'),
        'Timestamp': time.ctime()
    }
    # Publish message over selected topic
    clientMQTT.publish(topic=f'SPEA/DHT11/sensor_data', payload=json.dumps(payload), qos=1)
    time.sleep(time_sleep)
