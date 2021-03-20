import base64

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_parameters
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64decode
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
    client.subscribe(f'SPEA/{identifier}/register')
    client.subscribe(f'SPEA/{identifier}/config')
    client.subscribe(f'SPEA/{identifier}/switch')
    logging.info('SUBSCRIBED TO TOPICS:')
    logging.info(f'SPEA/{identifier}/register')
    logging.info(f'SPEA/{identifier}/config')
    logging.info(f'SPEA/{identifier}/switch')


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
    global identifier, shared_key, secure_channel, private_key, derived_key, parameters, platform_pk, register_message
    if topic == f'SPEA/{identifier}/register':
        # IoT platform sends registration messages
        received_data = json.loads(received_message)
        parameters = received_data['Parameters'].encode('UTF-8')
        platform_pk = received_data['PublicKey'].encode('UTF-8')
        register_message = True

    elif topic == f'SPEA/{identifier}/config':
        received_data = json.loads(received_message)
        global time_sleep
        time_sleep = received_data['TimeInterval']
        logging.info(f'CONFIG MESSAGE ARRIVED: {received_data["TimeInterval"]}')

    elif f'SPEA/{identifier}/switch':
        global led_status
        led_status ^= 1


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


def create_public_key():
    global private_key
    return private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


# Setting up logger to show info in terminal
logging.basicConfig(level=logging.INFO, format="%(asctime)s%(process)d: %(message)s")
# Read device identifier by promp input. Must be in IoT platform or data send by this device will be ignored
identifier = input("Please enter Light identifier (must be unique in IoT Platform): ")
# Sleep time, interval between reads
time_sleep = 60
# Create device private key with 512 bytes
# Defining MQTT Client, using paho library
clientMQTT = mqtt.Client()
# On Connection callbacks, function that execute when the connection to Client is completed
clientMQTT.on_connect = connection
# On Message callbacks, function that execute when a message in subscribed topic is received
clientMQTT.on_message = on_message
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
logging.info(f'DEVICE IDENTIFIER: {identifier}, DEVICE IP: {host_ip}')

# Setting username and password
clientMQTT.username_pw_set(username="translucentchopper874", password="QaZzAG8uYP06L8Dk")
# Connect to shiftr.io MQTT Client, using the url of the instace
clientMQTT.connect("translucentchopper874.cloud.shiftr.io", 1883, 60)
clientMQTT.loop_start()
# Parameters for private key creation placeholder
parameters = None
register_message = False
# IoT platform public key placeholder
platform_pk = b''
logging.info('WAITING IoT Platform registration message')
# Wait until platform register message
while not register_message:
    pass

# Load parameters from received bytes
private_key_parameters = load_pem_parameters(parameters)
private_key = private_key_parameters.generate_private_key()
# Serialize IoT platform public key to DHPublicKey
key = load_pem_public_key(data=platform_pk)
# Construct shared key, it will be used as Fernet secret
shared_key = private_key.exchange(key)

# Register message is send to synchronize with IoT platform
pk = create_public_key()
print(f'SHARED KEY: {shared_key}')
# Publish synchronize message, this is necessary to complete IoT platform registration
sync_data = {
    'DeviceType': 'light',
    'Identifier': identifier,
    'IP': host_ip,
    'PublicKey': pk.decode('UTF-8')
}

clientMQTT.publish(topic='SPEA/LIGHT/device_sync', payload=json.dumps(sync_data), qos=1)

# Now that the secure channel is created, it is time to create the derived key
# Fernet key parameters derived from Diffie Hellman
fernet_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                               length=32,
                               salt=b'',
                               iterations=100000)
# Password to be used in Fernet key derivation
fernet_password = base64.urlsafe_b64encode(fernet_parameters.derive(shared_key))
# Wait until IoT platform send the Fernet Key
fernet_key = Fernet(fernet_password)
# Initially light is off
led_status = 0
# Infinite loop simulating DHT11 sensor behaviour
while True:
    # Create json with simulated light status. This json will be encrypted and send through MQTT message
    data = {
        'Identifier': identifier,
        'Status': led_status,
        'Timestamp': time.ctime()
    }
    # Transform json object to string, this is necessary to encrypt it.
    bytes_json = json.dumps(data).encode('utf-8')
    # Encrypt message using key file
    message = fernet_key.encrypt(bytes_json)
    payload = {
        'Identifier': identifier,
        'Message': message.decode('utf-8'),
        'Timestamp': time.ctime()
    }
    logging.info('STATUS SWITCHED')
    # Publish message over selected topic
    clientMQTT.publish(topic='SPEA/LIGHT/device_status', payload=json.dumps(payload), qos=1)
    # Change led_status value
    led_status ^= 1
    time.sleep(time_sleep)
