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
    client.subscribe(f'SPEA/{identifier}/exchange')
    client.subscribe(f'SPEA/{identifier}/fernet_key')
    logging.info('SUBSCRIBED TO TOPICS:')
    logging.info(f'SPEA/{identifier}/register')
    logging.info(f'SPEA/{identifier}/config')
    logging.info(f'SPEA/{identifier}/exchange')
    logging.info(f'SPEA/{identifier}/fernet_key')


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

    elif topic == f'SPEA/{identifier}/exchange':
        received_data = json.loads(msg.payload)

        # Transform string message to bytes
        received_public_key = received_data['PublicKey'].encode('UTF-8')
        print(f'RECEIVED PUBLIC KEY: {received_public_key}')
        # Serialize bytes to public key DH object
        key = load_pem_public_key(data=received_public_key)
        print(f'CONSTRUCTED PUBLIC KEY: {key}')
        shared_key = private_key.exchange(key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b''
        ).derive(shared_key)
        logging.info(f'DIFFIE HELLMAN STARTS, PLATFORM KEY: {shared_key}')
        secure_channel = True

    elif topic == f'SPEA/{identifier}/fernet_key':
        # IoT platform sends the IV, Timestamp and Fernet Key

        # Message arrives in string format, so it is necessary to serialize it to JSON
        received_message = json.loads(msg.payload)
        # TODO: revisar que el timestamp es más o menos cercano a la fecha del sistema
        timestamp = received_message['Timestamp']
        iv = b64decode(received_message['IV'].encode('UTF-8'))
        # Decrypt message with derived key
        encrypted_fernet_key = received_message['FernetKey'].encode('UTF-8')
        # Create a cipher to get AES instance. CBC mode use block cipher
        cipher = Cipher(algorithm=algorithms.AES(derived_key), mode=modes.CBC(iv))
        decryptor = cipher.encryptor()
        # Decrypt data
        decrypted_fernet_key = decryptor.update(encrypted_fernet_key) + decryptor.finalize()

        # Prepare encrypted data unpadding it in case original plain text wasn't long enough
        unpadder = padding.PKCS7(128).unpadder()
        print(f'UNPADDER: {unpadder}')
        unpadded_data = unpadder.update(decrypted_fernet_key) + unpadder.finalize()
        print(f'UPADDED DARA: {unpadded_data}')
        fernet_key = unpadded_data
        logging.info(f'NEGOCIATED FERNET KEY {fernet_key}')


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
identifier = input("Please enter PIR sensor identifier (must be unique in IoT Platform): ")
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
    'DeviceType': 'pir_sensor',
    'Identifier': identifier,
    'IP': host_ip,
    'PublicKey': pk.decode('UTF-8')
}

clientMQTT.publish(topic='SPEA/PIR/device_sync', payload=json.dumps(sync_data), qos=1)

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
gelleta = fernet_key.encrypt(b'GALLETA')
file = open('galleta.key', 'wb')  # Open the file as wb to write bytes
file.write(gelleta)  # The key is type bytes still
file.close()
# Infinite loop simulating DHT11 sensor behaviour
while True:
    # Create json with simulated sensor data. This json will be encrypted and send through MQTT message
    data = {
        'Detection': 1,
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
    logging.info('PIR SENSOR ACTIVATED')
    # Publish message over selected topic, only if presence is detected
    if data['Detection'] == 1:
        clientMQTT.publish(topic='SPEA/PIR/sensor_data', payload=json.dumps(payload), qos=1)

    time.sleep(random.randint(10, 100))
