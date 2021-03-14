import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
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
    client.subscribe(f'SPEA/{identifier}/config')
    client.subscribe(f'SPEA/{identifier}/exchange')
    client.subscribe(f'SPEA/{identifier}/fernet_key')
    logging.info('SUBSCRIBED TO TOPICS:')
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
    global identifier
    if topic == f'SPEA/{identifier}/config':
        key_file = open('key.key', 'rb')  # Open the file as wb to read bytes
        fernet = Fernet(key_file.read())
        received_data = json.loads(fernet.decrypt(received_message).decode("UTF-8"))
        global time_sleep
        time_sleep = received_data['TimeInterval']
        logging.info(f'CONFIG MESSAGE ARRIVED: {received_data["TimeInterval"]}')

    elif topic == f'SPEA/{identifier}/exchange':
        received_data = json.loads(msg.payload)
        global shared_key, secure_channel, private_key
        # Transform string message to bytes
        public_key = received_data['PublicKey'].encode('UTF-8')
        # Serialize bytes to public key DH object
        key = load_pem_public_key(data=public_key)
        shared_key = private_key.exchange(key)
        logging.info(f'DIFFIE HELLMAN STARTS, PLATFORM KEY: {shared_key}')
        secure_channel = True

    elif topic == f'SPEA/{identifier}/fernet_key':
        # IoT platform sends the IV, Timestamp and Fernet Key
        global derived_key
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
        unpadded_data = unpadder.update(decrypted_fernet_key) + unpadder.finalize()
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


# Read device identifier by promp input. Must be in IoT platform or data send by this device will be ignored
identifier = input("Please enter DHT11 identifier (must be unique in IoT Platform): ")
# Sleep time, interval between reads
time_sleep = 60
# Create device private key with 512 bytes
parameters = dh.generate_parameters(generator=2, key_size=512)
private_key = parameters.generate_private_key()
# Placeholder for share key
shared_key = b''
secure_channel = False
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
pk = create_public_key()
sync_data = {
    'DeviceType': 'dht11',
    'Identifier': identifier,
    'IP': host_ip,
    'PublicKey': pk.decode('unicode_escape')
}
sync_message = encrypt_json(json_data=sync_data, key_name='key.key')
# Publish synchronize message, this is necessary to complete IoT platform registration
sync_message_json = {
    'Message': sync_message.decode('UTF-8'),
    'Timestamp': time.ctime()
}
clientMQTT.publish(topic='SPEA/DHT11/device_sync', payload=json.dumps(sync_message_json), qos=1)
# Wait for secure channel
while not secure_channel:
    pass

print(f'SHARED KEY: {shared_key}')
# Now that the secure channel is created, it is time to create the derived key
# The derived key is used to communicate through AES the Fernet key
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b''
).derive(shared_key)

# Wait until IoT platform send the Fernet Key
fernet_key = b''
fernet_wait = False
while not fernet_wait:
    pass

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
    logging.info('SENDING DATA')
    clientMQTT.publish(topic=f'SPEA/DHT11/sensor_data', payload=json.dumps(payload), qos=1)
    time.sleep(time_sleep)
