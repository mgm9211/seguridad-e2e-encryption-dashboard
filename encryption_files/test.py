import base64
import os
import time
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import paho.mqtt.client as mqtt
import json

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from base64 import b64encode


def connection(client, userdata, flags, rc):
    """
    Method to subcribe to given topic
    :param client: MQTT client created with paho
    :param userdata:
    :param flags:
    :param rc:
    :return:
    """
    global identifier
    client.subscribe('SPEA/PIR/device_sync')


def on_message(client, userdata, msg):
    """
    Logic to apply when message is received
    :param client:
    :param userdata:
    :param msg:
    :return:
    """
    received_message = msg.payload
    data = json.loads(received_message)
    topic = msg.topic
    global shared_key, secure_channel, private_key
    # Transform string message to bytes
    received_public_key = data['PublicKey'].encode('UTF-8')
    print(f'PUBLIC KEY IOT: {received_public_key}')
    # Serialize bytes to public key DH object
    key = load_pem_public_key(data=received_public_key)
    shared_key = private_key.exchange(key)
    print(f'SHARED KEY {shared_key}')
    secure_channel = True

# Defining MQTT Client, using paho library
clientMQTT = mqtt.Client()
clientMQTT.on_connect = connection
# On Message callbacks, function that execute when a message in subscribed topic is received
clientMQTT.on_message = on_message
# Setting username and password
clientMQTT.username_pw_set(username="translucentchopper874", password="QaZzAG8uYP06L8Dk")
# Connect to shiftr.io MQTT Client, using the url of the instace
clientMQTT.connect("translucentchopper874.cloud.shiftr.io", 1883, 60)
clientMQTT.loop_start()

parameters = dh.generate_parameters(generator=2, key_size=512)
private_key = parameters.generate_private_key()
public_key = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('UTF-8')
# Register message is send to synchronize with IoT platform
params = parameters.parameter_bytes(encoding=Encoding.PEM, format=serialization.ParameterFormat.PKCS3).decode('UTF-8')
print(f'PARAMETROS:{params}')
sync_data = {
    'PublicKey': public_key,
    'Parameters': params
}
# Publish synchronize message, this is necessary to complete IoT platform registration
clientMQTT.publish(topic='SPEA/pir/register', payload=json.dumps(sync_data), qos=1)
shared_key = b''
secure_channel = False
while not secure_channel:
    pass

fernet_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                               length=32,
                               salt=b'',
                               iterations=100000)
# Password to be used in Fernet key derivation
fernet_password = base64.urlsafe_b64encode(fernet_parameters.derive(shared_key))

# Wait until IoT platform send the Fernet Key
fernet_key = Fernet(fernet_password)
time.sleep(20)
file = open('galleta.key', 'rb')  # Open the file as wb to write bytes
print(f'GALLETA?: {fernet_key.decrypt(file.read())}')
file.close()



time.sleep(60)
