import os
import time
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import paho.mqtt.client as mqtt
import json
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
    client.subscribe('SPEA/DHT11/device_sync')


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
    key_file = open('key.key', 'rb')  # Open the file as wb to read bytes
    fernet = Fernet(key_file.read())
    received__data = fernet.decrypt(data['Message'].encode("UTF-8"))
    received_data = json.loads(received__data)
    global shared_key, secure_channel, private_key
    # Transform string message to bytes
    public_key = received_data['PublicKey'].encode('UTF-8')
    # Serialize bytes to public key DH object
    key = load_pem_public_key(data=public_key)
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
public_key = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()

# Register message is send to synchronize with IoT platform
sync_data = {
    'PublicKey': public_key
}
shared_key = b''
secure_channel = False
while not secure_channel:
    pass

time.sleep(20)
# Publish synchronize message, this is necessary to complete IoT platform registration
clientMQTT.publish(topic='SPEA/dht11/exchange', payload=json.dumps(sync_data), qos=1)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b''
).derive(shared_key)
fernet_key = Fernet.generate_key()
iv = os.urandom(16)
cipher = Cipher(algorithm=algorithms.AES(derived_key), mode=modes.CBC(iv))
encryptor = cipher.encryptor()
padder = padding.PKCS7(128).padder()
padded_data = padder.update(fernet_key)
padded_data += padder.finalize()

json_data = {
    'IV': b64encode(iv).decode('utf-8'),
    'Timestamp': time.ctime(),
    'FernetKey': padded_data.decode('UTF-8')
}
clientMQTT.publish(topic='SPEA/dht11/fernet_key', payload=json.dumps(json_data), qos=1)

time.sleep(60)
