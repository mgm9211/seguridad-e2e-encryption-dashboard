from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.fernet import Fernet

import base64
import json, os, time

from web.functions import save_sensor_data, save_light_data, save_pir_sensor_data, update_device
from web.models import Device


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

    if topic == 'SPEA/DHT11/sensor_data':
        encrypted_message = received_message['Message']
        device_identifier = received_message['Identifier']
        if Device.objects.filter(name=device_identifier).exists():
            device = Device.objects.get(name=device_identifier)
            algorithm = device.algorithm
            password_byte = device.key_public.encode('UTF-8')
            key = None
            if algorithm and algorithm == 'fernet':
                key = Fernet(password_byte)
                message = json.loads(key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
            elif algorithm and algorithm == 'aead':
                password = base64.b64decode(password_byte)
                key = AESCCM(password)
                iv = base64.b64decode(received_message['IV'].encode('UTF-8'))
                timestamp = received_message['Timestamp'].encode()
                encrypted_message = base64.b64decode(received_message['Message'].encode('UTF-8'))
                message = json.loads(key.decrypt(data=encrypted_message, nonce=iv, associated_data=timestamp))
            if key:
                save_sensor_data({
                    'Identifier': device_identifier,
                    'Temperature': message['Temperature'],
                    'Humidity': message['Humidity'],
                })

    elif topic == 'SPEA/LIGHT/device_status':
        # Light send status messages
        encrypted_message = received_message['Message']
        device_identifier = received_message['Identifier']
        if Device.objects.filter(name=device_identifier).exists():
            device = Device.objects.get(name=device_identifier)
            algorithm = device.algorithm
            password_byte = device.key_public.encode('UTF-8')
            if algorithm and algorithm=='fernet':
                key = Fernet(password_byte)
                message = json.loads(key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
            elif algorithm and algorithm=='aead':
                password = base64.b64decode(password_byte)
                key = AESCCM(password)
                iv = base64.b64decode(received_message['IV'].encode('UTF-8'))
                timestamp = received_message['Timestamp'].encode()
                encrypted_message = base64.b64decode(received_message['Message'].encode('UTF-8'))
                message = json.loads(key.decrypt(data=encrypted_message, nonce=iv, associated_data=timestamp))
            if key:
                save_light_data({
                    'Identifier': device_identifier,
                    'Status': message['Status']
                })

    elif topic == 'SPEA/PIR/sensor_data':
        # Light send status messages
        encrypted_message = received_message['Message']
        device_identifier = received_message['Identifier']
        if Device.objects.filter(name=device_identifier).exists():
            device = Device.objects.get(name=device_identifier)
            algorithm = device.algorithm
            password_byte = device.key_public.encode('UTF-8')
            if algorithm and algorithm == 'fernet':
                key = Fernet(password_byte)
                message = json.loads(key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
            elif algorithm and algorithm == 'aead':
                password = base64.b64decode(password_byte)
                key = AESCCM(password)
                iv = base64.b64decode(received_message['IV'].encode('UTF-8'))
                timestamp = received_message['Timestamp'].encode()
                encrypted_message = base64.b64decode(received_message['Message'].encode('UTF-8'))
                message = json.loads(key.decrypt(data=encrypted_message, nonce=iv, associated_data=timestamp))
            if key:
                save_pir_sensor_data({
                    'Identifier': device_identifier,
                    'Detection': message['Detection']
                })

    elif 'device_sync' in topic:
        # Take device info from received_message, and store it in Database
        device_type = received_message['DeviceType']
        device_identifier = received_message['Identifier']
        device_ip = received_message['IP']
        device_bytes_pk = received_message['PublicKey'].encode('UTF-8')
        device_pk = load_pem_public_key(data=device_bytes_pk)

        received_hmac = base64.b64decode(received_message['HMAC'].encode('utf-8'))
        received_iv = base64.b64decode(received_message['IV'].encode('utf-8'))
        own_hmac = hmac.HMAC(received_iv, hashes.SHA256())

        own_hmac.update(device_bytes_pk)
        try:
            own_hmac.verify(received_hmac)
            with open('./private_key.key', 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None)

            shared_key = private_key.exchange(device_pk)
            algorithm = received_message['Algorithm']

            password = ''
            if algorithm == 'Fernet':
                fernet_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                                               length=32,
                                               salt=b'',
                                               iterations=100000)
                # Password to be used in Fernet key derivation
                password = base64.urlsafe_b64encode(fernet_parameters.derive(shared_key))
            elif algorithm == 'AEAD':
                AES_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                                            length=32,
                                            salt=b'',
                                            iterations=100000)
                # Password to be used in Fernet key derivation
                password = base64.b64encode(AES_parameters.derive(shared_key))

            if password:
                update_device(name=device_identifier, type=device_type, algorithm=str.lower(algorithm), ip=device_ip,
                              public_key=password.decode('UTF-8'))
        except Exception:
            print('------------HMAC INCORRECTO')


def update_led_mqtt(device, clientMQTT):
    password_byte = device.key_public.encode('UTF-8')
    if device.algorithm and device.algorithm == 'fernet':
        fernet_key = Fernet(password_byte)
        secret = fernet_key.encrypt(b'Require switch').decode('UTF-8')
        data = {
            'Secret': secret
        }
    if device.algorithm and device.algorithm == 'aead':
        password = base64.b64decode(password_byte)
        key = AESCCM(password)
        iv = os.urandom(13)
        timestamp = time.ctime().encode()
        secret = key.encrypt(data=b'Require switch', nonce=iv, associated_data=timestamp)
        data = {
            'Secret': base64.b64encode(secret).decode('utf-8'),
            'IV': base64.b64encode(iv).decode('utf-8'),
            'Timestamp': timestamp.decode()
        }
    clientMQTT.publish(topic='SPEA/' + device.name + '/switch', payload=json.dumps(data), qos=1)