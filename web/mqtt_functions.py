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
    # Message arrived with string format, so it needed to transform to dict object.
    received_message = json.loads(msg.payload)
    # Topic of the incoming message
    topic = msg.topic

    if topic == 'SPEA/DHT11/sensor_data':
        # A DHT11 device send sensor data
        # Message with data is encrypted
        encrypted_message = received_message['Message']
        # Get device identifier
        device_identifier = received_message['Identifier']
        # Check if device are registered in the IoT Platform
        if Device.objects.filter(name=device_identifier).exists():
            device = Device.objects.get(name=device_identifier)
            # Check device encryption algorithm
            algorithm = device.algorithm
            # Get device's storage password, and encode to bytes
            password_byte = device.key_public.encode('UTF-8')
            key = None
            if algorithm and algorithm == 'fernet':
                # Generate Fernet key with storage password
                key = Fernet(password_byte)
                # Decrypt message and transform to dictionary (JSON format)
                # It is necessary to transform received encrypted message to bytes, and then decode it to string
                message = json.loads(key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
            elif algorithm and algorithm == 'aead':
                # Decode storage password with base 64 format
                password = base64.b64decode(password_byte)
                # Create AEAD key with decoded password
                key = AESCCM(password)
                # Read arrived IV
                iv = base64.b64decode(received_message['IV'].encode('UTF-8'))
                # Read arrived time stamp
                timestamp = received_message['Timestamp'].encode()
                # It is necessary to encode the message to bytes, and apply base 64 decode before decrypt it
                encrypted_message = base64.b64decode(received_message['Message'].encode('UTF-8'))
                # Decrypt message, using IV as nonce and timestamp as associated data
                message = json.loads(key.decrypt(data=encrypted_message, nonce=iv, associated_data=timestamp))
            if key:
                save_sensor_data({
                    'Identifier': device_identifier,
                    'Temperature': message['Temperature'],
                    'Humidity': message['Humidity'],
                })

    elif topic == 'SPEA/LIGHT/device_status':
        # A LIGHT device send sensor data
        # Message with data is encrypted
        encrypted_message = received_message['Message']
        # Get device identifier
        device_identifier = received_message['Identifier']
        # Check if device are registered in the IoT Platform
        if Device.objects.filter(name=device_identifier).exists():
            device = Device.objects.get(name=device_identifier)
            # Check device encryption algorithm
            algorithm = device.algorithm
            # Get device's storage password, and encode to bytes
            password_byte = device.key_public.encode('UTF-8')
            if algorithm and algorithm=='fernet':
                # Generate Fernet key with storage password
                key = Fernet(password_byte)
                # Decrypt message and transform to dictionary (JSON format)
                # It is necessary to transform received encrypted message to bytes, and then decode it to string
                message = json.loads(key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
            elif algorithm and algorithm=='aead':
                # Decode storage password with base 64 format
                password = base64.b64decode(password_byte)
                # Create AEAD key with decoded password
                key = AESCCM(password)
                # Read arrived IV
                iv = base64.b64decode(received_message['IV'].encode('UTF-8'))
                # Read arrived time stamp
                timestamp = received_message['Timestamp'].encode()
                # It is necessary to encode the message to bytes, and apply base 64 decode before decrypt it
                encrypted_message = base64.b64decode(received_message['Message'].encode('UTF-8'))
                # Decrypt message, using IV as nonce and timestamp as associated data
                message = json.loads(key.decrypt(data=encrypted_message, nonce=iv, associated_data=timestamp))
            if key:
                save_light_data({
                    'Identifier': device_identifier,
                    'Status': message['Status']
                })

    elif topic == 'SPEA/PIR/sensor_data':
        # A DHT11 device send sensor data
        # Message with data is encrypted
        encrypted_message = received_message['Message']
        # Get device identifier
        device_identifier = received_message['Identifier']
        # Check if device are registered in the IoT Platform
        if Device.objects.filter(name=device_identifier).exists():
            device = Device.objects.get(name=device_identifier)
            # Check device encryption algorithm
            algorithm = device.algorithm
            # Get device's storage password, and encode to bytes
            password_byte = device.key_public.encode('UTF-8')
            if algorithm and algorithm == 'fernet':
                # Generate Fernet key with storage password
                key = Fernet(password_byte)
                # Decrypt message and transform to dictionary (JSON format)
                # It is necessary to transform received encrypted message to bytes, and then decode it to string
                message = json.loads(key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
            elif algorithm and algorithm == 'aead':
                # Decode storage password with base 64 format
                password = base64.b64decode(password_byte)
                # Create AEAD key with decoded password
                key = AESCCM(password)
                # Read arrived IV
                iv = base64.b64decode(received_message['IV'].encode('UTF-8'))
                # Read arrived time stamp
                timestamp = received_message['Timestamp'].encode()
                # It is necessary to encode the message to bytes, and apply base 64 decode before decrypt it
                encrypted_message = base64.b64decode(received_message['Message'].encode('UTF-8'))
                # Decrypt message, using IV as nonce and timestamp as associated data
                message = json.loads(key.decrypt(data=encrypted_message, nonce=iv, associated_data=timestamp))
            if key:
                save_pir_sensor_data({
                    'Identifier': device_identifier,
                    'Detection': message['Detection']
                })

    elif 'device_sync' in topic:
        # Device sends synchronize messages
        # Take device info from received_message, and store it in Database
        device_type = received_message['DeviceType']
        device_identifier = received_message['Identifier']
        device_ip = received_message['IP']
        device_bytes_pk = received_message['PublicKey'].encode('UTF-8')
        device_pk = load_pem_public_key(data=device_bytes_pk)

        # Check public key HMAC to ensure it integrity
        received_hmac = base64.b64decode(received_message['HMAC'].encode('utf-8'))
        received_iv = base64.b64decode(received_message['IV'].encode('utf-8'))
        own_hmac = hmac.HMAC(received_iv, hashes.SHA256())

        own_hmac.update(device_bytes_pk)
        try:
            own_hmac.verify(received_hmac)
            # Read platform private key, needed to derive shared key
            with open('./private_key.key', 'rb') as f:
                private_key = load_pem_private_key(f.read(), password=None)

            shared_key = private_key.exchange(device_pk)
            algorithm = received_message['Algorithm']

            password = ''
            # Check device encryption algorithm
            if algorithm == 'Fernet':
                # Generate the Fernet parameters, used to derive Fernet key
                fernet_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                                               length=32,
                                               salt=b'',
                                               iterations=100000)
                # Password to be used in Fernet key derivation, storage in DB as string.
                password = base64.urlsafe_b64encode(fernet_parameters.derive(shared_key))
            elif algorithm == 'AEAD':
                # Generate the AEAD parameters, used to derive AEAD key
                AES_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                                            length=32,
                                            salt=b'',
                                            iterations=100000)
                # Password to be used in AEAD key derivation, storage in DB as string.
                password = base64.b64encode(AES_parameters.derive(shared_key))

            if password:
                # Update device in data base
                update_device(name=device_identifier, type=device_type, algorithm=str.lower(algorithm), ip=device_ip,
                              public_key=password.decode('UTF-8'))
        except Exception:
            print('------------HMAC INCORRECTO')


def update_led_mqtt(device, clientMQTT):
    # Method to send switch message to light device
    # Get device password
    password_byte = device.key_public.encode('UTF-8')
    # Check device encryption algorithm
    if device.algorithm and device.algorithm == 'fernet':
        # Generate Fernet key
        fernet_key = Fernet(password_byte)
        # Encrypt secret message that light device check to ensure that IoT platform is sending the message.
        secret = fernet_key.encrypt(b'Require switch').decode('UTF-8')
        data = {
            'Secret': secret
        }
    if device.algorithm and device.algorithm == 'aead':
        # Generate AEAD key
        password = base64.b64decode(password_byte)
        key = AESCCM(password)
        iv = os.urandom(13)
        timestamp = time.ctime().encode()
        # Encrypt secret message that light device check to ensure that IoT platform is sending the message.
        secret = key.encrypt(data=b'Require switch', nonce=iv, associated_data=timestamp)
        data = {
            'Secret': base64.b64encode(secret).decode('utf-8'),
            'IV': base64.b64encode(iv).decode('utf-8'),
            'Timestamp': timestamp.decode()
        }
    # Publish switch message on the MQTT Broker
    clientMQTT.publish(topic='SPEA/' + device.name + '/switch', payload=json.dumps(data), qos=1)