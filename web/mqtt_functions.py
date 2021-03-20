import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.fernet import Fernet
from web.functions import check_device, save_sensor_data, save_light_data, save_pir_sensor_data
from .functions import update_device
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
    if topic == 'SPEA/DHT11/device_sync':
        # Take device info from received_message, and store it in Database
        device_type = received_message['DeviceType']
        device_identifier = received_message['Identifier']
        device_ip = received_message['IP']
        device_bytes_pk = received_message['PublicKey'].encode('UTF-8')
        device_pk = load_pem_public_key(data=device_bytes_pk)
        with open('./private_key.key', 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=None)

        shared_key = private_key.exchange(device_pk)

        fernet_parameters = PBKDF2HMAC(algorithm=hashes.SHA256(),
                                       length=32,
                                       salt=b'',
                                       iterations=100000)
        # Password to be used in Fernet key derivation
        fernet_password = base64.urlsafe_b64encode(fernet_parameters.derive(shared_key))
        update_device(name=device_identifier, type=device_type, public_key=fernet_password.decode('UTF-8'), ip=device_ip)

    elif topic == 'SPEA/DHT11/sensor_data':
        encrypted_message = received_message['Message']
        device_identifier = received_message['Identifier']
        fernet_password_byte = Device.objects.get(name=device_identifier).key_public.encode('UTF-8')
        fernet_key = Fernet(fernet_password_byte)
        message = json.loads(fernet_key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
        save_sensor_data({
            'Identifier': device_identifier,
            'Temperature': message['Temperature'],
            'Humidity': message['Humidity'],
        })

    elif topic == 'SPEA/LIGHT/device_status':
        # Light send status messages
        encrypted_message = received_message['Message']
        device_identifier = received_message['Identifier']
        fernet_password_byte = Device.objects.get(name=device_identifier).key_public.encode('UTF-8')
        fernet_key = Fernet(fernet_password_byte)
        message = json.loads(fernet_key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
        save_light_data({
            'Identifier': device_identifier,
            'Status': message['Status']
        })

    elif topic == 'SPEA/PIR/sensor_data':
        # Light send status messages
        encrypted_message = received_message['Message']
        device_identifier = received_message['Identifier']
        fernet_password_byte = Device.objects.get(name=device_identifier).key_public.encode('UTF-8')
        fernet_key = Fernet(fernet_password_byte)
        message = json.loads(fernet_key.decrypt(encrypted_message.encode('UTF-8')).decode('UTF-8'))
        save_pir_sensor_data({
            'Identifier': device_identifier,
            'Detection': message['Detection']
        })
