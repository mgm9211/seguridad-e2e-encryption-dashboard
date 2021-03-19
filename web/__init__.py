from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat
from cryptography.hazmat.primitives import serialization


# Create private key and params when application start
parameters = dh.generate_parameters(generator=2, key_size=512)
private_key = parameters.generate_private_key()
pk = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, serialization.NoEncryption())
public_key = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
params = parameters.parameter_bytes(encoding=Encoding.PEM, format=serialization.ParameterFormat.PKCS3)

file = open('public_key.key', 'wb')  # Open the file as wb to write bytes
file.write(public_key)  # The key is type bytes still
file.close()

file = open('parameters.key', 'wb')  # Open the file as wb to write bytes
file.write(params)  # The key is type bytes still
file.close()

file = open('parameters.key', 'wb')  # Open the file as wb to write bytes
file.write(params)  # The key is type bytes still
file.close()

file = open('private_key.key', 'wb')  # Open key', 'w')  # Open the file as wb to write bytes
file.write(pk)  # The key is type bytes still
file.close()

