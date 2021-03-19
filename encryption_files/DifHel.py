from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

parameters = dh.generate_parameters(generator=2, key_size=512)
a_private = parameters.generate_private_key()
a_public = a_private.public_key()
print(f'TYPE: {a_public}')

b_private = parameters.generate_private_key()
b_public = b_private.public_key()

aShare = a_private.exchange(b_public)
bShare = b_private.exchange(a_public)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b''
).derive(aShare)

same_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'',
).derive(bShare)

print(aShare == bShare)

iv = os.urandom(16)
cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
encryptor = cipher.encryptor()
secret = open('key.key','rb').read()
secret2 = Fernet.generate_key()
print(secret2)
padder = padding.PKCS7(128).padder()
padded_data = padder.update(secret2)
padded_data += padder.finalize()
ct = encryptor.update(padded_data) + encryptor.finalize()
decryptor = cipher.decryptor()
dt = decryptor.update(ct) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
data = unpadder.update(dt)
data += unpadder.finalize()
print(data)
