import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

data = b"a secret message"
ts = time.ctime().encode()
key = open('keyAES.key','rb').read()
print(key)
nonce = os.urandom(13)
aes = AESCCM(key)
ct = aes.encrypt(nonce, data, ts)
print(ct)
dc = aes.decrypt(nonce, ct, ts)
print(dc)
