from cryptography.hazmat.primitives.ciphers.aead import AESCCM

key = AESCCM.generate_key(bit_length=128)
print(key)
file = open('keyAES.key', 'wb')  # Open the file as wb to write bytes
file.write(key)  # The key is type bytes still
file.close()
