from cryptography.fernet import Fernet
# Este fichero crea una nueva clave. No debe ejecutarse sin subirse para que todos compartan la misma clave.
key = Fernet.generate_key()
print(key)
file = open('key.key', 'wb')  # Open the file as wb to write bytes
file.write(key)  # The key is type bytes still
file.close()