import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from getpass import getpass


class HybridEncryption:
    def __init__(self):
        self.backend = default_backend()

    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(self, plaintext, public_key):
        encrypted = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def rsa_decrypt(self, ciphertext, private_key):
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def camellia_encrypt(self, plaintext, key, iv):
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext

    def camellia_decrypt(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted


def main():
    hybrid = HybridEncryption()

    # Генерация пары ключей RSA
    private_key, public_key = hybrid.generate_rsa_keys()

    # Чтение текста из файла
    input_path = input("Введите путь до файла с текстом: ")
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Выбор ключа Camellia
    key_length = int(input("Выберите длину ключа Camellia (128, 192, 256): "))
    camellia_key = os.urandom(key_length // 8)
    iv = os.urandom(16)

    # Шифрование текста с использованием Camellia
    ciphertext = hybrid.camellia_encrypt(plaintext, camellia_key, iv)

    # Шифрование ключа Camellia с использованием RSA
    encrypted_key = hybrid.rsa_encrypt(camellia_key, public_key)

    # Расшифровка ключа Camellia с использованием RSA
    decrypted_key = hybrid.rsa_decrypt(encrypted_key, private_key)

    # Расшифровка текста с использованием Camellia
    decrypted_text = hybrid.camellia_decrypt(ciphertext, decrypted_key, iv)

if __name__ =="__main__":
    main()