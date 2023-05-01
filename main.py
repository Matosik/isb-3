import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def rsa_decrypt(self, ciphertext, private_key):
        decrypted = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def camellia_encrypt(self, plaintext, key, iv):
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    def camellia_decrypt(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        padded_decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_text = unpadder.update(padded_decrypted_text) + unpadder.finalize()

        return decrypted_text

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

    # Расшифровка ключа amellia с использованием RSA
    decrypted_key = hybrid.rsa_decrypt(encrypted_key, private_key)
    # Расшифровка текста с использованием Camellia
    decrypted_text = hybrid.camellia_decrypt(ciphertext, decrypted_key, iv)

    # Сравнение исходного текста и расшифрованного текста
    if plaintext == decrypted_text:
       print("Шифрование и расшифровка прошли успешно!")
    else:
        print("Ошибка в процессе шифрования и/или расшифровки.")

# Сохранение зашифрованного текста в файл
    output_path = input("Введите путь для сохранения зашифрованного текста: ")
    with open(output_path, "wb") as f:
        f.write(ciphertext)

# Сохранение расшифрованного текста в файл
    decrypted_output_path = input("Введите путь для сохранения расшифрованного текста: ")
    with open(decrypted_output_path, "wb") as f:
        f.write(decrypted_text)


if __name__ == "__main__":
    main()