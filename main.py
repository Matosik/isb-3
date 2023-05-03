import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time


class HybridEncryption:
    def __init__(self):
        """_Инициализация класса_"""
        self.backend = default_backend()

    def generate_rsa_keys(self):
        """
        Генерация пары ключей RSA (открытый и закрытый ключ)

        Returns:
            tuple: private_key, public_key.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(self, plaintext: bytes, public_key):
        """Шифрование текста с использованием алгоритма RSA.

        Args:
            plaintext (bytes): текст для шифрования |
            public_key (RSAPublicKey): открытый ключ RSA.
        Returns:
            bytes: зашифрованный текст.
        """
        encrypted = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )
        return encrypted

    def rsa_decrypt(self, ciphertext: bytes, private_key):
        """Расшифровка текста с использованием алгоритма RSA.

        Args:
            ciphertext (bytes): зашифрованный текст
            private_key (RSAPrivateKey): закрытый ключ RSA.
        Returns:
            bytes: расшифрованный текст.
        """
        decrypted = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)
        )
        return decrypted

    def camellia_encrypt(self, plaintext: bytes, key: bytes, iv: bytes):
        """Шифрование текста с использованием алгоритма Camellia.

        Args:
            plaintext (bytes): текст для шифрования,
            key (bytes): ключ Camellia,
            iv (bytes): вектор инициализации.
        Returns:
            bytes: зашифрованный текст
        """
        cipher = Cipher(
            algorithms.Camellia(key),
            modes.CBC(iv),
            backend=self.backend)
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    def camellia_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes):
        """Расшифровка текста с использованием алгоритма Camellia.

        Args:
            ciphertext (bytes) - зашифрованный текст,
             key (bytes) - ключ Camellia,
            iv (bytes) - вектор инициализации.
        Returns:
            bytes: расшифрованный текст.
        """

        cipher = Cipher(
            algorithms.Camellia(key),
            modes.CBC(iv),
            backend=self.backend)
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext


def menu():
    """Выполняет роль меню"""
    hybrid = HybridEncryption()
    # Генерация пары ключей RSA
    private_key, public_key = hybrid.generate_rsa_keys()

    # Вывод открытого ключа для пользователя
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"Открытый ключ RSA:\n{pem_public_key.decode('utf-8')}")

    # Чтение текста из файла
    input_path = input("Введите путь до файла с текстом: ")
    while not os.path.isfile(os.path.join(input_path)):
        input_path = input(
            "\nА теперь введи, пожалуйста, нормальный путь до файла, а не абракадабру ^_^:")
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Выбор ключа Camellia
    key_length = input("\nВыберите длину ключа Camellia (128, 192, 256): ")
    while (key_length != "128" and key_length !=
           "192" and key_length != "256"):
        key_length = input(
            "Нет нет нет так не пойдет... Camellia использует размер ключа 128, 192 или 256 бит так, что выберете один из 3 доспупных: ")
    key_length = int(key_length)
    camellia_key = os.urandom(key_length // 8)
    iv = os.urandom(16)
    if not os.path.exists("Keys"):
        os.makedirs("Keys")
    nametxt = 0
    while os.path.isfile(os.path.join("Keys", f"Camellia{nametxt}.txt")):
        nametxt += 1
    with open(os.path.join("Keys", f"Camellia{nametxt}.txt"), "w") as f:
        f.write(camellia_key.hex())
    # Вывод ключа Camellia для пользователя
    print(f"\nКлюч Camellia (в формате base64) сохранен в папке Keys")
    # Шифрование текста с использованием Camellia
    ciphertext = hybrid.camellia_encrypt(plaintext, camellia_key, iv)

    # Шифрование ключа Camellia с использованием RSA
    encrypted_key = hybrid.rsa_encrypt(camellia_key, public_key)

    # Запрос у пользователя ключа Camellia для расшифровки
    entered_key_hex = input(
        "\nВведите ключ Camellia для расшифровки (в формате base64): ")
    while (entered_key_hex != camellia_key.hex()):
        entered_key_hex = input("\nНеверный ключ введите еще раз: ")
    entered_key = bytes.fromhex(entered_key_hex)

    print("\nОтлично! Ключ принят ожидайте расшифровки текста! ")
    time.sleep(2)
    # Расшифровка ключа Camellia с использованием RSA
    decrypted_key = hybrid.rsa_decrypt(encrypted_key, private_key)

    decrypted_text = hybrid.camellia_decrypt(ciphertext, entered_key, iv)

    if plaintext == decrypted_text:
        print("\nШифрование и расшифровка прошли успешно!")
    else:
        print("\nОшибка в процессе шифрования и/или расшифровки.")

    # Сохранение зашифрованного текста в файл
    name_path_ciphertext = input(
        "\nВведите имя для файла для зашифрованного текста: ")
    if not os.path.exists("Ciphertext"):
        os.makedirs("Ciphertext")
    with open(os.path.join("Ciphertext", f"{name_path_ciphertext}.txt"), "wb") as f:
        f.write(ciphertext)
    # Сохранение расшифрованного текста в файл
    if plaintext == decrypted_text:
        if not os.path.exists("Decrypted"):
            os.makedirs("Decrypted")
        decrypted_output_path = input(
            "\nВведите имя для файла для расшифрованного текста: ")
        with open(os.path.join("Decrypted", f"{decrypted_output_path}.txt"), "wb") as f:
            f.write(decrypted_text)
    else:
        print("\nУпс произошла ошибка, что маловероятно, наверное мой код не идеален, что так же маловероятно, или же сегодня ретроградный меркурий другого не дано *_*")


def main():
    """Повторюшка"""
    flag = True
    while (flag):
        menu()
        ro = input(
            "\nХотите еще раз поиграться с данной программой? да/нет yes/no : ")
        while (ro != "yes" and ro != "no" and ro != "да" and ro != "нет"):
            ro = input(
                "\nохххх я же спросил да или нет зачем же писать что-то друое... -_-\nХорошо давайте по новой. да или нет (:  ")
        if (ro == "no" or ro == "нет"):
            flag = False
            print("\nНа нет и суда нет O_o")
            time.sleep(1)
        else:
            print("\nДело сделано... опять работа ?")
            time.sleep(2)
    print("\nКто прочитал у того мама будет жить вечно!")


if __name__ == "__main__":
    main()
