import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

logging.basicConfig(level="DEBUG")
logger = logging.getLogger()


class Hybrid_Cryptosystem:
    def __init__(self, size: int, way: str) -> None:
        """
        initiation function
        Args:
            size (int): size key
            way (str): path for a key
        """
        self.size = int(size//8)
        self.way = way
        self.settings = {
            'encrypted_file': os.path.join(self.way, 'encrypted_file.txt'),
            'decrypted_file': os.path.join(self.way, 'decrypted_file.txt'),
            'symmetric_key': os.path.join(self.way, 'symmetric_key.txt'),
            'public_key': os.path.join(self.way, 'public_key.txt'),
            'secret_key': os.path.join(self.way, 'secret_key.txt'),
            'iv_path': os.path.join(self.way, 'iv_path.txt')
        }

    def generation_key(self) -> None:
        """
        Keys generation function
        """
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = keys
        public_key = keys.public_key()
        try:
            with open(self.settings['public_key'], 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['public_key']}")
        else:
            logging.info("The public key is recorded ^_^")
        try:
            with open(self.settings['secret_key'], 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['secret_key']}")
        else:
            logging.info("Private key recorded ^_^")
        symmetric_key = os.urandom(self.size)
        ciphertext = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
            algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        try:
            with open(self.settings['symmetric_key'], "wb") as f:
                f.write(ciphertext)
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['symmetric_key']}")
        else:
            logging.info("The symmetric key is written ^_^")

    def __sym_key(self) -> bytes:
        """
        Symmetric encryption key decryption function

        Returns:
            bytes: decrypted symmetric key
        """
        try:
            with open(self.settings['secret_key'], "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None)
        except OSError as err:
            logging.warning(
                f"{err} error when reading from a file x_x {self.settings['secret_key']}")
        try:
            with open(self.settings['symmetric_key'], "rb") as f:
                encrypted_symmetric_key = f.read()
            symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except OSError as err:
            logging.warning(
                f"{err} error when reading from a file x_x {self.settings['symmetric_key']}")
        return symmetric_key

    def encryption(self, way: str) -> None:
        """
        Text encryption function with the Camellia algorithm
        Args:
            way (str): path for a text
        """
        symmetric_key = self.__sym_key()
        try:
            with open(way, 'r', encoding='utf-8') as f:
                text = f.read()
        except OSError as err:
            logging.warning(f"{err} error when reading from a file x_x {way}")
        else:
            logging.info("Text accepted!")
        padder = sym_padding.PKCS7(128).padder()
        padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        c_text = encryptor.update(padded_text) + encryptor.finalize()
        try:
            with open(self.settings['iv_path'], 'wb') as key_file:
                key_file.write(iv)
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['iv_path']}")
        try:
            with open(self.settings['encrypted_file'], 'wb') as f_text:
                f_text.write(c_text)
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['encrypted_file']}")
        else:
            logging.info("Text encrypted successfully")

    def decryption(self) -> str:
        """
        Camellia algorithm text decoding function
        Returns:
            str: path to the decrypted file
        """
        symmetric_key = self.__sym_key()
        try:
            with open(self.settings['encrypted_file'], 'rb') as f:
                en_text = f.read()
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['encrypted_file']}")
        try:
            with open(self.settings['iv_path'], "rb") as f:
                iv = f.read()
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['iv_path']}")
        cipher = Cipher(algorithms.Camellia(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        dc_text = decryptor.update(en_text) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
        try:
            with open(self.settings['decrypted_file'], 'wb') as f:
                f.write(unpadded_dc_text)
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['decrypted_file']}")
        else:
            logging.info("Text decrypted successfully")
        return self.settings['decrypted_file']
