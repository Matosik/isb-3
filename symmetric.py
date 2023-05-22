import logging
import os

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

logging.basicConfig(level="DEBUG")
logger = logging.getLogger()

class SymmetricEncryption:
    def __init__(self, size: int,  setting) -> None:
        """
        Initiation function
        Args:
            size (int): size of the key
            way (str): path for the key
        """
        self.size = int(size // 8)

        self.settings = setting

    def __sym_key(self) -> bytes:
        """
        Symmetric encryption key decryption function
        Returns:
            bytes: decrypted symmetric key
        """
        try:
            with open(self.settings['symmetric_key'], "rb") as f:
                encrypted_symmetric_key = f.read()
        except OSError as err:
            logging.warning(
                f"{err} error when reading from a file x_x {self.settings['symmetric_key']}")

        return encrypted_symmetric_key

    def encryption(self) -> None:
        """
        Text encryption function with the Camellia algorithm
        Args:
            way (str): path for a text
        """
        symmetric_key = self.__sym_key()
        try:
            with open(self.settings["text"], 'r+', encoding='utf-8') as f:
                text = f.read()
            logging.info("Text accepted!")
        except OSError as err:
            logging.warning(
                "error when reading from a file x_x " + self.settings["text"])
        padder = sym_padding.PKCS7(128).padder()
        padded_text = padder.update(bytes(text, 'utf-8')) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(symmetric_key[:16]), modes.CBC(iv))
        encryptor = cipher.encryptor()
        c_text = encryptor.update(padded_text) + encryptor.finalize()
        try:
            with open(self.settings["iv_path"], 'wb') as key_file:
                key_file.write(iv)
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['iv_path']}")
        try:
            with open(self.settings["encrypted_file"], 'wb') as f_text:
                f_text.write(c_text)
            logging.info("Text encrypted successfully")
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['encrypted_file']}")

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
                f"{err} error when writing to file x_x" + {self.settings["encrypted_file"]})
        try:
            with open(self.settings['iv_path'], "rb") as f:
                iv = f.read()
        except OSError as err:
            logging.warning(
                f"{err} error when writing to file x_x {self.settings['iv_path']}")
        cipher = Cipher(algorithms.Camellia(symmetric_key[:16]), modes.CBC(iv))
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
