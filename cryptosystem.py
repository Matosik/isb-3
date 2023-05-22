import logging

from symmetric import SymmetricEncryption
from assymmetric import AsymmetricEncryption

logging.basicConfig(level="DEBUG")
logger = logging.getLogger()


class Cryptosystem:
    def __init__(self, size: int, setting) -> None:
        """
        Initiation function
        Args:
            size (int): size key
            way (str): path for a keys
        """
        self.symmetric_encryption = SymmetricEncryption(size,  setting)
        self.asymmetric_encryption = AsymmetricEncryption(size, setting)

    def generate_keys(self) -> None:
        """
        Keys generation function
        """
        self.asymmetric_encryption.generation_key()

    def encryption(self) -> None:
        """
        Encryption function
        Args:
            way (str): path for a text
        """
        self.symmetric_encryption.encryption()

    def decryption(self) -> str:
        """
        Decryption function
        Returns:
            str: path to the decrypted file
        """
        self.symmetric_encryption.decryption()