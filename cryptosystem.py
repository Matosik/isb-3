import logging
import os

from symmetric import SymmetricEncryption
from assymmetric import AsymmetricEncryption

logging.basicConfig(level="DEBUG")
logger = logging.getLogger()


class Hybrid_Cryptosystem:
    def __init__(self, size: int, way: str) -> None:
        """
        Initiation function
        Args:
            size (int): size key
            way (str): path for a key
        """
        self.symmetric_encryption = SymmetricEncryption(size, way)
        self.asymmetric_encryption = AsymmetricEncryption(size, way)

    def generate_keys(self) -> None:
        """
        Keys generation function
        """
        self.asymmetric_encryption.generation_key()

    def encryption(self, way: str) -> None:
        """
        Encryption function
        Args:
            way (str): path for a text
        """
        self.symmetric_encryption.encryption(way)

    def decryption(self) -> str:
        """
        Decryption function
        Returns:
            str: path to the decrypted file
        """
        return self.symmetric_encryption.decryption()