import logging
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


logging.basicConfig(level="DEBUG")
logger = logging.getLogger()

class AsymmetricEncryption:
    def __init__(self, size: int, way: str) -> None:
        """
        Initiation function
        Args:
            size (int): size of the key
            way (str): path for the key
        """
        self.size = int(size // 8)
        self.way = way
        self.settings = {
            'public_key': os.path.join(self.way, 'public_key.txt'),
            'secret_key': os.path.join(self.way, 'secret_key.txt'),
            'symmetric_key': os.path.join(self.way, 'symmetric_key.txt'),
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