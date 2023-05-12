import re
import sys

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import (
    QApplication, QLabel, QMainWindow, QPushButton, QFileDialog)
from cryptosystem import Hybrid_Cryptosystem


class Window_main(QMainWindow):
    def __init__(self) -> None:
        """
        Initialization function
        """
        super(Window_main, self).__init__()
        self.setWindowTitle('Camellia')
        self.setFixedSize(600, 400)
        self.background = QLabel(self)
        self.background.setGeometry(0, 0, 600, 400)
        self.background.setStyleSheet("background-color: #B0E0E6;")

        self.info = QLabel(self)
        self.info.setText('Selection size key')
        self.info.setGeometry(225, 15, 500, 50)

        self.button_keys = QPushButton('Generate keys', self)
        self.button_keys.setGeometry(200, 105, 200, 50)
        self.button_keys.setStyleSheet(
            ' border-radius: 15%; background-color: #FFFFF0 ;border: 2px solid black;')
        self.button_keys.clicked.connect(self.generation_key)
        self.button_keys.hide()

        self.key_size = QtWidgets.QComboBox(self)
        self.key_size.setStyleSheet(
            'border-radius: 15%; border: 2px solid black;background-color: #FFFFF0;')
        self.key_size.addItems(["128 бит", "192 бит", "256 бит"])
        self.key_size.setGeometry(200, 50, 200, 50)
        self.key_size.activated[str].connect(self.size_selection)

        self.enycryption_button = QPushButton('Encrypt the text', self)
        self.enycryption_button.setStyleSheet(
            ' border-radius: 15%; background-color: #FFFFF0 ;border: 2px solid black;')
        self.enycryption_button.setGeometry(200, 165, 200, 50)
        self.enycryption_button.clicked.connect(self.encryption)
        self.enycryption_button.hide()

        self.decryption_button = QPushButton('Decode the text', self)
        self.decryption_button.setStyleSheet(
            ' border-radius: 15%; background-color: #FFFFF0 ; border: 2px solid black;')
        self.decryption_button.setGeometry(200, 225, 200, 50)
        self.decryption_button.clicked.connect(self.decryption)
        self.decryption_button.hide()
        
        self.message = QLabel(self)
        self.message.setGeometry(244, 265, 200, 50)
        self.show()

    def size_selection(self, text: str) -> None:
        """
        The function assigns the size of the key
        Args:
            text (str): строка которую из которой выбрали нужный ключ
        """
        self.size = int(re.findall('(\d+)', text)[0])
        self.info.setText("Generate the keys")
        self.button_keys.show()

    def generation_key(self) -> None:
        """
        The function generates keys and shows 2 buttons(encryption,decryption)
        """
        way = str(QFileDialog.getExistingDirectory(
            caption='Selecting a directory'))
        self.key = Hybrid_Cryptosystem(self.size, way)
        self.key.generation_key()
        self.info.setText("Keys generated successfully")
        self.message.setText("Please encrypt the text")
        self.decryption_button.show()
        self.enycryption_button.show()

    def encryption(self) -> None:
        """
        Encryption function
        """
        way_e = str(QFileDialog.getOpenFileName(
            caption='Select the file for encrypted in txt format', filter='*.txt'))
        way_e = way_e.split('\'')[1]
        self.key.encryption(way_e)
        self.info.setText("The text is encrypted")
        self.message.setText("Decipher the text")

    def decryption(self) -> None:
        """
        Decoding function
        """
        way = self.key.decryption()
        self.info.setText("The text decrypted successfully")
        self.message.setGeometry(155, 280, 600, 30)
        self.message.setText(
            f"\tThe decrypted text is located at this path:\n{way}")


def application() -> None:
    """
    The function starts the application
    """
    app = QApplication(sys.argv)
    window = Window_main()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    application()
