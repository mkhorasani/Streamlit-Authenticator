"""
Script description: This module executes the logic for the encrypting and decrypting of plain text. 

Libraries imported:
- base64: Module executing encode/decode operations for the code challenge security feature.
- hashlib: Module implementing hashing for the code challenge security feature.
- cryptography: Module implementing secure encrypting and decrypting for plain text.
"""

import base64
import hashlib
from cryptography.fernet import Fernet

class Encryptor:
    """
    This class will encrypt and decrypt plain text.
    """
    def __init__(self, secret_key: str):
        """
        Creates a new instance of "Encryptor".

        Parameters
        ----------
        secret_key : str
            A secret key used for encryption and decryption.
        """
        secret_key = hashlib.sha256(secret_key.encode()).digest()[:32]
        secret_key = base64.urlsafe_b64encode(secret_key)
        self.cipher = Fernet(secret_key)
    def encrypt(self, string: str) -> str:
        """
        Encrypts a plain text string.

        Parameters
        ----------
        string: str
            The plain text string.
        Returns
        -------
        str
            Encrypted plain text string.
        """
        return self.cipher.encrypt(string.encode()).decode()
    def decrypt(self, string: str) -> str:
        """
        Decrypts an encrypted string.

        Parameters
        ----------
        string: str
            The encrypted string.
        Returns
        -------
        str
            Decrypted plain text string.
        """
        return self.cipher.decrypt(string.encode()).decode()
