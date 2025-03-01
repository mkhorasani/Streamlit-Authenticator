"""
Script description: Handles encryption and decryption of plain text using AES-based encryption.

Libraries Imported:
-------------------
- base64: Encodes and decodes data in a URL-safe format.
- hashlib: Implements hashing for security.
- cryptography: Provides secure encryption and decryption.
"""

import base64
import hashlib
from cryptography.fernet import Fernet


class Encryptor:
    """
    This class provides encryption and decryption of plain text strings.
    """
    def __init__(
            self,
            secret_key: str
            ) -> None:
        """
        Initializes the Encryptor instance.

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
        string : str
            The plain text string to encrypt.

        Returns
        -------
        str
            The encrypted text as a base64-encoded string.
        """
        return self.cipher.encrypt(string.encode()).decode()
    def decrypt(self, string: str) -> str:
        """
        Decrypts an encrypted string.

        Parameters
        ----------
        string : str
            The encrypted text as a base64-encoded string.

        Returns
        -------
        str
            The decrypted plain text.
        """
        return self.cipher.decrypt(string.encode()).decode()
