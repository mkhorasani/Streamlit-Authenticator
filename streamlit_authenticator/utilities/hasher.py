"""
Script description: This module executes the logic for the hashing of plain text passwords. 

Libraries imported:
- re: Module implementing regular expressions.
- bcrypt: Module implementing secure hashing for plain text.
"""

import re
import bcrypt

class Hasher:
    """
    This class will hash plain text passwords.
    """
    def __init__(self, passwords: list):
        """
        Create a new instance of "Hasher".

        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        """
        self.passwords = passwords
    @classmethod
    def check_pw(cls, password: str, hashed_password: str) -> bool:
        """
        Checks the validity of the entered password.

        Parameters
        ----------
        password: str
            The plain text password.
        hashed_password: str
            The hashed password.
        Returns
        -------
        bool
            Validity of the entered password by comparing it to the hashed password.
        """
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    def generate(self) -> list:
        """
        Hashes the list of plain text passwords.

        Returns
        -------
        list
            The list of hashed passwords.
        """
        return [self._hash(password) for password in self.passwords]
    @classmethod
    def hash_passwords(cls, credentials: dict) -> dict:
        """
        Hashes all plain text passwords in the credentials dict.

        Parameters
        ----------
        credentials: dict
            The credentials dict with plain text passwords.
        Returns
        -------
        dict
            The credentials dict with hashed passwords.
        """
        usernames = credentials['usernames']

        for _, user in usernames.items():
            password = user['password']
            if not cls._is_hash(password):
                hashed_password = cls._hash(password)
                user['password'] = hashed_password
        return credentials
    @classmethod
    def _hash(cls, password: str) -> str:
        """
        Hashes the plain text password.

        Parameters
        ----------
        password: str
            The plain text password.
        Returns
        -------
        str
            The hashed password.
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    @classmethod
    def _is_hash(cls, hash_string: str) -> bool:
        """
        Determines if a string is a hash.

        Returns
        -------
        bool
            The state of whether the string is a hash,
            True: the string is a hash,
            False: the string is not a hash.
        """
        bcrypt_regex = re.compile(r'^\$2[aby]\$\d+\$.{53}$')
        return bool(bcrypt_regex.match(hash_string))
    