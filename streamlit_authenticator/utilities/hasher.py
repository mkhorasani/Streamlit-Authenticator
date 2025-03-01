"""
Script description: Handles secure hashing and validation of plain text passwords using bcrypt.

Libraries Imported:
-------------------
- re: Implements regular expressions for pattern matching.
- bcrypt: Provides secure password hashing.
- typing: Provides standard type hints for Python functions.
"""

import re
import bcrypt
from typing import Dict, List


class Hasher:
    """
    This class provides methods for hashing and verifying passwords.
    """
    def __init__(self) -> None:
        pass
    @classmethod
    def check_pw(cls, password: str, hashed_password: str) -> bool:
        """
        Verifies if a plain text password matches a hashed password.

        Parameters
        ----------
        password : str
            The plain text password.
        hashed_password : str
            The hashed password to compare against.

        Returns
        -------
        bool
            True if the password matches the hash, False otherwise.
        """
        return bcrypt.checkpw(password.encode(), hashed_password.encode())
    @classmethod
    def hash(cls, password: str) -> str:
        """
        Hashes a plain text password using bcrypt.

        Parameters
        ----------
        password : str
            The plain text password.

        Returns
        -------
        str
            The securely hashed password.
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    @classmethod
    def hash_list(cls, passwords: List[str]) -> List[str]:
        """
        Hashes a list of plain text passwords.

        Parameters
        ----------
        passwords : list of str
            The list of plain text passwords to be hashed.

        Returns
        -------
        list of str
            The list of securely hashed passwords.
        """
        return [cls.hash(password) for password in passwords]
    @classmethod
    def hash_passwords(cls, credentials: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
        """
        Hashes all plain text passwords in a credentials dictionary.

        Parameters
        ----------
        credentials : dict
            Dictionary containing usernames as keys and user details as values.

        Returns
        -------
        dict
            The credentials dictionary with all passwords securely hashed.
        """
        usernames = credentials['usernames']

        for _, user in usernames.items():
            password = user['password']
            if not cls.is_hash(password):
                hashed_password = cls.hash(password)
                user['password'] = hashed_password
        return credentials
    @classmethod
    def is_hash(cls, hash_string: str) -> bool:
        """
        Determines if a given string is a bcrypt hash.

        Parameters
        ----------
        hash_string : str
            The string to check.

        Returns
        -------
        bool
            True if the string is a valid bcrypt hash, False otherwise.
        """
        bcrypt_regex = re.compile(r'^\$2[aby]\$\d+\$.{53}$')
        return bool(bcrypt_regex.match(hash_string))
