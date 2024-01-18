
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
    def _hash(self, password: str) -> str:
        """
        Hashes the plain text password.

        Parameters
        ----------
        password: str
            The plain text password to be hashed.
        Returns
        -------
        str
            The hashed password.
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

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
    def _is_hash(self, hash_string: str) -> bool:
        """
        Determines if a string is a hash.

        Returns
        -------
        bool
            The validity of the hash string.
        """
        bcrypt_regex = re.compile(r'^\$2[aby]\$\d+\$.{53}$')
        return bool(bcrypt_regex.match(hash_string))