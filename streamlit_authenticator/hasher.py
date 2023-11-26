import bcrypt
from exceptions import HasherError

class Hasher:
    """
    This class will hash plain text passwords.
    """
    def __init__(self, passwords: list=None, config_dict: dict=None):
        """
        Create a new instance of "Hasher".

        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        """
        if passwords:
            self.passwords = passwords
        elif config_dict:
            self.config_dict = config_dict
        else:
            raise HasherError('Need to provide one of: list of passwords or config dictionary')

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

    def _check_if_hash(self, password):
        """
        Checks to see if a password is already hashed.

        Returns
        -------
        bool
            Returns True if password is already hashed, otherwise returns False.
        """
        try:
            bcrypt.checkpw(b'password', password.encode('utf-8'))
            return True
        except:
            return False

    def hash_config(self) -> dict:
        """
        Hashes the config dict.

        Returns
        -------
        dict
            The config dict with hashed passwords.
        """ 
        for username in self.config_dict['credentials']['usernames'].keys():
            if not self._check_if_hash(self.config_dict['credentials']['usernames'][username]['password']):
                self.config_dict['credentials']['usernames'][username]['password'] = self._hash(self.config_dict['credentials']['usernames'][username]['password'])
        return self.config_dict