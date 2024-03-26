"""
Script description: This module executes the logic for miscellaneous functions for this
library. 

Libraries imported:
- string: Module providing support for ASCII character encoding.
- random: Module generating random characters.
"""

import string
import random

class Helpers:
    """
    This class executes the logic for miscellaneous functions.
    """
    def __init__(self):
        pass
    @classmethod
    def generate_random_pw(cls, length: int=16) -> str:
        """
        Generates a random password.

        Parameters
        ----------
        length: int
            The length of the returned password.
        Returns
        -------
        str
            The randomly generated password.
        """
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length)).replace(' ','')
    