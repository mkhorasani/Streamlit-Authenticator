"""
Script description: This module executes the logic for miscellaneous functions for this
library. 

Libraries imported:
- string: Module providing support for ASCII character encoding.
- random: Module generating random characters.
- captcha: Module generating captcha images.
"""

import string
import random
from captcha.image import ImageCaptcha

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
    @classmethod
    def generate_captcha(cls) -> tuple:
        """
        Generates a captcha image.

        Returns
        -------
        int
            The randomly generated four digit captcha.
        ImageCaptcha
            The randomly generated captcha object.
        """
        image = ImageCaptcha(width=120, height=75)
        random_digit = random.choices(string.digits, k=4)
        return random_digit, image.generate(random_digit)
    
