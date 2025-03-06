"""
Script description: This module provides miscellaneous utility functions for authentication and configuration.

Libraries Imported:
-------------------
- yaml: Handles data serialization for human-readable configuration files.
- string: Provides support for ASCII character encoding.
- random: Generates random characters.
- streamlit: Framework used to build web applications.
- captcha: Generates captcha images.
"""

import yaml
from yaml.loader import SafeLoader
import string
import random
import streamlit as st
from captcha.image import ImageCaptcha

from ..utilities import Encryptor


class Helpers:
    """
    This class provides various helper functions for authentication and configuration handling.
    """
    def __init__(self) -> None:
        pass
    @classmethod
    def check_captcha(cls, captcha_name: str, entered_captcha: str, secret_key: str):
        """
        Checks the validity of the entered captcha.

        Parameters
        ----------
        captcha_name : str
            Name of the generated captcha stored in the session state.
        entered_captcha : str
            User-entered captcha to validate against the stored captcha.
        secret_key : str
            A secret key used for encryption and decryption.

        Returns
        -------
        bool
            True if the entered captcha is valid, False otherwise.
        """
        encryptor = Encryptor(secret_key)
        if entered_captcha == encryptor.decrypt(st.session_state[captcha_name]):
            return True
        return False
    @classmethod
    def generate_captcha(cls, captcha_name: str, secret_key: str) -> ImageCaptcha:
        """
        Generates a captcha image and stores the associated captcha string in session state.

        Parameters
        ----------
        captcha_name : str
            Name of the generated captcha stored in the session state.
        secret_key : str
            A secret key used for encryption and decryption.

        Returns
        -------
        ImageCaptcha
            The generated captcha image.
        """
        encryptor = Encryptor(secret_key)
        image = ImageCaptcha(width=120, height=75)
        if captcha_name not in st.session_state:
            st.session_state[captcha_name] = encryptor.encrypt(''.join(random.choices(string.digits,
                                                                                      k=4)))
        return image.generate(encryptor.decrypt(st.session_state[captcha_name]))
    @classmethod
    def generate_random_string(cls, length: int=16, letters: bool=True, digits: bool=True,
                               punctuation: bool=True) -> str:
        """
        Generates a random string with optional character sets.

        Parameters
        ----------
        length : int, default=16
            Length of the generated string.
        letters : bool, default=True
            If True, includes uppercase and lowercase letters.
        digits : bool, default=True
            If True, includes numerical digits.
        punctuation : bool, default=True
            If True, includes punctuation symbols.

        Returns
        -------
        str
            A randomly generated string.
        """
        letters = (string.ascii_letters if letters else '') + \
                  (string.digits if digits else '') + \
                  (''.join(c for c in string.punctuation if c not in "<>") if punctuation else '')
        return ''.join(random.choice(letters) for i in range(length)).replace(' ','')
    #@st.cache
    @classmethod
    def read_config_file(cls, path: str) -> dict:
        """
        Reads a configuration file in YAML format.

        Parameters
        ----------
        path : str
            File path of the configuration file.

        Returns
        -------
        dict
            Parsed YAML configuration.
        """
        with open(path, 'r', encoding='utf-8') as file:
            return yaml.load(file, Loader=SafeLoader)
    @classmethod
    def write_config_file(cls, path: str, config: dict) -> None:
        """
        Writes a configuration dictionary to a YAML file.

        Parameters
        ----------
        path : str
            File path of the configuration file.
        config : dict
            Configuration data to write.
        """
        with open(path, 'w', encoding='utf-8') as file:
            yaml.dump(config, file, default_flow_style=False, allow_unicode=True)
    @classmethod
    def update_config_file(cls, path: str, key: str, items: dict) -> None:
        """
        Updates a specific key in a YAML configuration file.

        Parameters
        ----------
        path : str
            File path of the configuration file.
        key : str
            The key to update in the configuration.
        items : dict
            The new values to set for the key.
        """
        with open(path, 'r', encoding='utf-8') as file:
            config = yaml.load(file, Loader=SafeLoader)
        config[key] = items
        with open(path, 'w', encoding='utf-8') as file:
            yaml.dump(config, file, default_flow_style=False, allow_unicode=True)
