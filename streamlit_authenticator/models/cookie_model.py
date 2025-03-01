"""
Script description: This module handles cookie-based password-less re-authentication.

Libraries imported:
-------------------
- typing: Provides standard type hints for Python functions.
- datetime: Handles date and time operations.
- jwt: Implements JSON Web Tokens for authentication.
- streamlit: Framework for building web applications.
- extra_streamlit_components: Provides cookie management for Streamlit.
"""

from typing import Any, Dict, Optional
from datetime import datetime, timedelta
import jwt
from jwt import DecodeError, InvalidSignatureError
import streamlit as st
import extra_streamlit_components as stx

from ..utilities import Helpers


class CookieModel:
    """
    Manages cookie-based password-less re-authentication, including setting, retrieving,
    and deleting authentication cookies.
    """
    def __init__(
            self,
            cookie_name: Optional[str] = None,
            cookie_key: Optional[str] = None,
            cookie_expiry_days: Optional[float] = None,
            path: Optional[str] = None
            ) -> None:
        """
        Initializes the CookieModel instance.

        Parameters
        ----------
        cookie_name : str, optional
            Name of the cookie stored in the client's browser for password-less re-authentication.
        cookie_key : str, optional
            Secret key used for signing and verifying the authentication cookie.
        cookie_expiry_days : float, optional
            Number of days before the re-authentication cookie expires.
        path : str, optional
            Path to the configuration file.
        """
        if path:
            config = Helpers.read_config_file(path)
            self.cookie_name        = config['cookie']['name']
            self.cookie_key         = config['cookie']['key']
            self.cookie_expiry_days = config['cookie']['expiry_days']
        else:
            self.cookie_name            =   cookie_name
            self.cookie_key             =   cookie_key
            self.cookie_expiry_days     =   cookie_expiry_days
        self.cookie_manager         =   stx.CookieManager()
        self.token                  =   None
        self.exp_date               =   None
    def delete_cookie(self) -> None:
        """
        Deletes the re-authentication cookie from the user's browser.
        """
        try:
            self.cookie_manager.delete(self.cookie_name)
        except KeyError as e:
            print(e)
    def get_cookie(self) -> Optional[Dict[str, Any]]:
        """
        Retrieves, validates, and returns the authentication cookie.

        Returns
        -------
        dict or None
            If valid, returns a dictionary containing the cookie's data.
            Returns None if the cookie is expired or invalid.
        """
        if st.session_state['logout']:
            return False
        # self.token = self.cookie_manager.get(self.cookie_name)
        self.token = st.context.cookies[self.cookie_name] if self.cookie_name in \
            st.context.cookies else None
        if self.token is not None:
            self.token = self._token_decode()
            if (self.token is not False and 'username' in self.token and
                self.token['exp_date'] > datetime.now().timestamp()):
                return self.token
        return None
    def set_cookie(self) -> None:
        """
        Creates and stores the authentication cookie in the user's browser.
        """
        if self.cookie_expiry_days != 0:
            self.exp_date = self._set_exp_date()
            token = self._token_encode()
            self.cookie_manager.set(self.cookie_name, token,
                                    expires_at=datetime.now() + \
                                    timedelta(days=self.cookie_expiry_days))
    def _set_exp_date(self) -> float:
        """
        Computes the expiration timestamp for the authentication cookie.

        Returns
        -------
        float
            Unix timestamp representing the expiration date of the cookie.
        """
        return (datetime.now() + timedelta(days=self.cookie_expiry_days)).timestamp()
    def _token_decode(self) -> Optional[Dict[str, Any]]:
        """
        Decodes and verifies the JWT authentication token.

        Returns
        -------
        dict or None
            Decoded token contents if verification is successful.
            Returns None if decoding fails due to an invalid signature or token error.
        """
        try:
            return jwt.decode(self.token, self.cookie_key, algorithms=['HS256'])
        except (DecodeError, InvalidSignatureError) as e:
            print(e)
            return False
    def _token_encode(self) -> str:
        """
        Encodes the authentication data into a JWT token.

        Returns
        -------
        str
            The signed JWT token containing authentication details.
        """
        return jwt.encode({'username': st.session_state['username'],
            'exp_date': self.exp_date}, self.cookie_key, algorithm='HS256')
