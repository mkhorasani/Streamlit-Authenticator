"""
Script description: This module handles Google OAuth2 authentication for guest login.

Libraries imported:
-------------------
- base64: Provides encoding/decoding functions for the PKCE security feature.
- hashlib: Implements hashing for the PKCE security feature.
- os: Executes system-level functions.
- time: Implements sleep functions for login delays.
- typing: Provides standard type hints for Python functions.
- requests: Handles HTTP requests made to the OAuth2 server.
- streamlit: Framework for building web applications.
"""

import base64
import hashlib
import os
import time
from typing import Dict, Union

import requests
import streamlit as st

from ... import params
from ...utilities import LoginError


class GoogleModel:
    """
    Handles Google OAuth2 authentication using PKCE (Proof Key for Code Exchange).
    """
    def __init__(
            self,
            google: Dict[str, str]
            ) -> None:
        """
        Initializes the GoogleModel instance.

        Parameters
        ----------
        google : dict
            Dictionary containing Google OAuth2 configuration, including `client_id`,
            `redirect_uri`, and optionally `client_secret`.
        """
        self.google = google
        self.code_verifier = None
    def generate_code_verifier(self) -> None:
        """
        Generates a random code verifier for PKCE authentication.
        """
        self.code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    def generate_code_challenge(self) -> str:
        """
        Generates a code challenge based on the previously generated code verifier.

        Returns
        -------
        str
            The generated code challenge.
        """
        if self.code_verifier is None:
            raise LoginError('Code verifier not generated')
        return base64.urlsafe_b64encode(
            hashlib.sha256(self.code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
    def login_google(self) -> str:
        """
        Constructs the Google OAuth2 authorization URL.

        Returns
        -------
        str
            The Google OAuth2 authorization endpoint URL.
        """
        # self.generate_code_verifier()
        # code_challenge = self.generate_code_challenge()
        google_auth_endpoint = (
            f"https://accounts.google.com/o/oauth2/auth"
            f"?client_id={self.google['client_id']}"
            f"&redirect_uri={self.google['redirect_uri']}"
            f"&response_type=code"
            f"&scope=openid%20email%20profile"
            # f"&code_challenge={code_challenge}"
            # f"&code_challenge_method=S256"
        )
        return google_auth_endpoint
    def get_google_user_info(self, auth_code: str) -> Dict[str, str]:
        """
        Exchanges an authorization code for an access token and retrieves user information.

        Parameters
        ----------
        auth_code : str
            The authorization code received from Google after user consent.

        Returns
        -------
        dict
            Dictionary containing user information retrieved from Google.
        """
        time.sleep(params.PRE_GUEST_LOGIN_SLEEP_TIME)
        if 'GoogleModel.get_google_user_info' not in st.session_state:
            st.session_state['GoogleModel.get_google_user_info'] = None
        if not st.session_state['GoogleModel.get_google_user_info']:
            st.session_state['GoogleModel.get_google_user_info'] = True
            token_url = 'https://oauth2.googleapis.com/token'
            token_data = {
                'code': auth_code,
                'client_id': self.google['client_id'],
                'client_secret': self.google.get('client_secret'),
                'redirect_uri': self.google['redirect_uri'],
                'grant_type': 'authorization_code'
                # 'code_verifier': self.code_verifier
            }
            token_r = requests.post(token_url, data=token_data, timeout=10)
            token_json = token_r.json()
            if 'access_token' not in token_json:
                print('No access token received')
                st.rerun()
            user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
            user_info_headers = {
                'Authorization': f"Bearer {token_json['access_token']}"
            }
            user_info_r = requests.get(user_info_url, headers=user_info_headers, timeout=10)
            if user_info_r.status_code != 200:
                raise LoginError('Failed to retrieve user information')
            return user_info_r.json()
    def guest_login(self) -> Union[str, Dict[str, str]]:
        """
        Handles the login process and fetches user information or returns the authorization
        endpoint.

        Returns
        -------
        Union[str, dict]
            - If not authenticated, returns the authorization endpoint URL (str).
            - If authenticated, returns a dictionary containing user information.
        """
        auth_code = st.query_params.get('code')
        if auth_code:
            user_info = self.get_google_user_info(auth_code)
            if user_info:
                return user_info
        else:
            return self.login_google()
        return None
