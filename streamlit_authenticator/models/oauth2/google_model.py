"""
Script description: This module executes the logic for the guest login widget using
Google OAuth2. 

Libraries imported:
- base64: Module executing encode/decode operations for the code challenge security feature.
- hashlib: Module implementing hashing for the code challenge security feature.
- os: Module executing system level functions.
- time: Module implementing the sleep function.
- typing: Module implementing standard typing notations for Python functions.
- requests: Module executing the http requests made to the OAuth2 server.
- streamlit: Framework used to build pure Python web applications.
"""

import base64
import hashlib
import os
import time
from typing import Union

import requests
import streamlit as st

from ... import params
from ...utilities import LoginError

class GoogleModel:
    """
    This class executes the logic for a Google OAuth2 login using PKCE
    (Proof Key for Code Exchange).
    """
    def __init__(self, google: dict):
        """
        Create a new instance of "GoogleModel".

        Parameters
        ----------
        google : dict
            A dictionary containing the Google OAuth2 configuration, including client_id,
            redirect_uri, and client_secret.
        """
        self.google = google
        self.code_verifier = None
    def generate_code_verifier(self):
        """
        Generate a code verifier for PKCE.
        """
        self.code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    def generate_code_challenge(self) -> str:
        """
        Generate a code challenge based on the code verifier.

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
        Initiate login with Google using PKCE.

        Returns
        -------
        str
            The authorization endpoint URL for Google login.
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
    def get_google_user_info(self, auth_code: str) -> dict:
        """
        Exchange the authorization code for an access token using the PKCE flow.

        Parameters
        ----------
        auth_code : str
            The authorization code received from Google.

        Returns
        -------
        dict
            The user information retrieved from Google or None if unsuccessful.
        """
        time.sleep(params.PRE_GUEST_LOGIN_SLEEP_TIME)
        if 'GoogleModel.get_google_user_info' not in st.session_state:
            st.session_state['GoogleModel.get_google_user_info'] = None
        if not st.session_state['GoogleModel.get_google_user_info']:
            st.session_state['GoogleModel.get_google_user_info'] = True
            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "code": auth_code,
                "client_id": self.google['client_id'],
                "client_secret": self.google.get('client_secret'),
                "redirect_uri": self.google['redirect_uri'],
                "grant_type": "authorization_code"
                # "code_verifier": self.code_verifier
            }
            token_r = requests.post(token_url, data=token_data, timeout=10)
            token_json = token_r.json()
            if 'access_token' not in token_json:
                print('No access token received')
                st.rerun()
            user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
            user_info_headers = {
                "Authorization": f"Bearer {token_json['access_token']}"
            }
            user_info_r = requests.get(user_info_url, headers=user_info_headers, timeout=10)
            if user_info_r.status_code != 200:
                raise LoginError('Failed to retrieve user information')
            return user_info_r.json()
    def guest_login(self) -> Union[str, dict]:
        """
        Handles the login process and fetches user information or returns the authorization
        endpoint.

        Returns
        -------
        Union[str, dict]
            If initiated returns the authorization endpoint URL as a string, 
            subsequently returns a dictionary containing the decoded JWT OAuth2 token.
        """
        auth_code = st.query_params.get('code')
        if auth_code:
            user_info = self.get_google_user_info(auth_code)
            if user_info:
                return user_info
        else:
            return self.login_google()
        return None
