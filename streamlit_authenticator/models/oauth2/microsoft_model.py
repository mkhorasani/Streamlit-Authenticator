"""
Script description: This module handles Microsoft OAuth2 authentication for guest login.

Libraries imported:
-------------------
- base64: Provides encoding/decoding functions for the PKCE security feature.
- hashlib: Implements hashing for the PKCE security feature.
- json: Handles JSON documents for OAuth2 endpoints.
- os: Executes system-level functions.
- time: Implements sleep functions for login delays.
- typing: Provides standard type hints for Python functions.
- requests: Handles HTTP requests made to the OAuth2 server.
- streamlit: Framework for building web applications.
"""

import base64
import hashlib
import json
import os
import time
from typing import Dict, Union

import requests
import streamlit as st

from ... import params
from ...utilities import LoginError


class MicrosoftModel:
    """
    Handles Microsoft OAuth2 authentication using PKCE (Proof Key for Code Exchange).
    """
    def __init__(
            self,
            microsoft: Dict[str, str]
            ) -> None:
        """
        Initializes the MicrosoftModel instance.

        Parameters
        ----------
        microsoft : dict
            Dictionary containing Microsoft OAuth2 configuration, including `client_id`,
            `tenant_id`, `redirect_uri`, and optionally `client_secret`.
        """
        self.microsoft = microsoft
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
    def login_microsoft(self) -> str:
        """
        Constructs the Microsoft OAuth2 authorization URL.

        Returns
        -------
        str
            The Microsoft OAuth2 authorization endpoint URL.
        """
        # self.generate_code_verifier()
        # code_challenge = self.generate_code_challenge()
        microsoft_auth_endpoint = (
            f"https://login.microsoftonline.com/{self.microsoft['tenant_id']}/oauth2/v2.0/authorize"
            f"?client_id={self.microsoft['client_id']}"
            f"&redirect_uri={self.microsoft['redirect_uri']}"
            f"&response_type=code"
            f"&scope=openid%20profile%20email"
            # f"&code_challenge={code_challenge}"
            # f"&code_challenge_method=S256"
        )
        return microsoft_auth_endpoint
    def decode_jwt(self, token: str) -> Dict[str, str]:
        """
        Decodes a JWT token.

        Parameters
        ----------
        token : str
            The JWT OAuth2 token.

        Returns
        -------
        dict
            Decoded JWT payload.
        """
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError('Invalid JWT token')
        decoded_payload = base64.urlsafe_b64decode(parts[1] + '==')
        payload_json = json.loads(decoded_payload)
        return payload_json
    def get_microsoft_user_info(self, auth_code: str) -> Dict[str, str]:
        """
        Exchanges an authorization code for an access token and retrieves user information.

        Parameters
        ----------
        auth_code : str
            The authorization code received from Microsoft after user consent.

        Returns
        -------
        dict
            Dictionary containing user information retrieved from Microsoft.
        """
        time.sleep(params.PRE_GUEST_LOGIN_SLEEP_TIME)
        if 'MicrosoftModel.get_microsoft_user_info' not in st.session_state:
            st.session_state['MicrosoftModel.get_microsoft_user_info'] = None
        if not st.session_state['MicrosoftModel.get_microsoft_user_info']:
            st.session_state['MicrosoftModel.get_microsoft_user_info'] = True
            base_url = 'https://login.microsoftonline.com'
            token_url = f"{base_url}/{self.microsoft['tenant_id']}/oauth2/v2.0/token"
            token_data = {
                'code': auth_code,
                'client_id': self.microsoft['client_id'],
                'client_secret': self.microsoft.get('client_secret'),
                'redirect_uri': self.microsoft['redirect_uri'],
                'grant_type': 'authorization_code'
                # 'code_verifier': self.code_verifier
            }
            token_r = requests.post(token_url, data=token_data, timeout=10)
            token_json = token_r.json()
            if 'access_token' not in token_json:
                print('No access token received')
                st.rerun()
            token_json = self.decode_jwt(token_json['access_token'])
            keys = {'email', 'upn', 'family_name', 'given_name'}
            return {key: token_json[key] for key in keys if key in token_json}
            # user_info_url = 'https://graph.microsoft.com/v1.0/me'
            # user_info_headers = {
            #     "Authorization": f"Bearer {token_json['access_token']}"
            # }
            # user_info_r = requests.get(user_info_url, headers=user_info_headers, timeout=10)
            # if user_info_r.status_code != 200:
            #     raise LoginError('Failed to retrieve user information')
            # return user_info_r.json()
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
            user_info = self.get_microsoft_user_info(auth_code)
            if user_info:
                return user_info
        else:
            return self.login_microsoft()
        return None
