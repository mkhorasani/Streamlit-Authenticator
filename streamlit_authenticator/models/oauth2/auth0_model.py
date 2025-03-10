import base64  
import hashlib  
import os  
import time  
from typing import Union  
  
import requests  
import streamlit as st  
  
from ... import params  
from ...utilities import LoginError  
  
class Auth0Model:  
    """  
    This class executes the logic for an Auth0 OAuth2 login using PKCE  
    (Proof Key for Code Exchange).  
    """  
    def __init__(self, auth0: dict):  
        """  
        Create a new instance of "Auth0Model".  
          
        Parameters  
        ----------  
        auth0: dict  
            Dictionary containing the Auth0 OAuth2 configuration, including client_id,  
            redirect_uri, and client_secret.  
        """  
        self.auth0 = auth0
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
  
    def login_auth0(self) -> str:  
        """  
        Initiate login with Auth0 using PKCE.  
  
        Returns  
        -------  
        str  
            The authorization endpoint URL for Auth0 login.  
        """  
        #self.generate_code_verifier()  
        #code_challenge = self.generate_code_challenge()  
        auth0_auth_endpoint = (  
            f"https://{self.auth0['domain']}/authorize"  
            f"?audience={self.auth0['audience']}"
            f"&scope=openid%20profile%20email"  
            f"&response_type=code"  
            f"&client_id={self.auth0['client_id']}"  
            f"&redirect_uri={self.auth0['redirect_uri']}"  
            #f"&code_challenge={code_challenge}"  
            #f"&code_challenge_method=S256"  
        )  
        return auth0_auth_endpoint  
  
    def get_auth0_user_info(self, auth_code: str) -> dict:  
        """  
        Exchange the authorization code for an access token using the PKCE flow.  
  
        Parameters  
        ----------  
        auth_code : str  
            The authorization code received from Auth0.  
  
        Returns  
        -------  
        dict  
            The user information retrieved from Auth0 or None if unsuccessful.  
        """  
        time.sleep(params.PRE_GUEST_LOGIN_SLEEP_TIME)  
        if 'Auth0Model.get_auth0_user_info' not in st.session_state:  
            st.session_state['Auth0Model.get_auth0_user_info'] = None  
        if not st.session_state['Auth0Model.get_auth0_user_info']:  
            st.session_state['Auth0Model.get_auth0_user_info'] = True  
            token_url = f"https://{self.auth0['domain']}/oauth/token"  
            token_data = {  
                "grant_type": "authorization_code",   
                "client_id": self.auth0['client_id'], 
                #"code_verifier": self.code_verifier,
                "client_secret": self.auth0.get('client_secret'),  
                "code": auth_code,
                "redirect_uri": self.auth0['redirect_uri']
            }  
            token_r = requests.post(token_url, data=token_data, headers={'content-type': 'application/x-www-form-urlencoded'}, timeout=10)  
            token_json = token_r.json()  
            if 'access_token' not in token_json:  
                print('No access token received')  
                st.rerun()  
            user_info_url = f"https://{self.auth0['domain']}/userinfo"  
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
            user_info = self.get_auth0_user_info(auth_code)  
            if user_info:  
                return user_info  
        else:  
            return self.login_auth0()  
        return None  
