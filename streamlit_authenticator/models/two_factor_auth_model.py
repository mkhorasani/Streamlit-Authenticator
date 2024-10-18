import json
import requests
import streamlit as st

from .. import params
from ..utilities import Helpers, TwoFactorAuthError

class TwoFactorAuthModel:
    """
    This class executes the logic for two factor authentication.
    """
    def __init__(self, API_key: str=None):
        """
        Create a new instance of "TwoFactorAuthModel".

        Parameters
        ----------
        API_key: str
            The API key used to connect to the two factor authentication server.
        """
        self.API_key = API_key
        self.server_url = self.get_remote_variable(params['REMOTE_VARIABLES_LINK'], 'TWO_FACTOR_AUTH_SERVER_ADDRESS')
    def generate_two_factor_auth_code(self) -> str:
        """
        Generates a random four digit code.

        Returns
        -------
        str
            Random four digit code.
        """
        return Helpers.generate_random_string(length=4, letters=False, punctuation=False)
    @st.cache_data(show_spinner=False)
    def get_remote_variable(self, url: str=None, variable_name: str=None) -> str:
        """
        Gets a remote variable.

        Parameters
        ----------
        url: str
            Path to the remote file storing variables.
        variable_name: str
            Name of variable.
        """
        try:
            response = requests.get(server_url)
            if response.status_code == 200:
                content = response.text
                exec(content)
                return locals()[variable_name]
        except Exception as e:
            raise TwoFactorAuthError(e)
    def send_email(self, recepient: str='', subject: str='', body: str='') -> bool:
        """
        Sends an email to a specified recepient.

        Parameters
        ----------
        recepient: str
            Recepient's email address.
        subject: str
            Email subject.
        body: str
            Email body.

        Returns
        -------
        bool
            Status of sending email, 
            None: no email sent, 
            True: email sent successfully, 
            False: email failed to sent.
        """
        pass
