import json
import requests
import streamlit as st

from .. import params
from ..utilities import TwoFactorAuthError

class TwoFactorAuthModel:
    """
    This class executes the logic for two factoru authentication.
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
    @st.cache_data(show_spinner=False)
    def get_remote_variable(self, url, variable_name):
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
            raise CloudError(e)
