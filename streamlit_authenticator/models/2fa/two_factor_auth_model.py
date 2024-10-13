import json
import requests
import streamlit as st

from exceptions import CloudError

class TwoFactorAuthModel:
    """
    This class will read and write the config file to the cloud.
    """
    def __init__(self, cloud_credentials: dict=None):
        """
        Create a new instance of "Cloud".

        Parameters
        ----------
        cloud: dict
            The dictionary containing the registered email and API key that enables connection to the cloud.
        """
        self.email = cloud_credentials['email']
        self.API_key = cloud_credentials['API_key']
        self.github_file_url = 'https://raw.githubusercontent.com/mkhorasani/streamlit_authenticator_variables/main/variables' #add to params.py
        self.variable_name_to_read = 'server_address'
        self.url = self.get_remote_variable(self.github_file_url, self.variable_name_to_read)
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
            response = requests.get(url)
            if response.status_code == 200:
                content = response.text
                exec(content)
                return locals()[variable_name]
        except Exception as e:
            raise CloudError(e)
