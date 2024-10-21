import json
import requests
import streamlit as st

from .. import params
from ..utilities import Helpers, CloudError

class CloudModel:
    """
    This class executes the logic for cloud related transactions.
    """
    def __init__(self, API_KEY: str=None):
        """
        Create a new instance of "CloudModel".

        Parameters
        ----------
        API_key: str
            The API key used to connect to the cloud server.
        """
        self.API_KEY = API_KEY
        self.SERVER_URL = self.get_remote_variable(params['REMOTE_VARIABLES_LINK'], 'TWO_FACTOR_AUTH_SERVER_ADDRESS')
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
            response = requests.get(self.SERVER_URL)
            if response.status_code == 200:
                content = response.text
                exec(content)
                return locals()[variable_name]
        except Exception as e:
            raise CloudError(e)
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
            True: email sent successfully.
        """
        try:
            email_data = {
                "recepient": recepient,
                "subject": subject,
                "body": body
            }
            url = self.SERVER_URL + 'send_email'
            headers = {'Authorization': f'Bearer {self.API_KEY}'}
            response = requests.post(url, headers=headers, json=email_data)
        except Exception as e:
            raise CloudError(e)
        if 'error' in json.loads(response.text).keys():
            raise CloudError(list(json.loads(response.text).values())[0])
        else:
            return True
        return None
