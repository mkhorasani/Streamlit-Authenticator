"""
Script description: This module executes the logic for cloud related transactions. 

Libraries imported:
- json: Module used to create JSON documents.
- typing: Module implementing standard typing notations for Python functions.
- requests: Module executing the http requests made to the OAuth2 server.
- streamlit: Framework used to build pure Python web applications.
"""

import json
import requests
import streamlit as st

from typing import Optional

import params
from utilities import CloudError

class CloudModel:
    """
    This class executes the logic for cloud related transactions.
    """
    def __init__(_self, API_KEY: str=None, SERVER_URL: Optional[str]=None):
        """
        Create a new instance of "CloudModel".

        Parameters
        ----------
        API_KEY: str
            API key used to connect to the cloud server.
        SERVER_URL: str, optional
            Cloud server URL used for cloud related transactions.
        """
        _self.API_KEY = API_KEY
        _self.SERVER_URL = SERVER_URL if SERVER_URL else \
            _self.get_remote_variable(params.REMOTE_VARIABLES_LINK, 'TWO_FACTOR_AUTH_SERVER_ADDRESS')
    @st.cache_data(show_spinner=False)
    def get_remote_variable(_self, url: str=None, variable_name: str=None) -> str:
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
            print(f"""Cannot find server URL, please enter it manually into the 'Authenticate' class 
                  as SERVER_URL='{params.SERVER_URL}'""")
            raise CloudError(e)
    def send_email(_self, recepient: str='', subject: str='', body: str='') -> bool:
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
            url = _self.SERVER_URL + params.SEND_EMAIL
            headers = {'Authorization': f'Bearer {_self.API_KEY}'}
            response = requests.post(url, headers=headers, json=email_data)
        except Exception as e:
            raise CloudError(e)
        if 'error' in json.loads(response.text).keys():
            raise CloudError(list(json.loads(response.text).values())[0])
        else:
            return True
        return None
