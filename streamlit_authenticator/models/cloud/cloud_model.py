"""
Script description: This module handles cloud-related transactions.

Libraries imported:
-------------------
- typing: Module implementing standard typing notations for Python functions.
- json: Module used to create JSON documents.
- requests: Module for making HTTP requests to the OAuth2 server.
- streamlit: Framework used to build pure Python web applications.
"""

from typing import Literal, Optional

import json
import requests
import streamlit as st

from ... import params
from ...utilities import CloudError


class CloudModel:
    """
    Handles cloud-related transactions, including retrieving remote variables
    and sending emails.
    """
    def __init__(
            _self,
            api_key: str,
            server_url: Optional[str] = None
            ) -> None:
        """
        Initializes the CloudModel instance.

        Parameters
        ----------
        api_key : str
            API key used to connect to the cloud server.
        server_url : str, optional
            Cloud server URL used for cloud-related transactions.
        """
        _self.api_key = api_key
        _self.server_url = server_url if server_url else \
            _self.get_remote_variable(params.REMOTE_VARIABLES_LINK,
                                      'TWO_FACTOR_AUTH_SERVER_ADDRESS')
    @st.cache_data(show_spinner=False)
    def get_remote_variable(_self, url: str, variable_name: str) -> str:
        """
        Retrieves a variable stored on a remote server.

        Parameters
        ----------
        url : str
            URL of the remote file storing variables.
        variable_name : str
            Name of the variable to retrieve.

        Returns
        -------
        Optional[str]
            The value of the remote variable if found, otherwise None.
        """
        try:
            response = requests.get(url, timeout = params.TIMEOUT)
            if response.status_code == 200:
                content = response.text
                variables = {}
                for line in content.splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        variables[key.strip()] = value.strip()
                if variable_name in variables:
                    return variables[variable_name]
        except Exception as e:
            print(f"""Cannot find server URL, please enter it manually into the 'Authenticate' class
                  as server_url='{params.SERVER_URL}'""")
            raise CloudError(str(e)) from e
    def send_email(_self, email_type: Literal['2FA', 'PWD', 'USERNAME'], recipient: str,
                   content: str) -> bool:
        """
        Sends an email to a specified recipient.

        Parameters
        ----------
        email_type : Literal['2FA', 'PWD', 'USERNAME']
            Type of email to send:
            - '2FA': Two-factor authentication code.
            - 'PWD': Reset password.
            - 'USERNAME': Forgotten username.
        recipient : str
            Recipient's email address.
        content : str
            Email body.

        Returns
        -------
        bool
            True if the email was sent successfully.
        """
        try:
            email_data = {
                'content': content,
                'recipient': recipient,
                'email_type': email_type
            }
            url = _self.server_url + params.SEND_EMAIL
            headers = {'Authorization': f'Bearer {_self.api_key}'}
            response = requests.post(url, headers=headers, json=email_data, timeout=params.TIMEOUT)
        except Exception as e:
            raise CloudError(str(e)) from e
        if 'error' in json.loads(response.text).keys():
            raise CloudError(list(json.loads(response.text).values())[0])
        return True
