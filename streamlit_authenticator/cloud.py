import yaml
import json
import requests
import streamlit as st
from yaml.loader import SafeLoader

from exceptions import CloudError

class Cloud:
    """
    This class will read and write the config file to the cloud.
    """
    def __init__(_self, cloud_credentials: dict=None):
        """
        Create a new instance of "Cloud".

        Parameters
        ----------
        cloud: dict
            The dictionary containing the registered email and API key that enables connection to the cloud.
        """
        _self.email = cloud_credentials['email']
        _self.API_key = cloud_credentials['API_key']
        _self.github_file_url = 'https://raw.githubusercontent.com/mkhorasani/streamlit_authenticator_variables/main/variables'
        _self.variable_name_to_read = 'server_address'
        _self.url = _self.get_remote_variable(_self.github_file_url, _self.variable_name_to_read)
    
    @st.cache_data(show_spinner=False)
    def get_remote_variable(_self, url, variable_name):
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

    @st.cache_data(show_spinner=False)
    def write_config_to_cloud(_self, file_path: str=None, config_dict: dict=None):
        """
        Writes the config to the cloud.

        Parameters
        ----------
        file_path: str
            Path to the local config file.
        config_dict: str
            Config dictionary.

        Returns
        -------
        bool
            The state of the write request.
        """
        try:
            if file_path:
                with open(file_path) as file:
                    config = yaml.load(file, Loader=SafeLoader)
            elif config_dict:
                config = config_dict  
            url = _self.url + 'write_data'
            headers = {'Authorization': f'Bearer {_self.email} {_self.API_key}'}
            response = requests.post(url, headers=headers, json=config)
        except Exception as e:
            raise CloudError(e)

        if 'error' in json.loads(response.text).keys():
            raise CloudError(list(json.loads(response.text).values())[0])
        else:
            return True

    def read_config_from_cloud(_self):
        """
        Reads the config file from the cloud.
        
        Returns
        -------
        dict
            The config file read from the cloud.
        """
        try:
            url = _self.url + 'get_data'
            headers = {'Authorization': f'Bearer {_self.email} {_self.API_key}'}
            response = requests.get(url, headers=headers)
            data = response.json()
        except:
            raise CloudError('Failed to connect to the cloud')
        
        if 'error' in str(data.keys()):
            raise CloudError(str(list(data.values())[0]))
        else:
            return data