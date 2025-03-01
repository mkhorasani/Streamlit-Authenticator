"""
Script description: This module executes the logic for authentication, including login, logout,
user registration, password reset, and user modifications.

Libraries imported:
-------------------
- json: Handles JSON documents.
- typing: Provides standard type hints for Python functions.
- streamlit: Framework used for building web applications.
"""

import json
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple

import streamlit as st

from ..models.cloud import CloudModel
from ..models.oauth2 import GoogleModel
from ..models.oauth2 import MicrosoftModel
from .. import params
from ..utilities import (Encryptor,
                         Hasher,
                         Helpers,
                         CloudError,
                         CredentialsError,
                         ForgotError,
                         LoginError,
                         RegisterError,
                         ResetError,
                         UpdateError,
                         Validator)


class AuthenticationModel:
    """
    Manages user authentication, including login, logout, registration, password resets, 
    and user details updates.
    """
    def __init__(
            self,
            credentials: Optional[Dict[str, Any]] = None,
            auto_hash: bool = True,
            path: Optional[str] = None,
            api_key: Optional[str] = None,
            secret_key: str = 'some_key',
            server_url: Optional[str] = None,
            validator: Optional[Validator] = None
            ) -> None:
        """
        Initializes the AuthenticationModel instance.

        Parameters
        ----------
        credentials: dict
            Dictionary of usernames, names, passwords, emails, and other user data.
        auto_hash: bool
            If True, automatically hashes plain-text passwords.
        path: str
            File path of the config file.
        api_key: str, optional
            API key used to connect to the cloud server to send reset passwords and two
            factor authorization codes to the user by email.
        secret_key : str
            A secret key used for encryption and decryption.
        server_url: str, optional
            Cloud server URL used for cloud-related transactions.
        validator: Validator, optional
            Validator object to check username, name, and email fields.
        """
        self.api_key = api_key
        self.config = self.credentials = None
        self.path = path
        if self.path:
            self.config = Helpers.read_config_file(path)
            self.credentials = self.config.get('credentials')
            self.api_key = self.api_key or self.config.get('api_key')
        else:
            self.credentials = credentials
        self.cloud_model = CloudModel(self.api_key, server_url) if self.api_key else None
        self.secret_key = secret_key
        self.validator = validator if validator is not None else Validator()
        if self.credentials['usernames']:
            self.credentials['usernames'] = {
                key.lower(): value
                for key, value in self.credentials['usernames'].items()
                }
            if auto_hash:
                if len(self.credentials['usernames']) > params.AUTO_HASH_MAX_USERS:
                    print(f"""Auto hashing in progress. To avoid runtime delays, please manually
                          pre-hash all plain text passwords in the credentials using the
                          Hasher.hash_passwords function, and set auto_hash=False for the
                          Authenticate class. For more information please refer to
                          {params.AUTO_HASH_MAX_USERS_LINK}.""")
                for username, _ in self.credentials['usernames'].items():
                    if 'password' in self.credentials['usernames'][username] and \
                        not Hasher.is_hash(self.credentials['usernames'][username]['password']):
                        self.credentials['usernames'][username]['password'] = \
                        Hasher.hash(self.credentials['usernames'][username]['password'])
        else:
            self.credentials['usernames'] = {}
        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'email' not in st.session_state:
            st.session_state['email'] = None
        if 'roles' not in st.session_state:
            st.session_state['roles'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None
        self.encryptor = Encryptor(self.secret_key)
    def check_credentials(self, username: str, password: str) -> bool:
        """
        Checks whether the entered credentials are valid.

        Parameters
        ----------
        username : str
            The entered username.
        password : str
            The entered password.

        Returns
        -------
        bool
            True if credentials are valid, False otherwise.
        """
        if username not in self.credentials['usernames']:
            return False
        try:
            if Hasher.check_pw(password, self.credentials['usernames'][username]['password']):
                return True
            self._record_failed_login_attempts(username)
            return False
        except (TypeError, ValueError) as e:
            print(f'{e} please hash all plain text passwords')
        return None
    def _count_concurrent_users(self) -> int:
        """
        Counts the number of currently logged-in users.

        Returns
        -------
        int
            Number of concurrently logged-in users.
        """
        concurrent_users = 0
        for username, _ in self.credentials['usernames'].items():
            if 'logged_in' in self.credentials['usernames'][username] and \
                self.credentials['usernames'][username]['logged_in']:
                concurrent_users += 1
        return concurrent_users
    def _credentials_contains_value(self, value: str) -> bool:
        """
        Checks if a value exists in the credentials dictionary.

        Parameters
        ----------
        value : str
            The value to check.

        Returns
        -------
        bool
            True if the value is found, False otherwise.
        """
        return any(value in d.values() for d in self.credentials['usernames'].values())
    def forgot_password(self, username: str, callback: Optional[Callable] = None
                        ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Generates a new random password for a user.

        Parameters
        ----------
        username: str
            The username for which the password needs to be reset.
        callback: Callable, optional
            Function to be invoked upon form submission.

        Returns
        -------
        tuple[str, str, str] or (None, None, None)
            The username, email, and new randomly generated password if successful, 
            otherwise (None, None, None).
        """
        if self._is_guest_user(username):
            raise ForgotError('Guest user cannot use forgot password widget')
        if username in self.credentials['usernames']:
            user = self.credentials['usernames'][username]
            email = user.get('email')
            random_password = self._set_random_password(username)
            if callback:
                callback({'widget': 'Forgot password', 'username': username, 'email': email,
                          'name': self._get_user_name(username), 'roles': user.get('roles'),
                          'random_password': random_password})
            return (username, email, random_password)
        return False, None, None
    def forgot_username(self, email: str, callback: Optional[Callable]=None
                        ) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieves the username associated with a given email.

        Parameters
        ----------
        email : str
            The email associated with the forgotten username.
        callback : Callable, optional
            Function to be invoked upon form submission.

        Returns
        -------
        tuple[str, str] or (None, None)
            The username and email if found, otherwise (None, None).
        """
        username = self._get_username('email', email)
        if username:
            user = self.credentials['usernames'][username]
            if callback:
                callback({'widget': 'Forgot username', 'username': username, 'email': email,
                        'name': self._get_user_name(username), 'roles': user.get('roles')})
        return username, email
    def generate_two_factor_auth_code(self, email: str, widget: Optional[str] = None) -> str:
        """
        Generates and sends a two-factor authentication code to the user's email.

        Parameters
        ----------
        email : str
            Email to send two factor authentication code to.
        widget : str, optional
            Widget name to append to session state variable name.
        """
        two_factor_auth_code = Helpers.generate_random_string(length=4, letters=False,
                                                              punctuation=False)
        st.session_state[f'2FA_code_{widget}'] = self.encryptor.encrypt(two_factor_auth_code)
        self.send_email('2FA', email, two_factor_auth_code)
    def _get_username(self, key: str, value: str) -> Optional[str]:
        """
        Retrieves the username associated with a given key-value pair.

        Parameters
        ----------
        key : str
            The field name to search in (e.g., "email").
        value : str
            The value to search for (e.g., "user@example.com").

        Returns
        -------
        str or None
            The associated username if found, otherwise None.
        """
        for username, values in self.credentials['usernames'].items():
            if values[key] == value:
                return username
        return False
    def _get_user_name(self, username: str) -> Optional[str]:
        """
        Retrieves the full name of a user.

        Parameters
        ----------
        username : str
            The username of the user.

        Returns
        -------
        Optional[str]
            The full name of the user if available, otherwise None.
        """
        user = self.credentials['usernames'][username]
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() \
            or user.get('name')
        return name
    def guest_login(self, cookie_controller: Any, provider: str = 'google',
                    oauth2: Optional[Dict[str, Any]] = None,
                    max_concurrent_users: Optional[int] = None,
                    single_session: bool = False, roles: Optional[List[str]] = None,
                    callback: Optional[Callable] = None) -> Optional[str]:
        """
        Handles guest login via OAuth2 providers.

        Parameters
        ----------
        cookie_controller : Any
            The cookie controller used for setting session cookies.
        provider : str, default='google'
            OAuth2 provider name (e.g., 'google' or 'microsoft').
        oauth2 : dict, optional
            OAuth2 configuration parameters.
        max_concurrent_users : int, optional
            Maximum number of concurrent guest users allowed.
        single_session : bool, default=False
            If True, prevents multiple logins from the same user.
        roles : list, optional
            Roles assigned to the guest user.
        callback : Callable, optional
            Function to be executed after successful login.

        Returns
        -------
        Optional[str]
            Redirect URL if authentication requires further steps, otherwise None.
        """
        if not oauth2 and self.path:
            oauth2 = self.config['oauth2']
        if provider.lower() == 'google':
            google_model = GoogleModel(oauth2[provider])
            result = google_model.guest_login()
        elif provider.lower() == 'microsoft':
            microsoft_model = MicrosoftModel(oauth2[provider])
            result = microsoft_model.guest_login()
        if isinstance(result, dict):
            if isinstance(max_concurrent_users, int) and self._count_concurrent_users() > \
                max_concurrent_users - 1:
                st.query_params.clear()
                raise LoginError('Maximum number of concurrent users exceeded')
            result['email'] = result.get('email', result.get('upn')).lower()
            if result['email'] not in self.credentials['usernames']:
                self.credentials['usernames'][result['email']] = {}
            if not self._is_guest_user(result['email']):
                st.query_params.clear()
                raise LoginError('User already exists')
            self.credentials['usernames'][result['email']] = \
                {'email': result['email'],
                 'logged_in': True, 'first_name': result.get('given_name', ''),
                 'last_name': result.get('family_name', ''),
                 'picture': result.get('picture', None),
                 'roles': roles}
            if single_session and self.credentials['usernames'][result['email']]['logged_in']:
                raise LoginError('Cannot log in multiple sessions')
            st.session_state['authentication_status'] = True
            st.session_state['name'] = f'{result.get("given_name", "")} ' \
                f'{result.get("family_name", "")}'
            st.session_state['email'] = result['email']
            st.session_state['username'] = result['email']
            st.session_state['roles'] = roles
            st.query_params.clear()
            cookie_controller.set_cookie()
            if self.path:
                Helpers.update_config_file(self.path, 'credentials', self.credentials)
            if callback:
                callback({'widget': 'Guest login', 'email': result['email']})
            return None
        return result
    def _is_guest_user(self, username : str) -> bool:
        """
        Checks if a username is associated with a guest user.

        Parameters
        ----------
        username : str
            Provided username.

        Returns
        -------
        bool
            Type of user,
            True: guest user,
            False: non-guest user.
        """
        return 'password' not in self.credentials['usernames'].get(username, {'password': None})
    def login(self, username: str, password: str, max_concurrent_users: Optional[int] = None,
              max_login_attempts: Optional[int] = None, token: Optional[Dict[str, str]] = None,
              single_session: bool = False, callback: Optional[Callable] = None) -> bool:
        """
        Executes the login by setting authentication status to true and adding the user's
        username and name to the session state.

        Parameters
        ----------
        username : str
            The entered username.
        password : str
            The entered password.
        max_concurrent_users : int, optional
            Maximum number of users allowed to login concurrently.
        max_login_attempts : int, optional
            Maximum number of failed login attempts a user can make.
        token : dict, optional
            The re-authentication cookie to get the username from.
        single_session : bool
            Disables the ability for the same user to log in multiple sessions,
            True: single session allowed,
            False: multiple sessions allowed.
        callback : Callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool or None
            True if login succeeds, False if it fails, or None if credentials are missing.
        """
        if username:
            if (isinstance(max_login_attempts, int) and
                self.credentials['usernames'].get(username,
                                                  {}).get('failed_login_attempts',
                                                          0) >= max_login_attempts):
                raise LoginError('Maximum number of login attempts exceeded')
            if self.check_credentials(username, password):
                if isinstance(max_concurrent_users, int) and self._count_concurrent_users() > \
                    max_concurrent_users - 1:
                    raise LoginError('Maximum number of concurrent users exceeded')
                user = self.credentials['usernames'][username]
                if single_session and user.get('logged_in'):
                    raise LoginError('Cannot log in multiple sessions')
                st.session_state['email'] = user.get('email')
                st.session_state['name'] = self._get_user_name(username)
                st.session_state['roles'] = user.get('roles')
                st.session_state['authentication_status'] = True
                st.session_state['username'] = username
                self._record_failed_login_attempts(username, reset=True)
                self.credentials['usernames'][username]['logged_in'] = True
                if 'password_hint' in st.session_state:
                    del st.session_state['password_hint']
                if self.path:
                    Helpers.update_config_file(self.path, 'credentials', self.credentials)
                if callback:
                    callback({'widget': 'Login', 'username': username, 'email': user.get('email'),
                              'name': self._get_user_name(username), 'roles': user.get('roles')})
                return True
            st.session_state['authentication_status'] = False
            if username in self.credentials['usernames'] and 'password_hint' in \
                self.credentials['usernames'][username]:
                user = self.credentials['usernames'][username]
                st.session_state['password_hint'] = user.get('password_hint')
            return False
        if token:
            if not token['username'] in self.credentials['usernames']:
                raise LoginError('User not authorized')
            user = self.credentials['usernames'][token['username']]
            st.session_state['email'] = user.get('email')
            st.session_state['name'] = self._get_user_name(token['username'])
            st.session_state['roles'] = user.get('roles')    
            st.session_state['authentication_status'] = True
            st.session_state['username'] = token['username']
            self.credentials['usernames'][token['username']]['logged_in'] = True
            if self.path:
                Helpers.update_config_file(self.path, 'credentials', self.credentials)
        return None
    def logout(self, callback: Optional[Callable] = None) -> None:
        """
        Logs out the user by clearing session state variables.

        Parameters
        ----------
        callback : Callable, optional
            Function to be invoked upon logout.
        """
        username = st.session_state.get('username')
        if username and self.credentials and 'usernames' in self.credentials:
            if username in self.credentials['usernames']:
                self.credentials['usernames'][username]['logged_in'] = False
        if callback:
            callback({'widget': 'Logout', 'username': username,
                      'email': st.session_state.get('email'),
                      'name': st.session_state.get('name'),
                      'roles': st.session_state.get('roles')
            })
        st.session_state['logout'] = True
        for key in ['name', 'username', 'authentication_status', 'email', 'roles']:
            st.session_state.setdefault(key, None)
            st.session_state[key] = None
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def _record_failed_login_attempts(self, username: str, reset: bool = False) -> None:
        """
        Records the number of failed login attempts for a given username.

        Parameters
        ----------
        username : str
            The entered username.
        reset : bool
            Reset failed login attempts option,
            True: number of failed login attempts for the user will be reset to 0,
            False: number of failed login attempts for the user will be incremented.
        """
        if 'failed_login_attempts' not in self.credentials['usernames'][username]:
            self.credentials['usernames'][username]['failed_login_attempts'] = 0
        if reset:
            self.credentials['usernames'][username]['failed_login_attempts'] = 0
        else:
            self.credentials['usernames'][username]['failed_login_attempts'] += 1
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def _register_credentials(self, username: str, first_name: str, last_name: str,
                              password: str, email: str, password_hint: str,
                              roles: Optional[List[str]] = None) -> None:
        """
        Adds the new user's information to the credentials dictionary.

        Parameters
        ----------
        username : str
            Username of the new user.
        first_name : str
            First name of the new user.
        last_name : str
            Last name of the new user.
        password : str
            Password of the new user.
        email : str
            Email of the new user.
        password_hint : str
            Password hint for the user to remember their password.
        roles : list, optional
            User roles for registered users.
        """
        user_data = {
            'email': email,
            'logged_in': False,
            'first_name': first_name,
            'last_name': last_name,
            'password': Hasher.hash(password),
            'roles': roles
        }
        if password_hint:
            user_data['password_hint'] = password_hint
        self.credentials['usernames'][username] = user_data
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def register_user(self, new_first_name: str, new_last_name: str, new_email: str,
                      new_username: str, new_password: str, password_hint: str,
                      pre_authorized: Optional[List[str]] = None,
                      roles: Optional[List[str]] = None,
                      callback: Optional[Callable] = None) -> Tuple[str, str, str]:
        """
        Registers a new user's first name, last name, username, password, email, and roles.

        Parameters
        ----------
        new_first_name : str
            First name of the new user.
        new_last_name : str
            Last name of the new user.
        new_email : str
            Email address of the new user.
        new_username : str
            Chosen username for the new user.
        new_password : str
            Password for the new user.
        password_hint : str
            A hint for remembering the password.
        pre_authorized : list, optional
            List of pre-authorized email addresses.
        roles : list, optional
            List of roles assigned to the user.
        callback : Callable, optional
            Function to be executed after successful registration.

        Returns
        -------
        Tuple[str, str, str]
            The email, username, and full name of the registered user.
        """
        if self._credentials_contains_value(new_email):
            raise RegisterError('Email already taken')
        if new_username in self.credentials['usernames']:
            raise RegisterError('Username/email already taken')
        if not pre_authorized and self.path:
            pre_authorized = self.config.get('pre-authorized', {}).get('emails', None)
        if isinstance(pre_authorized, list):
            if new_email in pre_authorized:
                self._register_credentials(new_username, new_first_name, new_last_name,
                                           new_password, new_email, password_hint, roles)
                pre_authorized.remove(new_email)
                if self.path:
                    Helpers.update_config_file(self.path, 'pre-authorized', pre_authorized)
                if callback:
                    callback({'widget': 'Register user', 'new_name': new_first_name,
                              'new_last_name': new_last_name, 'new_email': new_email,
                              'new_username': new_username})
                return new_email, new_username, f'{new_first_name} {new_last_name}'
            raise RegisterError('User not pre-authorized to register')
        self._register_credentials(new_username, new_first_name, new_last_name, new_password,
                                   new_email, password_hint, roles)
        if callback:
            callback({'widget': 'Register user', 'new_name': new_first_name,
                      'new_last_name': new_last_name, 'new_email': new_email,
                      'new_username': new_username})
        return new_email, new_username, f'{new_first_name} {new_last_name}'
    def reset_password(self, username: str, password: str, new_password: str,
                       callback: Optional[Callable] = None) -> bool:
        """
        Resets the user's password after validating the current one.

        Parameters
        ----------
        username : str
            The username of the user.
        password : str
            The current password.
        new_password : str
            The new password to be set.
        callback : callable, optional
            Function to be invoked upon successful password reset.

        Returns
        -------
        bool
            True if the password is reset successfully, otherwise raises an exception.
        """
        if self._is_guest_user(username):
            raise ResetError('Guest user cannot reset password')
        if not self.check_credentials(username, password):
            raise CredentialsError('password')
        self._update_password(username, new_password)
        self._record_failed_login_attempts(username, reset=True)
        user = self.credentials['usernames'][username]
        if callback:
            callback({'widget': 'Reset password', 'username': username, 'email': user.get('email'),
                      'name': self._get_user_name(username), 'roles': user.get('roles')})
        return True
    def send_email(self, email_type: Literal['2FA', 'PWD', 'USERNAME'], recipient: str,
                   content: str) -> bool:
        """
        Sends an email containing authentication-related information.

        Parameters
        ----------
        email_type : Literal['2FA', 'PWD', 'USERNAME']
            Type of email to send.
            - '2FA' for two-factor authentication codes.
            - 'PWD' for password resets.
            - 'USERNAME' for forgotten usernames.
        recipient : str
            Email address of the recipient.
        content : str
            Email body content.

        Returns
        -------
        bool
            True if the email is successfully sent, False otherwise.
        """
        if not self.api_key:
            raise CloudError(f"""Please provide an API key to use the two factor authentication
                             feature. For further information please refer to
                             {params.TWO_FACTOR_AUTH_LINK}.""")
        if not self.validator.validate_email(recipient):
            raise CloudError('Email not valid')
        return self.cloud_model.send_email(email_type, recipient, content)
    def send_password(self, result: Optional[Dict[str, Any]] = None) -> bool:
        """
        Sends a newly generated password to the user via email.

        Parameters
        ----------
        result : dict, optional
            Dictionary containing username, email, and generated password.

        Returns
        -------
        bool
            True if the password was sent successfully, otherwise False.
        """
        if not result and '2FA_content_forgot_password' in st.session_state:
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_password'])
            _, email, password = json.loads(decrypted)
            return self.send_email('PWD', email, password)
        return self.send_email('PWD', result[1], result[2])
    def send_username(self, result: Optional[Dict[str, Any]] = None) -> bool:
        """
        Sends the forgotten username to the user's email.

        Parameters
        ----------
        result : dict, optional
            Dictionary containing the username and email.

        Returns
        -------
        bool
            True if the username was sent successfully, otherwise False.
        """
        if not result and '2FA_content_forgot_username' in st.session_state:
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_username'])
            username, email = json.loads(decrypted)
            return self.send_email('USERNAME', email, username)
        return self.send_email('USERNAME', result[1], result[0])
    def _set_random_password(self, username: str) -> str:
        """
        Updates the credentials dictionary with the user's hashed random password.

        Parameters
        ----------
        username : str
            Username of the user to set the random password for.

        Returns
        -------
        str
            New plain text password that should be transferred to the user securely.
        """
        random_password = Helpers.generate_random_string()
        self.credentials['usernames'][username]['password'] = Hasher.hash(random_password)
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
        return random_password
    def _update_entry(self, username: str, key: str, value: str) -> None:
        """
        Updates the credentials dictionary with the user's updated entry.

        Parameters
        ----------
        username : str
            Username of the user to update the entry for.
        key : str
            Updated entry key i.e. "email".
        value : str
            Updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials['usernames'][username][key] = value
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def _update_password(self, username: str, password: str) -> None:
        """
        Updates the credentials dictionary with the user's hashed reset password.

        Parameters
        ----------
        username : str
            Username of the user to update the password for.
        password : str
            Updated plain text password.
        """
        self.credentials['usernames'][username]['password'] = Hasher.hash(password)
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def update_user_details(self, username: str, field: str, new_value: str,
                            callback: Optional[Callable] = None) -> bool:
        """
        Updates a user's name or email in the credentials database.

        Parameters
        ----------
        username : str
            The username of the user whose details are being updated.
        field : str
            The field to be updated ('email', 'first_name', 'last_name').
        new_value : str
            The new value for the field.
        callback : Callable, optional
            Function to be executed after updating details.

        Returns
        -------
        bool
            True if the update was successful, otherwise raises an exception.
        """
        user = self.credentials['usernames'][username]
        if field == 'email':
            if self._credentials_contains_value(new_value):
                raise UpdateError('Email already taken')
        if 'first_name' not in user:
            self.credentials['usernames'][username]['first_name'] = None
            self.credentials['usernames'][username]['last_name'] = None
        if new_value != self.credentials['usernames'][username][field]:
            self._update_entry(username, field, new_value)
            if field in {'first_name', 'last_name'}:
                st.session_state['name'] = self._get_user_name(username)
                if 'name' in user:
                    del self.credentials['usernames'][username]['name']
            if callback:
                callback({'widget': 'Update user details', 'username': username,
                          'field': field, 'new_value': new_value, 'email': user.get('email'),
                          'name': self._get_user_name(username), 'roles': user.get('roles')})
            return True
        raise UpdateError('New and current values are the same')
