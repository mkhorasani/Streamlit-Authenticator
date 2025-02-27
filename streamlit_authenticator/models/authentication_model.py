"""
Script description: This module executes the logic for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets.

Libraries imported:
- json: Module used to create JSON documents.
- typing: Module implementing standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

import json
from typing import Any, Callable, Dict, List, Literal, Optional

import streamlit as st

from models.cloud import CloudModel
from models.oauth2 import GoogleModel
from models.oauth2 import MicrosoftModel
import params
from utilities import (Encryptor,
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
    This class executes the logic for the login, logout, register user, reset password,
    forgot password, forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: Optional[dict]=None, auto_hash: bool=True,
                 path: Optional[str]=None, api_key: Optional[str]=None, secret_key: str='some_key',
                 server_url: Optional[str]=None, validator: Optional[Validator]=None):
        """
        Create a new instance of "AuthenticationModel".

        Parameters
        ----------
        credentials: dict
            Dictionary of usernames, names, passwords, emails, and other user data.
        auto_hash: bool
            Automatic hashing requirement for the passwords,
            True: plain text passwords will be automatically hashed,
            False: plain text passwords will not be automatically hashed.
        path: str
            File path of the config file.
        api_key: str, optional
            API key used to connect to the cloud server to send reset passwords and two
            factor authorization codes to the user by email.
        secret_key : str
            A secret key used for encryption and decryption.
        server_url: str, optional
            Cloud server URL used for cloud related transactions.
        validator: Validator, optional
            Validator object that checks the validity of the username, name, and email fields.
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
        Checks the validity of the entered credentials.

        Parameters
        ----------
        username: str
            The entered username.
        password: str
            The entered password.

        Returns
        -------
        bool
            Validity of entered credentials,
            None: no credentials entered,
            True: correct credentials,
            False: incorrect credentials.
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
        Counts the number of users logged in concurrently.

        Returns
        -------
        int
            Number of users logged in concurrently.
        """
        concurrent_users = 0
        for username, _ in self.credentials['usernames'].items():
            if 'logged_in' in self.credentials['usernames'][username] and \
                self.credentials['usernames'][username]['logged_in']:
                concurrent_users += 1
        return concurrent_users
    def _credentials_contains_value(self, value: str) -> bool:
        """
        Checks to see if a value is present in the credentials dictionary.

        Parameters
        ----------
        value: str
            Value being checked.

        Returns
        -------
        bool
            Presence/absence of the value,
            True: value present,
            False value absent.
        """
        return any(value in d.values() for d in self.credentials['usernames'].values())
    def forgot_password(self, username: str, callback: Optional[Callable]=None) -> tuple:
        """
        Creates a new random password for the user.

        Parameters
        ----------
        username: str
            Username associated with the forgotten password.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        str
            New random password of the user.
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
    def forgot_username(self, email: str, callback: Optional[Callable]=None) -> tuple:
        """
        Gets the forgotten username of a user.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        """
        username = self._get_username('email', email)
        if username:
            user = self.credentials['usernames'][username]
            if callback:
                callback({'widget': 'Forgot username', 'username': username, 'email': email,
                        'name': self._get_user_name(username), 'roles': user.get('roles')})
        return username, email
    def generate_two_factor_auth_code(self, email: str, widget: Optional[str]=None) -> str:
        """
        Generates and sends a two factor authentication code.

        Parameters
        ----------
        email: str
            Email to send two factor authentication code to.
        widget: str, optional
            Widget name to append to session state variable name.
        """
        two_factor_auth_code = Helpers.generate_random_string(length=4, letters=False,
                                                              punctuation=False)
        st.session_state[f'2FA_code_{widget}'] = self.encryptor.encrypt(two_factor_auth_code)
        self.send_email('2FA', email, two_factor_auth_code)
    def _get_username(self, key: str, value: str) -> str:
        """
        Gets the username based on a provided entry.

        Parameters
        ----------
        key: str
            Name of the credential to query i.e. "email".
        value: str
            Value of the queried credential i.e. "jsmith@gmail.com".

        Returns
        -------
        str
            Username associated with the given key, value pair i.e. "jsmith".
        """
        for username, values in self.credentials['usernames'].items():
            if values[key] == value:
                return username
        return False
    def _get_user_name(self, username: str) -> tuple:
        """
        Gets the user's name.

        Parameters
        ----------
        username: str
            Username of the user.

        Returns
        -------
        str
            Name associated with the given username.
        """
        user = self.credentials['usernames'][username]
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip() \
            or user.get('name')
        return name
    def guest_login(self, cookie_controller: Any, provider: str='google',
                    oauth2: Optional[dict]=None, max_concurrent_users: Optional[int]=None,
                    single_session: bool=False, roles: Optional[List[str]]=None,
                    callback: Optional[Callable]=None) -> Optional[str]:
        """
        Executes the guest login by setting authentication status to true and adding the user's
        username and name to the session state.

        Parameters
        ----------
        cookie_controller: CookieController
            Cookie controller object used to set the re-authentication cookie.
        provider: str
            OAuth2 provider selection i.e. google or microsoft.
        oauth2: dict, optional
            Configuration parameters to implement an OAuth2 authentication.
        max_concurrent_users: int, optional
            Maximum number of users allowed to login concurrently.
        single_session: bool
            Disables the ability for the same user to log in multiple sessions,
            True: single session allowed,
            False: multiple sessions allowed.
        roles: list, optional
            User roles for guest users.
        callback: callable, optional
            Callback function that will be invoked on button press.

        Returns
        -------
        Optional[str]
            The authorization endpoint URL for the guest login.
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
    def _is_guest_user(self, username: str) -> bool:
        """
        Checks if a username is associated with a guest user.

        Parameters
        ----------
        username: str
            Provided username.

        Returns
        -------
        bool
            Type of user,
            True: guest user,
            False: non-guest user.
        """
        return 'password' not in self.credentials['usernames'].get(username, {'password': None})
    def login(self, username: str, password: str, max_concurrent_users: Optional[int]=None,
              max_login_attempts: Optional[int]=None, token: Optional[Dict[str, str]]=None,
              single_session: bool=False, callback: Optional[Callable]=None) -> bool:
        """
        Executes the login by setting authentication status to true and adding the user's
        username and name to the session state.

        Parameters
        ----------
        username: str
            The entered username.
        password: str
            The entered password.
        max_concurrent_users: int, optional
            Maximum number of users allowed to login concurrently.
        max_login_attempts: int, optional
            Maximum number of failed login attempts a user can make.
        token: dict, optional
            The re-authentication cookie to get the username from.
        single_session: bool
            Disables the ability for the same user to log in multiple sessions,
            True: single session allowed,
            False: multiple sessions allowed.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            Status of authentication,
            None: no credentials entered,
            True: correct credentials,
            False: incorrect credentials.
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
    def logout(self, callback: Optional[Callable]=None):
        """
        Clears the cookie and session state variables associated with the logged in user.

        Parameters
        ----------
        callback: callable, optional
            Callback function that will be invoked on button press.
        """
        self.credentials['usernames'][st.session_state['username']]['logged_in'] = False
        if callback:
            callback({'widget': 'Logout', 'username': st.session_state.get('username'),
                      'email': st.session_state.get('email'), 'name': st.session_state.get('name'),
                      'roles': st.session_state.get('roles')})
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None
        st.session_state['email'] = None
        st.session_state['roles'] = None
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def _record_failed_login_attempts(self, username: str, reset: bool=False):
        """
        Records the number of failed login attempts for a given username.

        Parameters
        ----------
        username: str
            The entered username.
        reset: bool
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
                              roles: Optional[List[str]]=None):
        """
        Adds the new user's information to the credentials dictionary.

        Parameters
        ----------
        username: str
            Username of the new user.
        first_name: str
            First name of the new user.
        last_name: str
            Last name of the new user.
        password: str
            Password of the new user.
        email: str
            Email of the new user.
        password_hint: str
            Password hint for the user to remember their password.
        roles: list, optional
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
                      pre_authorized: Optional[List[str]]=None,
                      roles: Optional[List[str]]=None,
                      callback: Optional[Callable]=None) -> tuple:
        """
        Registers a new user's first name, last name, username, password, email, and roles.

        Parameters
        ----------
        new_first_name: str
            First name of the new user.
        new_last_name: str
            Last name of the new user.
        new_email: str
            Email of the new user.
        new_username: str
            Username of the new user.
        new_password: str
            Password of the new user.
        password_hint: str
            Password hint for the user to remember their password.
        pre-authorized: list, optional
            List of emails of unregistered users who are authorized to register.
        roles: list, optional
            User roles for registered users.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        str
            Email of the new user.
        str
            Username of the new user.
        str
            Name of the new user.
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
                       callback: Optional[Callable]=None) -> bool:
        """
        Validates the user's current password and subsequently saves their new password to the
        credentials dictionary.

        Parameters
        ----------
        username: str
            Username of the user.
        password: str
            Current password of the user.
        new_password: str
            New password of the user.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of resetting the password,
            True: password reset successfully.
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
        Implements the logic to send an email.

        Parameters
        ----------
        email_type: str
            Type of email to send,
            2FA: two factor authentication code,
            PWD: reset password,
            USERNAME: forgotten username.
        recipient: str
            Email to send two factor authentication code to.
        content: str
            Email content.

        Returns
        -------
        bool
            Status of sending email,
            None: no email sent,
            True: email sent successfully.
        """
        if not self.api_key:
            raise CloudError(f"""Please provide an API key to use the two factor authentication
                             feature. For further information please refer to
                             {params.TWO_FACTOR_AUTH_LINK}.""")
        if not self.validator.validate_email(recipient):
            raise CloudError('Email not valid')
        return self.cloud_model.send_email(email_type, recipient, content)
    def send_password(self, result: Optional[dict]=None) -> bool:
        """
        Implements the logic to send the password by email.

        Parameters
        ----------
        result: dict, optional
            Dict containing user's username, email, and generated password.

        Returns
        -------
        bool
            Status of sending password,
            None: no password sent,
            True: password sent successfully.
        """
        if not result and '2FA_content_forgot_password' in st.session_state:
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_password'])
            _, email, password = json.loads(decrypted)
            return self.send_email('PWD', email, password)
        return self.send_email('PWD', result[1], result[2])
    def send_username(self, result: Optional[dict]=None) -> bool:
        """
        Implements the logic to send the username by email.

        Parameters
        ----------
        result: dict, optional
            Dict containing user's username and email.

        Returns
        -------
        bool
            Status of sending username,
            None: no username sent,
            True: username sent successfully.
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
        username: str
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
    def _update_entry(self, username: str, key: str, value: str):
        """
        Updates the credentials dictionary with the user's updated entry.

        Parameters
        ----------
        username: str
            Username of the user to update the entry for.
        key: str
            Updated entry key i.e. "email".
        value: str
            Updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials['usernames'][username][key] = value
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def _update_password(self, username: str, password: str):
        """
        Updates the credentials dictionary with the user's hashed reset password.

        Parameters
        ----------
        username: str
            Username of the user to update the password for.
        password: str
            Updated plain text password.
        """
        self.credentials['usernames'][username]['password'] = Hasher.hash(password)
        if self.path:
            Helpers.update_config_file(self.path, 'credentials', self.credentials)
    def update_user_details(self, username: str, field: str, new_value: str,
                            callback: Optional[Callable]=None) -> bool:
        """
        Validates the user's updated name or email and subsequently modifies it in the
        credentials dictionary.

        Parameters
        ----------
        username: str
            Username of the user.
        field: str
            Field to update i.e. name or email.
        new_value: str
            New value for the name or email.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of updating the user's detail,
            True: details updated successfully.
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
