"""
Script description: This module executes the logic for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- typing: Module implementing standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

from typing import Callable, Dict, List, Optional
import streamlit as st

from .. import params
from ..utilities import (Hasher,
                         Helpers,
                         CredentialsError,
                         LoginError,
                         RegisterError,
                         UpdateError,
                         Validator)

class AuthenticationModel:
    """
    This class executes the logic for the login, logout, register user, reset password, 
    forgot password, forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, pre_authorized: Optional[List[str]]=None,
                 validator: Optional[Validator]=None, auto_hash: bool=True):
        """
        Create a new instance of "AuthenticationService".

        Parameters
        ----------
        credentials: dict
            Dictionary of usernames, names, passwords, emails, and other user data.
        pre-authorized: list, optional
            List of emails of unregistered users who are authorized to register.        
        validator: Validator, optional
            Validator object that checks the validity of the username, name, and email fields.
        auto_hash: bool
            Automatic hashing requirement for the passwords, 
            True: plain text passwords will be automatically hashed,
            False: plain text passwords will not be automatically hashed.
        """
        self.credentials = credentials
        if self.credentials['usernames']:
            if 'AuthenticationService.__init__' not in st.session_state:
                st.session_state['AuthenticationService.__init__'] = None
            if not st.session_state['AuthenticationService.__init__']:
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
                        if not Hasher._is_hash(self.credentials['usernames'][username]['password']):
                            self.credentials['usernames'][username]['password'] = \
                            Hasher._hash(self.credentials['usernames'][username]['password'])
                st.session_state['AuthenticationService.__init__'] = True
        else:
            self.credentials['usernames'] = {}
        self.pre_authorized = pre_authorized
        self.validator = validator if validator is not None else Validator()
        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None
    def check_credentials(self, username: str, password: str,
                          max_concurrent_users: Optional[int]=None,
                          max_login_attempts: Optional[int]=None) -> bool:
        """
        Checks the validity of the entered credentials.

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

        Returns
        -------
        bool
            Validity of entered credentials,
            None: no credentials entered, 
            True: correct credentials,
            False: incorrect credentials.
        """
        if isinstance(max_concurrent_users, int) and self._count_concurrent_users() > \
            max_concurrent_users - 1:
            raise LoginError('Maximum number of concurrent users exceeded')
        if username not in self.credentials['usernames']:
            return False
        if isinstance(max_login_attempts, int) and \
            'failed_login_attempts' in self.credentials['usernames'][username] and \
            self.credentials['usernames'][username]['failed_login_attempts'] >= max_login_attempts:
            raise LoginError('Maximum number of login attempts exceeded')
        try:
            if Hasher.check_pw(password, self.credentials['usernames'][username]['password']):
                return True
            self._record_failed_login_attempts(username)
            return False
        except (TypeError, ValueError) as e:
            print(e)
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
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username of the user. 
        str
            Email of the user.
        str
            New random password of the user.
        """
        if username in self.credentials['usernames']:
            if callback:
                callback({'username': username})
            return (username, self._get_credentials()[username]['email'],
                    self._set_random_password(username))
        return False, None, None
    def forgot_username(self, email: str, callback: Optional[Callable]=None) -> tuple:
        """
        Gets the forgotten username of a user.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        """
        if callback:
            callback({'email': email})
        return self._get_username('email', email), email
    def _get_credentials(self) -> dict:
        """
        Gets the user credentials dictionary.

        Returns
        -------
        dict
            User credentials dictionary.
        """
        return self.credentials['usernames']
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
    def login(self, username: str, password: str, max_concurrent_users: Optional[int]=None,
              max_login_attempts: Optional[int]=None, token: Optional[Dict[str, str]]=None,
              callback: Optional[Callable]=None) -> bool:
        """
        Executes login by setting authentication status to true and adding the user's
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
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        bool
            Status of authentication, 
            None: no credentials entered, 
            True: correct credentials, 
            False: incorrect credentials.
        """
        if username:
            if self.check_credentials(username, password, max_concurrent_users, max_login_attempts):
                st.session_state['username'] = username
                st.session_state['name'] = self.credentials['usernames'][username]['name']
                st.session_state['authentication_status'] = True
                self._record_failed_login_attempts(username, reset=True)
                self.credentials['usernames'][username]['logged_in'] = True
                if callback:
                    callback({'username': username})
                return True
            st.session_state['authentication_status'] = False
            return False
        if token:
            if not token['username'] in self.credentials['usernames']:
                raise LoginError('User not authorized')
            st.session_state['username'] = token['username']
            st.session_state['name'] = self.credentials['usernames'][token['username']]['name']
            st.session_state['authentication_status'] = True
            self.credentials['usernames'][token['username']]['logged_in'] = True
        return None
    def logout(self):
        """
        Clears the cookie and session state variables associated with the logged in user.
        """
        self.credentials['usernames'][st.session_state['username']]['logged_in'] = False
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None
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
    def _register_credentials(self, username: str, name: str, password: str, email: str):
        """
        Adds the new user's information to the credentials dictionary.

        Parameters
        ----------
        username: str
            Username of the new user.
        name: str
            Name of the new user.
        password: str
            Password of the new user.
        email: str
            Email of the new user.
        """
        self.credentials['usernames'][username] = \
            {'name': name, 'password': Hasher([password]).generate()[0], 'email': email,
             'logged_in': False}
    def register_user(self, new_name: str, new_email: str, new_username: str,
                      new_password: str, pre_authorization: bool,
                      callback: Optional[Callable]=None) -> tuple:
        """
        Registers a new user's name, username, password, and email.

        Parameters
        ----------
        new_name: str
            Name of the new user.
        new_email: str
            Email of the new user.
        new_username: str
            Username of the new user.
        new_password: str
            Password of the new user.
        pre-authorization: bool
            Pre-authorization requirement, 
            True: user must be pre-authorized to register, 
            False: any user can register.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

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
            raise RegisterError('Username already taken')
        if callback:
            callback({'new_name': new_name, 'new_email': new_email,
                      'new_username': new_username})
        if pre_authorization:
            if new_email in self.pre_authorized['emails']:
                self._register_credentials(new_username, new_name, new_password, new_email)
                self.pre_authorized['emails'].remove(new_email)
                return new_email, new_username, new_name
            raise RegisterError('User not pre-authorized to register')
        self._register_credentials(new_username, new_name, new_password, new_email)
        return new_email, new_username, new_name
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
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of resetting the password, 
            True: password reset successfully.
        """
        if not self.check_credentials(username, password):
            raise CredentialsError('password')
        self._update_password(username, new_password)
        self._record_failed_login_attempts(username, reset=True)
        if callback:
            callback({})
        return True
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
        random_password = Helpers.generate_random_pw()
        self.credentials['usernames'][username]['password'] = \
            Hasher([random_password]).generate()[0]
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
        self.credentials['usernames'][username]['password'] = Hasher([password]).generate()[0]
    def update_user_details(self, new_value: str, username: str, field: str,
                            callback: Optional[Callable]=None) -> bool:
        """
        Validates the user's updated name or email and subsequently modifies it in the
        credentials dictionary.

        Parameters
        ----------
        new_value: str
            New value for the name or email.
        username: str
            Username of the user.
        field: str
            Field to update i.e. name or email.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of updating the user's detail, 
            True: details updated successfully.
        """
        if field == 'email':
            if self._credentials_contains_value(new_value):
                raise UpdateError('Email already taken')
        if new_value != self.credentials['usernames'][username][field]:
            self._update_entry(username, field, new_value)
            if field == 'name':
                st.session_state['name'] = new_value
            if callback:
                callback({'field': field, 'new_value': new_value})
            return True
        raise UpdateError('New and current values are the same')
