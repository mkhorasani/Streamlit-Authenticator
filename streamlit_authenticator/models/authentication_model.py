"""
Script description: This module executes the logic for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- typing: Module implementing standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

from typing import Callable, Dict, List, Optional
import streamlit as st

import params
from utilities import (Hasher,
                         Helpers,
                         CredentialsError,
                         LoginError,
                         RegisterError,
                         UpdateError)

class AuthenticationModel:
    """
    This class executes the logic for the login, logout, register user, reset password, 
    forgot password, forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, auto_hash: bool=True):
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
        """
        self.credentials = credentials
        if self._get_credentials():
            self.credentials['usernames'] = {
                key.lower(): value
                for key, value in self._get_credentials().items()
                }
            if auto_hash:
                if len(self._get_credentials()) > params.AUTO_HASH_MAX_USERS:
                    print(f"""Auto hashing in progress. To avoid runtime delays, please manually
                          pre-hash all plain text passwords in the credentials using the
                          Hasher.hash_passwords function, and set auto_hash=False for the
                          Authenticate class. For more information please refer to
                          {params.AUTO_HASH_MAX_USERS_LINK}.""")
                for username, _ in self._get_credentials().items():
                    if not Hasher.is_hash(self._get_credentials()[username]['password']):
                        self._get_credentials()[username]['password'] = \
                        Hasher._hash(self._get_credentials()[username]['password'])
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
        if username not in self._get_credentials():
            return False
        if isinstance(max_login_attempts, int) and \
            'failed_login_attempts' in self._get_credentials()[username] and \
            self._get_credentials()[username]['failed_login_attempts'] >= max_login_attempts:
            raise LoginError('Maximum number of login attempts exceeded')
        try:
            if Hasher.check_pw(password, self._get_credentials()[username]['password']):
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
        for username, _ in self._get_credentials().items():
            if 'logged_in' in self._get_credentials()[username] and \
                self._get_credentials()[username]['logged_in']:
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
        return any(value in d.values() for d in self._get_credentials().values())
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
        if username in self._get_credentials():
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
            Callback function that will be invoked on form submission.

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
        for username, values in self._get_credentials().items():
            if values[key] == value:
                return username
        return False
    def _get_user_variables(self, username: str) -> tuple:
        """
        Gets the user's email, name, and roles based on a provided username.

        Parameters
        ----------
        username: str
            Username of the user.

        Returns
        -------
        str
            Email associated with the given username.
        str
            Name associated with the given username.
        str
            Roles associated with the given username.
        """
        if 'first_name' in self._get_credentials()[username] and \
            'last_name' in self._get_credentials()[username]:
            first_name = self._get_credentials()[username]['first_name']
            last_name = self._get_credentials()[username]['last_name']
            name = f'{first_name} {last_name}'
        else:
            name = self._get_credentials()[username]['name']
        if 'roles' in self._get_credentials()[username]:
            roles = self._get_credentials()[username]['roles']
        else:
            roles = None
        return self._get_credentials()[username]['email'], name, roles 
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
            if self.check_credentials(username, password, max_concurrent_users, max_login_attempts):
                st.session_state['email'], st.session_state['name'], st.session_state['roles'] = \
                    self._get_user_variables(username)
                st.session_state['authentication_status'] = True
                st.session_state['username'] = username
                self._record_failed_login_attempts(username, reset=True)
                self._get_credentials()[username]['logged_in'] = True
                if 'password_hint' in st.session_state:
                    del st.session_state['password_hint']
                if callback:
                    callback({'username': username})
                return True
            st.session_state['authentication_status'] = False
            if 'password_hint' in self._get_credentials()[username]:
                st.session_state['password_hint'] = \
                    self._get_credentials()[username]['password_hint']
            return False
        if token:
            if not token['username'] in self._get_credentials():
                raise LoginError('User not authorized')
            st.session_state['email'], st.session_state['name'], st.session_state['roles'] = \
                self._get_user_variables(token['username'])
            st.session_state['authentication_status'] = True
            st.session_state['username'] = token['username']
            self._get_credentials()[token['username']]['logged_in'] = True
        return None
    def logout(self, callback: Optional[Callable]=None):
        """
        Clears the cookie and session state variables associated with the logged in user.

        Parameters
        ----------
        callback: callable, optional
            Callback function that will be invoked on button press.
        """
        self._get_credentials()[st.session_state['username']]['logged_in'] = False
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None
        st.session_state['email'] = None
        st.session_state['roles'] = None
        if callback:
            callback({})
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
        if 'failed_login_attempts' not in self._get_credentials()[username]:
            self._get_credentials()[username]['failed_login_attempts'] = 0
        if reset:
            self._get_credentials()[username]['failed_login_attempts'] = 0
        else:
            self._get_credentials()[username]['failed_login_attempts'] += 1
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
        self._get_credentials()[username] = {'email': email, 'logged_in': False,
                                             'first_name': first_name, 'last_name': last_name,
                                              'password': Hasher.hash(password),
                                              'password_hint': password_hint, 'roles': roles}
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
        if new_username in self._get_credentials():
            raise RegisterError('Username already taken')
        if pre_authorized and new_email in pre_authorized['emails']:
            self._register_credentials(new_username, new_first_name, new_last_name, new_password,
                                       new_email, password_hint, roles)
            pre_authorized['emails'].remove(new_email)
            return new_email, new_username, f'{new_first_name} {new_last_name}'
        if pre_authorized and new_email not in pre_authorized['emails']:
            raise RegisterError('User not pre-authorized to register')
        self._register_credentials(new_username, new_first_name, new_last_name, new_password,
                                   new_email, password_hint, roles)
        if callback:
            callback({'new_name': new_first_name, 'new_last_name': new_last_name,
                      'new_email': new_email, 'new_username': new_username})
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
        self._get_credentials()[username]['password'] = \
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
        self._get_credentials()[username][key] = value
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
        self._get_credentials()[username]['password'] = Hasher([password]).generate()[0]
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
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of updating the user's detail, 
            True: details updated successfully.
        """
        if field == 'email':
            if self._credentials_contains_value(new_value):
                raise UpdateError('Email already taken')
        if new_value != self._get_credentials()[username][field]:
            self._update_entry(username, field, new_value)
            if field == 'name':
                st.session_state['name'] = new_value
            if callback:
                callback({'field': field, 'new_value': new_value})
            return True
        raise UpdateError('New and current values are the same')
