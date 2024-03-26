"""
Script description: This module executes the logic for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- streamlit: Framework used to build pure Python web applications.
- typing: Module implementing standard typing notations for Python functions.
"""

from typing import Optional
import streamlit as st

from ...utilities.hasher import Hasher
from ...utilities.validator import Validator
from ...utilities.helpers import Helpers
from ...utilities.exceptions import (CredentialsError,
                                  ForgotError,
                                  LoginError,
                                  RegisterError,
                                  ResetError,
                                  UpdateError)

class AuthenticationHandler:
    """
    This class will execute the logic for the login, logout, register user, reset password, 
    forgot password, forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, pre_authorized: Optional[list]=None,
                 validator: Optional[Validator]=None):
        """
        Create a new instance of "AuthenticationHandler".

        Parameters
        ----------
        credentials: dict
            Dictionary of usernames, names, passwords, emails, and other user data.
        pre-authorized: list
            List of emails of unregistered users who are authorized to register.        
        validator: Validator
            Validator object that checks the validity of the username, name, and email fields.
        """
        self.credentials                =   credentials
        self.pre_authorized             =   pre_authorized
        self.credentials['usernames']   =   {
                                            key.lower(): value
                                            for key, value in credentials['usernames'].items()
                                            }
        self.validator                  =   validator if validator is not None else Validator()
        self.random_password            =   None
        for username, _ in self.credentials['usernames'].items():
            if 'logged_in' not in self.credentials['usernames'][username]:
                self.credentials['usernames'][username]['logged_in'] = False
            if 'failed_login_attempts' not in self.credentials['usernames'][username]:
                self.credentials['usernames'][username]['failed_login_attempts'] = 0
            if not Hasher._is_hash(self.credentials['usernames'][username]['password']):
                self.credentials['usernames'][username]['password'] = \
                    Hasher._hash(self.credentials['usernames'][username]['password'])
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
        max_concurrent_users: int
            Maximum number of users allowed to login concurrently.
        max_login_attempts: int
            Maximum number of failed login attempts a user can make.

        Returns
        -------
        bool
            Validity of the entered credentials.
        """
        if isinstance(max_concurrent_users, int):
            if self._count_concurrent_users() > max_concurrent_users - 1:
                raise LoginError('Maximum number of concurrent users exceeded')
        if username in self.credentials['usernames']:
            if isinstance(max_login_attempts, int):
                if self.credentials['usernames'][username]['failed_login_attempts'] >= \
                    max_login_attempts:
                    raise LoginError('Maximum number of login attempts exceeded')
            try:
                if Hasher.check_pw(password, self.credentials['usernames'][username]['password']):
                    return True
                st.session_state['authentication_status'] = False
                self._record_failed_login_attempts(username)
                return False
            except TypeError as e:
                print(e)
            except ValueError as e:
                print(e)
        else:
            st.session_state['authentication_status'] = False
            return False
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
            if self.credentials['usernames'][username]['logged_in']:
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
            Presence/absence of the value, True: value present, False value absent.
        """
        return any(value in d.values() for d in self.credentials['usernames'].values())
    def execute_login(self, username: Optional[str]=None, token: Optional[dict]=None):
        """
        Executes login by setting authentication status to true and adding the user's
        username and name to the session state.

        Parameters
        ----------
        username: str
            The username of the user being logged in.
        token: dict
            The re-authentication cookie to retrieve the username from.
        """
        if username:
            st.session_state['username'] = username
            st.session_state['name'] = self.credentials['usernames'][username]['name']
            st.session_state['authentication_status'] = True
            self._record_failed_login_attempts(username, reset=True)
            self.credentials['usernames'][username]['logged_in'] = True
        elif token:
            st.session_state['username'] = token['username']
            st.session_state['name'] = self.credentials['usernames'][token['username']]['name']
            st.session_state['authentication_status'] = True
            self.credentials['usernames'][token['username']]['logged_in'] = True
    def execute_logout(self):
        """
        Clears cookie and session state variables associated with the logged in user.
        """
        self.credentials['usernames'][st.session_state['username']]['logged_in'] = False
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None
    def forgot_password(self, username: str) -> tuple:
        """
        Creates a new random password for the user.

        Parameters
        ----------
        username: str
            Username associated with the forgotten password.

        Returns
        -------
        tuple
            Username of the user; email of the user; new random password of the user.
        """
        if not self.validator.validate_length(username, 1):
            raise ForgotError('Username not provided')
        if username in self.credentials['usernames']:
            return (username, self.credentials['usernames'][username]['email'],
                    self._set_random_password(username))
        else:
            return False, None, None
    def forgot_username(self, email: str) -> tuple:
        """
        Retrieves the forgotten username of a user.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.

        Returns
        -------
        tuple
            Username of the user; email of the user.
        """
        if not self.validator.validate_length(email, 1):
            raise ForgotError('Email not provided')
        return self._get_username('email', email), email
    def _get_username(self, key: str, value: str) -> str:
        """
        Retrieves the username based on a provided entry.

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
    def _record_failed_login_attempts(self, username: str, reset: bool=False):
        """
        Records the number of failed login attempts for a given username.
        
        Parameters
        ----------
        reset: bool            
            Reset failed login attempts option, True: number of failed login attempts
            for the user will be reset to 0, 
            False: number of failed login attempts for the user will be incremented.
        """
        if reset:
            self.credentials['usernames'][username]['failed_login_attempts'] = 0
        else:
            self.credentials['usernames'][username]['failed_login_attempts'] += 1
    def _register_credentials(self, username: str, name: str, password: str, email: str,
                              pre_authorization: bool, domains: list):
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
        pre-authorization: bool
            Pre-authorization requirement, True: user must be pre-authorized to register, 
            False: any user can register.
        domains: list
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: the required list of domains, None: any domain is allowed.
        """
        if not self.validator.validate_email(email):
            raise RegisterError('Email is not valid')
        if self._credentials_contains_value(email):
            raise RegisterError('Email already taken')
        if domains:
            if email.split('@')[1] not in ' '.join(domains):
                raise RegisterError('Email not allowed to register')
        if not self.validator.validate_username(username):
            raise RegisterError('Username is not valid')
        if username in self.credentials['usernames']:
            raise RegisterError('Username already taken')
        if not self.validator.validate_name(name):
            raise RegisterError('Name is not valid')
        self.credentials['usernames'][username] = \
            {'name': name, 'password': Hasher([password]).generate()[0], 'email': email,
             'logged_in': False}
        if pre_authorization:
            self.pre_authorized['emails'].remove(email)
    def register_user(self, new_password: str, new_password_repeat: str, pre_authorization: bool,
                      new_username: str, new_name: str, new_email: str,
                      domains: Optional[list]=None) -> tuple:
        """
        Validates a new user's username, password, and email. Subsequently adds the validated user 
        details to the credentials dictionary.

        Parameters
        ----------
        new_password: str
            Password of the new user.
        new_password_repeat: str
            Repeated password of the new user.
        pre-authorization: bool
            Pre-authorization requirement, True: user must be pre-authorized to register, 
            False: any user can register.
        new_username: str
            Username of the new user.
        new_name: str
            Name of the new user.
        new_email: str
            Email of the new user.
        domains: list
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: the required list of domains, None: any domain is allowed.

        Returns
        -------
        tuple
            Email of the new user; username of the new user; name of the new user.
        """
        if not self.validator.validate_length(new_password, 1) \
            or not self.validator.validate_length(new_password_repeat, 1):
            raise RegisterError('Password/repeat password fields cannot be empty')
        if new_password != new_password_repeat:
            raise RegisterError('Passwords do not match')
        if pre_authorization:
            if new_email in self.pre_authorized['emails']:
                self._register_credentials(new_username, new_name, new_password, new_email,
                                            pre_authorization, domains)
                return new_email, new_username, new_name
            else:
                raise RegisterError('User not pre-authorized to register')
        else:
            self._register_credentials(new_username, new_name, new_password, new_email,
                                        pre_authorization, domains)
            return new_email, new_username, new_name

    def reset_password(self, username: str, password: str, new_password: str,
                       new_password_repeat: str) -> bool:
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
        new_password_repeat: str
            Repeated new password of the user.

        Returns
        -------
        bool
            State of resetting the password, True: password reset successfully.
        """
        if self.check_credentials(username, password):
            if not self.validator.validate_length(new_password, 1):
                raise ResetError('No new password provided')
            if new_password != new_password_repeat:
                raise ResetError('Passwords do not match')
            if password != new_password:
                self._update_password(username, new_password)
                return True
            else:
                raise ResetError('New and current passwords are the same')
        else:
            raise CredentialsError('password')
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
        self.random_password = Helpers.generate_random_pw()
        self.credentials['usernames'][username]['password'] = \
            Hasher([self.random_password]).generate()[0]
        return self.random_password
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
    def update_user_details(self, new_value: str, username: str, field: str) -> bool:
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

        Returns
        -------
        bool
            State of updating the user's detail, True: details updated successfully.
        """
        if field == 'name':
            if not self.validator.validate_name(new_value):
                raise UpdateError('Name is not valid')
        if field == 'email':
            if not self.validator.validate_email(new_value):
                raise UpdateError('Email is not valid')
            if self._credentials_contains_value(new_value):
                raise UpdateError('Email already taken')
        if new_value != self.credentials['usernames'][username][field]:
            self._update_entry(username, field, new_value)
            if field == 'name':
                st.session_state['name'] = new_value
            return True
        else:
            raise UpdateError('New and current values are the same')
        