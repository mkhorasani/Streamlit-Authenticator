"""
Script description: This module controls the requests for the login, logout, register user,
reset password, forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- typing: Module implementing standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

from typing import Callable, Dict, List, Optional
import streamlit as st

from ..models import AuthenticationModel
from ..utilities import (ForgotError,
                         Helpers,
                         LoginError,
                         RegisterError,
                         ResetError,
                         UpdateError,
                         Validator)

class AuthenticationController:
    """
    This class controls the requests for the login, logout, register user, reset password, 
    forgot password, forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, pre_authorized: Optional[List[str]]=None,
                 validator: Optional[Validator]=None, auto_hash: bool=True):
        """
        Create a new instance of "AuthenticationController".

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
        self.authentication_model = AuthenticationModel(credentials,
                                                        pre_authorized,
                                                        validator,
                                                        auto_hash)
        self.validator = Validator()
    def _check_captcha(self, captcha_name: str, exception: Exception, entered_captcha: str):
        """
        Checks the validity of the entered captcha.

        Parameters
        ----------
        captcha_name: str
            Name of the generated captcha stored in the session state.
        exception: Exception
            Type of exception to be raised.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.
        """
        if Helpers.check_captcha(captcha_name, entered_captcha):
            del st.session_state[captcha_name]
        else:
            raise exception('Captcha entered incorrectly')
    def forgot_password(self, username: str, callback: Optional[Callable]=None,
                        captcha: bool=False, entered_captcha: Optional[str]=None) -> tuple:
        """
        Controls the request to create a new random password for the user.

        Parameters
        ----------
        username: str
            Username associated with the forgotten password.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        captcha: bool
            Captcha requirement for the login widget, 
            True: captcha required,
            False: captcha removed.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        str
            New random password of the user.
        """
        username = username.lower().strip()
        if captcha:
            if not entered_captcha:
                raise ForgotError('Captcha not entered')
            entered_captcha = entered_captcha.strip()
            self._check_captcha('forgot_password_captcha', ForgotError, entered_captcha)
        if not self.validator.validate_length(username, 1):
            raise ForgotError('Username not provided')
        return self.authentication_model.forgot_password(username, callback)
    def forgot_username(self, email: str, callback: Optional[Callable]=None,
                        captcha: bool=False, entered_captcha: Optional[str]=None) -> tuple:
        """
        Controls the request to get the forgotten username of the user.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        captcha: bool
            Captcha requirement for the login widget, 
            True: captcha required,
            False: captcha removed.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        str
            Username of the user.
        str
            Email of the user.
        """
        email = email.strip()
        if captcha:
            if not entered_captcha:
                raise ForgotError('Captcha not entered')
            entered_captcha = entered_captcha.strip()
            self._check_captcha('forgot_username_captcha', ForgotError, entered_captcha)
        if not self.validator.validate_length(email, 1):
            raise ForgotError('Email not provided')
        return self.authentication_model.forgot_username(email, callback)
    def login(self, username: Optional[str]=None, password: Optional[str]=None,
              max_concurrent_users: Optional[int]=None, max_login_attempts: Optional[int]=None,
              token: Optional[Dict[str, str]]=None, callback: Optional[Callable]=None,
              captcha: bool=False, entered_captcha: Optional[str]=None):
        """
        Controls the request to login the user.

        Parameters
        ----------
        username: str, optional
            The username of the user being logged in.
        password: str, optional
            The entered password.
        max_concurrent_users: int, optional
            Maximum number of users allowed to login concurrently.
        max_login_attempts: int, optional
            Maximum number of failed login attempts a user can make.
        token: dict, optional
            The re-authentication cookie to get the username from.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        captcha: bool
            Captcha requirement for the login widget, 
            True: captcha required,
            False: captcha removed.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        bool
            Status of authentication, 
            None: no credentials entered, 
            True: correct credentials, 
            False: incorrect credentials.
        """
        if username and password:
            username = username.lower().strip()
            password = password.strip()
        if captcha:
            if not entered_captcha:
                raise LoginError('Captcha not entered')
            entered_captcha = entered_captcha.strip()
            self._check_captcha('login_captcha', LoginError, entered_captcha)
        return self.authentication_model.login(username, password, max_concurrent_users,
                                               max_login_attempts, token, callback)
    def logout(self):
        """
        Controls the request to logout the user.

        """
        self.authentication_model.logout()
    def register_user(self, new_name: str, new_email: str, new_username: str,
                      new_password: str, new_password_repeat: str, pre_authorization: bool,
                      domains: Optional[List[str]]=None, callback: Optional[Callable]=None,
                      captcha: bool=False, entered_captcha: Optional[str]=None) -> tuple:
        """
        Controls the request to register the new user's name, username, password, and email.

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
        new_password_repeat: str
            Repeated password of the new user.
        pre-authorization: bool
            Pre-authorization requirement, 
            True: user must be pre-authorized to register, 
            False: any user can register.
        domains: list, optional
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: the required list of domains, 
            None: any domain is allowed.
        callback: callable, optional
            Optional callback function that will be invoked on form submission.
        captcha: bool
            Captcha requirement for the login widget, 
            True: captcha required,
            False: captcha removed.
        entered_captcha: str, optional
            User entered captcha to validate against the generated captcha.

        Returns
        -------
        str
            Email of the new user.
        str
            Username of the new user.
        str
            Name of the new user.
        """
        new_name = new_name.strip()
        new_email = new_email.strip()
        new_username = new_username.lower().strip()
        new_password = new_password.strip()
        new_password_repeat = new_password_repeat.strip()
        if not self.validator.validate_name(new_name):
            raise RegisterError('Name is not valid')
        if not self.validator.validate_email(new_email):
            raise RegisterError('Email is not valid')
        if domains:
            if new_email.split('@')[1] not in ' '.join(domains):
                raise RegisterError('Email not allowed to register')
        if not self.validator.validate_username(new_username):
            raise RegisterError('Username is not valid')
        if not self.validator.validate_length(new_password, 1) \
            or not self.validator.validate_length(new_password_repeat, 1):
            raise RegisterError('Password/repeat password fields cannot be empty')
        if new_password != new_password_repeat:
            raise RegisterError('Passwords do not match')
        if not self.validator.validate_password(new_password):
            raise RegisterError('Password does not meet criteria')
        if pre_authorization:
            if not self.authentication_model.pre_authorized:
                raise RegisterError('Pre-authorization argument must not be None')
        if captcha:
            if not entered_captcha:
                raise RegisterError('Captcha not entered')
            entered_captcha = entered_captcha.strip()
            self._check_captcha('register_user_captcha', RegisterError, entered_captcha)
        return self.authentication_model.register_user(new_name, new_email, new_username,
                                                       new_password, pre_authorization,
                                                       callback)
    def reset_password(self, username: str, password: str, new_password: str,
                       new_password_repeat: str, callback: Optional[Callable]=None) -> bool:
        """
        Controls the request to reset the user's password.

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
        callback: callable, optional
            Optional callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of resetting the password, 
            True: password reset successfully.
        """
        if not self.validator.validate_length(new_password, 1):
            raise ResetError('No new password provided')
        if new_password != new_password_repeat:
            raise ResetError('Passwords do not match')
        if password == new_password:
            raise ResetError('New and current passwords are the same')
        if not self.validator.validate_password(new_password):
            raise ResetError('Password does not meet criteria')
        return self.authentication_model.reset_password(username, password, new_password,
                                                        callback)
    def update_user_details(self, new_value: str, username: str, field: str,
                            callback: Optional[Callable]=None) -> bool:
        """
        Controls the request to update the user's name or email.

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
        if field == 'name':
            if not self.validator.validate_name(new_value):
                raise UpdateError('Name is not valid')
        if field == 'email':
            if not self.validator.validate_email(new_value):
                raise UpdateError('Email is not valid')
        return self.authentication_model.update_user_details(new_value, username, field,
                                                             callback)
