"""
Script description: This module controls authentication-related requests, including login, 
logout, user registration, password reset, and user modifications.

Libraries imported:
-------------------
- json: Handles JSON documents.
- typing: Provides standard type hints for Python functions.
- streamlit: Framework for building web applications.
"""

import json
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
import streamlit as st

from ..models import AuthenticationModel
from ..utilities import (Encryptor,
                         ForgotError,
                         Helpers,
                         LoginError,
                         RegisterError,
                         ResetError,
                         UpdateError,
                         Validator)


class AuthenticationController:
    """
    Controls authentication-related requests, including login, logout, user registration,
    password reset, and user modifications.
    """
    def __init__(
            self,
            credentials: Optional[Dict[str, Any]] = None,
            validator: Optional[Validator] = None,
            auto_hash: bool = True,
            path: Optional[str] = None,
            api_key: Optional[str] = None,
            secret_key: str = 'some_key',
            server_url: Optional[str] = None) -> None:
        """
        Initializes the AuthenticationController instance.

        Parameters
        ----------
        credentials : dict, optional
            Dictionary containing usernames, names, passwords, emails, and other user data.       
        validator : Validator, optional
            Validator object for checking the validity of usernames, names, and email fields.
        auto_hash : bool, default=True
            If True, plain-text passwords will be automatically hashed.
        path : str, optional
            File path of the configuration file.
        api_key : str, optional
            API key for connecting to the cloud server for password resets and two-factor
            authentication.
        secret_key : str, default='some_key'
            Secret key used for encryption and decryption.
        server_url : str, optional
            Cloud server URL used for cloud-related transactions.
        """
        self.secret_key = secret_key
        self.validator = validator if validator is not None else Validator()
        self.authentication_model = AuthenticationModel(credentials, auto_hash, path, api_key,
                                                        self.secret_key, server_url, self.validator)
        self.encryptor = Encryptor(self.secret_key)
    def _check_captcha(self, captcha_name: str, exception: Type[Exception], entered_captcha: str
                       ) -> None:
        """
        Validates the entered captcha against the generated captcha stored in session state.

        Parameters
        ----------
        captcha_name : str
            The session state key where the generated captcha is stored.
        exception : Exception
            The exception to raise if captcha validation fails.
        entered_captcha : str
            The captcha value entered by the user.
        """
        if Helpers.check_captcha(captcha_name, entered_captcha, self.secret_key):
            del st.session_state[captcha_name]
        else:
            raise exception('Captcha entered incorrectly')
    def check_two_factor_auth_code(self, code: str, content: Optional[Dict[str, Any]] = None,
                                   widget: Optional[str]=None) -> bool:
        """
        Verifies the two-factor authentication code.

        Parameters
        ----------
        code : str
            Entered two-factor authentication code.
        content : dict, optional
            Content to save in session state upon successful verification.
        widget : str, optional
            Widget name used in session state.

        Returns
        -------
        bool
            True if the authentication code is correct, False otherwise.
        """
        if code == self.encryptor.decrypt(st.session_state[f'2FA_code_{widget}']):
            st.session_state[f'2FA_check_{widget}'] = True
            st.session_state[f'2FA_content_{widget}'] = \
                self.encryptor.encrypt(json.dumps(content)) if content else None
            del st.session_state[f'2FA_code_{widget}']
            return True
        st.session_state[f'2FA_check_{widget}'] = False
        return False
    def forgot_password(self, username: str, callback: Optional[Callable] = None,
                        captcha: bool = False, entered_captcha: Optional[str] = None
                        ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Handles user password reset requests.

        Parameters
        ----------
        username : str
            Username associated with the forgotten password.
        callback : Callable, optional
            Function to be executed upon successful password reset.
        captcha : bool, default=False
            If True, a captcha check is required.
        entered_captcha : str, optional
            User-entered captcha value for validation.

        Returns
        -------
        Tuple[Optional[str], Optional[str], Optional[str]]
            Tuple containing (username, email, new password), or (None, None, None) if unsuccessful.
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
    def forgot_username(self, email: str, callback: Optional[Callable] = None,
                        captcha: bool = False, entered_captcha: Optional[str] = None
                        ) -> Tuple[Optional[str], Optional[str]]:
        """
        Handles forgotten username requests.

        Parameters
        ----------
        email: str
            Email associated with the forgotten username.
        callback : Callable, optional
            Function to be executed upon successful password reset.
        captcha : bool, default=False
            If True, a captcha check is required.
        entered_captcha : str, optional
            User-entered captcha value for validation.

        Returns
        -------
        Tuple[Optional[str], Optional[str]]
            Tuple containing (username, email), or (None, None) if unsuccessful.
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
    def generate_two_factor_auth_code(self, email: str, widget: Optional[str] = None) -> str:
        """
        Handles requests to generate a two factor authentication code.
        
        Parameters
        ----------
        email : str
            Email to send two factor authentication code to.
        widget : str, optional
            Widget name to append to session state variable name.
        """
        self.authentication_model.generate_two_factor_auth_code(email, widget)
    def guest_login(self, cookie_controller: Any, provider: str = 'google',
                    oauth2: Optional[Dict[str, Any]] = None,
                    max_concurrent_users: Optional[int] = None,
                    single_session: bool = False, roles: Optional[List[str]] = None,
                    callback: Optional[Callable] = None) -> Optional[str]:
        """
        Handles guest login via OAuth2 providers.

        Parameters
        ----------
        cookie_controller : CookieController
            Cookie controller object used to set the re-authentication cookie.
        provider : str
            OAuth2 provider selection i.e. google or microsoft.
        oauth2 : dict, optional
            Configuration parameters to implement an OAuth2 authentication.
        max_concurrent_users : int, optional
            Maximum number of users allowed to login concurrently.
        single_session : bool, default=False
            If True, prevents multiple logins from the same user.
        roles : list, optional
            User roles for guest users.
        callback : callable, optional
            Callback function that will be invoked on button press.

        Returns
        -------
        Optional[str]
            Redirect URL if authentication requires further steps, otherwise None.
        """
        if roles and not isinstance(roles, list):
            raise LoginError('Roles must be provided as a list')
        return self.authentication_model.guest_login(cookie_controller=cookie_controller,
                                                     provider=provider, oauth2=oauth2, roles=roles,
                                                     max_concurrent_users=max_concurrent_users,
                                                     single_session=single_session,
                                                     callback=callback)
    def login(self, username: Optional[str] = None, password: Optional[str] = None,
              max_concurrent_users: Optional[int] = None, max_login_attempts: Optional[int] = None,
              token: Optional[Dict[str, str]] = None, single_session: bool = False,
              callback: Optional[Callable] = None,
              captcha: bool = False, entered_captcha: Optional[str] = None) -> Optional[bool]:
        """
        Handles user login requests.

        Parameters
        ----------
        username : str, optional
            The username of the user being logged in.
        password : str, optional
            The entered password.
        max_concurrent_users : int, optional
            Maximum number of users allowed to login concurrently.
        max_login_attempts : int, optional
            Maximum number of failed login attempts a user can make.
        token : dict, optional
            Re-authentication token for retrieving the username.
        single_session : bool, default=False
            If True, prevents multiple logins from the same user.
        callback : Callable, optional
            Function to be executed upon successful login.
        captcha : bool, default=False
            If True, a captcha check is required.
        entered_captcha : str, optional
            User-entered captcha value for validation.

        Returns
        -------
        bool or None
            True if login is successful, False if it fails, or None if no credentials are provided.
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
                                               max_login_attempts, token, single_session,
                                               callback)
    def logout(self, callback: Optional[Callable]=None) -> None:
        """
        Logs out the user by clearing session state variables.

        Parameters
        ----------
        callback: Callable, optional
            Function to be executed upon logout.
        """
        self.authentication_model.logout(callback)
    def register_user(self, new_first_name: str, new_last_name: str, new_email: str,
                      new_username: str, new_password: str, new_password_repeat: str,
                      password_hint: str, pre_authorized: Optional[List[str]] = None,
                      domains: Optional[List[str]] = None, roles: Optional[List[str]] = None,
                      callback: Optional[Callable] = None, captcha: bool = False,
                      entered_captcha: Optional[str] = None) -> Tuple[str, str, str]:
        """
        Handles user registration requests.

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
        new_password_repeat: str
            Repeated password of the new user.
        password_hint: str
            A hint for remembering the password.
        pre-authorized: list, optional
            List of emails of unregistered users who are authorized to register. 
        domains: list, optional
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: the required list of domains, 
            None: any domain is allowed.
        roles: list, optional
            User roles for registered users.
        callback : Callable, optional
            Function to be executed upon successful login.
        captcha : bool, default=False
            If True, a captcha check is required.
        entered_captcha : str, optional
            User-entered captcha value for validation.

        Returns
        -------
        Tuple[str, str, str]
            Tuple containing (email, username, full name).
        """
        new_first_name = new_first_name.strip()
        new_last_name = new_last_name.strip()
        new_email = new_email.strip()
        new_username = new_username.lower().strip()
        new_password = new_password.strip()
        new_password_repeat = new_password_repeat.strip()
        password_hint = password_hint.strip() if password_hint else None
        if not self.validator.validate_name(new_first_name):
            raise RegisterError('First name is not valid')
        if not self.validator.validate_name(new_last_name):
            raise RegisterError('Last name is not valid')
        if not self.validator.validate_email(new_email):
            raise RegisterError('Email is not valid')
        if domains and new_email.split('@')[-1] not in domains:
            raise RegisterError('Email domain is not allowed to register')
        if not self.validator.validate_username(new_username):
            raise RegisterError('Username is not valid')
        if not self.validator.validate_length(new_password, 1) \
            or not self.validator.validate_length(new_password_repeat, 1):
            raise RegisterError('Password/repeat password fields cannot be empty')
        if new_password != new_password_repeat:
            raise RegisterError('Passwords do not match')
        if password_hint and not self.validator.validate_length(password_hint, 1):
            raise RegisterError('Password hint cannot be empty')
        if not self.validator.validate_password(new_password):
            raise RegisterError(self.validator.diagnose_password(new_password))
        if roles and not isinstance(roles, list):
            raise LoginError('Roles must be provided as a list')
        if captcha:
            if not entered_captcha:
                raise RegisterError('Captcha not entered')
            entered_captcha = entered_captcha.strip()
            self._check_captcha('register_user_captcha', RegisterError, entered_captcha)
        return self.authentication_model.register_user(new_first_name, new_last_name, new_email,
                                                       new_username, new_password, password_hint,
                                                       pre_authorized, roles, callback)
    def reset_password(self, username: str, password: str, new_password: str,
                       new_password_repeat: str, callback: Optional[Callable] = None) -> bool:
        """
        Handles user password reset requests.

        Parameters
        ----------
        username : str
            Username of the user.
        password : str
            Current password of the user.
        new_password : str
            New password of the user.
        new_password_repeat : str
            Repeated new password of the user.
        callback : Callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            State of resetting the password, 
            True: password reset successfully.
        """
        username = username.lower().strip()
        if not self.validator.validate_length(new_password, 1):
            raise ResetError('No new password provided')
        if new_password != new_password_repeat:
            raise ResetError('Passwords do not match')
        if password == new_password:
            raise ResetError('New and current passwords are the same')
        if not self.validator.validate_password(new_password):
            raise ResetError(self.validator.diagnose_password(new_password))
        return self.authentication_model.reset_password(username, password, new_password,
                                                        callback)
    def send_password(self, result: Tuple[Optional[str], Optional[str], Optional[str]]) -> bool:
        """
        Sends a newly generated password to the user via email.

        Parameters
        ----------
        result : tuple
            Tuple containing (username, email, new password).

        Returns
        -------
        bool
            True if password email was sent successfully, False otherwise.
        """
        return self.authentication_model.send_email('PWD', result[1], result[2])
    def send_username(self, result: Tuple[Optional[str], Optional[str]]) -> bool:
        """
        Sends the retrieved username to the user via email.

        Parameters
        ----------
        result : tuple
            Tuple containing (username, email).

        Returns
        -------
        bool
            True if username email was sent successfully, False otherwise.
        """
        return self.authentication_model.send_email('USERNAME', result[1], result[0])
    def update_user_details(self, username: str, field: str, new_value: str,
                            callback: Optional[Callable] = None) -> bool:
        """
        Updates user details such as name or email.

        Parameters
        ----------
        username : str
            Username of the user.
        field : str
            Field to update (e.g., 'email', 'first_name', 'last_name').
        new_value : str
            New value for the specified field.
        callback : Callable, optional
            Function to be executed upon successful update.

        Returns
        -------
        bool
            True if update is successful, False otherwise.
        """
        username = username.lower().strip()
        if field == 'first_name' and not self.validator.validate_name(new_value):
            raise UpdateError('First name is not valid')
        if field == 'last_name' and not self.validator.validate_name(new_value):
            raise UpdateError('Last name is not valid')
        if field == 'email' and not self.validator.validate_email(new_value):
            raise UpdateError('Email is not valid')
        return self.authentication_model.update_user_details(username, field, new_value,
                                                             callback)
