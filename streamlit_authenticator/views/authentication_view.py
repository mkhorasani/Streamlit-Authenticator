"""
Script description: This module renders the login, logout, register user, reset password,
forgot password, forgot username, and modify user details widgets.

Libraries imported:
-------------------
- json: Handles JSON documents.
- time: Implements sleep function.
- typing: Implements standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

import json
import time
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

import streamlit as st

from ..controllers import AuthenticationController, CookieController
from .. import params
from ..utilities import (DeprecationError,
                         Encryptor,
                         Helpers,
                         LogoutError,
                         ResetError,
                         UpdateError,
                         Validator)


class Authenticate:
    """
    This class renders login, logout, register user, reset password, forgot password,
    forgot username, and modify user details widgets.
    """
    def __init__(
            self,
            credentials: Union[Dict[str, Any], str],
            cookie_name: str = 'some_cookie_name',
            cookie_key: str = 'some_key',
            cookie_expiry_days: float = 30.0,
            validator: Optional[Validator] = None,
            auto_hash: bool = True,
            api_key: Optional[str] = None,
            **kwargs: Optional[Dict[str, Any]]
            ) -> None:
        """
        Initializes an instance of Authenticate.

        Parameters
        ----------
        credentials : dict or str
            Dictionary of user credentials or path to a configuration file.
        cookie_name : str, default='some_cookie_name'
            Name of the re-authentication cookie stored in the client's browser.
        cookie_key : str, default='some_key'
            Secret key used for encrypting the re-authentication cookie.
        cookie_expiry_days : float, default=30.0
            Expiry time for the re-authentication cookie in days.
        validator : Validator, optional
            Validator object for checking username, name, and email validity.
        auto_hash : bool, default=True
            If True, passwords will be automatically hashed.
        api_key : str, optional
            API key for sending password reset and authentication emails.
        **kwargs : dict, optional
            Additional keyword arguments.
        """
        self.api_key = api_key
        self.attrs = kwargs
        self.secret_key = cookie_key
        if isinstance(validator, dict):
            raise DeprecationError(f"""Please note that the 'pre_authorized' parameter has been
                                   removed from the Authenticate class and added directly to the
                                   'register_user' function. For further information please refer to
                                   {params.REGISTER_USER_LINK}.""")
        self.path = credentials if isinstance(credentials, str) else None
        self.cookie_controller          =   CookieController(cookie_name,
                                                             cookie_key,
                                                             cookie_expiry_days,
                                                             self.path)
        self.authentication_controller  =   AuthenticationController(credentials,
                                                                     validator,
                                                                     auto_hash,
                                                                     self.path,
                                                                     self.api_key,
                                                                     self.secret_key,
                                                                     self.attrs.get('server_url'))
        self.encryptor = Encryptor(self.secret_key)
    def forgot_password(self, location: Literal['main', 'sidebar'] = 'main',
                        fields: Optional[Dict[str, str]] = None, captcha: bool = False,
                        send_email: bool = False, two_factor_auth: bool = False,
                        clear_on_submit: bool = False, key: str = 'Forgot password',
                        callback: Optional[Callable] = None
                        ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Renders a forgot password widget.

        Parameters
        ----------
        location : {'main', 'sidebar'}, default='main'
            Location of the forgot password widget.
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=False
            If True, requires captcha validation.
        send_email : bool, default=False
            If True, sends the new password to the user's email.
        two_factor_auth : bool, default=False
            If True, enables two-factor authentication.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Forgot password'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to be executed after form submission.

        Returns
        -------
        tuple[str, str, str] or (None, None, None)
            - Username associated with the forgotten password.
            - Email associated with the forgotten password.
            - New plain-text password to be securely transferred to the user.
        """
        if fields is None:
            fields = {'Form name':'Forgot password', 'Username':'Username', 'Captcha':'Captcha',
                      'Submit':'Submit', 'Dialog name':'Verification code', 'Code':'Code',
                      'Error':'Code is incorrect'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        forgot_password_form.subheader(fields.get('Form name', 'Forgot password'))
        username = forgot_password_form.text_input(fields.get('Username', 'Username'),
                                                   autocomplete='off')
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_password_form.text_input(fields.get('Captcha', 'Captcha'),
                                                              autocomplete='off')
            forgot_password_form.image(Helpers.generate_captcha('forgot_password_captcha',
                                                                self.secret_key))
        result = (None, None, None)
        if forgot_password_form.form_submit_button(fields.get('Submit', 'Submit')):
            result = self.authentication_controller.forgot_password(username, callback, captcha,
                                                                    entered_captcha)
            if not two_factor_auth:
                if send_email:
                    self.authentication_controller.send_password(result)
                return result
            self.__two_factor_auth(result[1], result, widget='forgot_password', fields=fields)
        if two_factor_auth and st.session_state.get('2FA_check_forgot_password'):
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_password'])
            result = json.loads(decrypted)
            if send_email:
                self.authentication_controller.send_password(result)
            del st.session_state['2FA_check_forgot_password']
            return result
        return None, None, None
    def forgot_username(self, location: Literal['main', 'sidebar'] = 'main',
                        fields: Optional[Dict[str, str]] = None, captcha: bool = False,
                        send_email: bool = False, two_factor_auth: bool = False,
                        clear_on_submit: bool = False, key: str = 'Forgot username',
                        callback: Optional[Callable]=None) -> Tuple[Optional[str], Optional[str]]:
        """
        Renders a forgot username widget.

        Parameters
        ----------
        location : {'main', 'sidebar'}, default='main'
            Location of the forgot username widget.
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=False
            If True, requires captcha validation.
        send_email : bool, default=False
            If True, sends the retrieved username to the user's email.
        two_factor_auth : bool, default=False
            If True, enables two-factor authentication.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Forgot username'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to be executed after form submission.

        Returns
        -------
        tuple[str, str] or (None, str)
            - Username associated with the forgotten username.
            - Email associated with the forgotten username.
        """
        if fields is None:
            fields = {'Form name':'Forgot username', 'Email':'Email', 'Captcha':'Captcha',
                      'Submit':'Submit', 'Dialog name':'Verification code', 'Code':'Code',
                      'Error':'Code is incorrect'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_username_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        forgot_username_form.subheader('Forgot username' if 'Form name' not in fields
                                       else fields['Form name'])
        email = forgot_username_form.text_input('Email' if 'Email' not in fields
                                                else fields['Email'], autocomplete='off')
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_username_form.text_input('Captcha' if 'Captcha' not in fields
                                                              else fields['Captcha'],
                                                              autocomplete='off')
            forgot_username_form.image(Helpers.generate_captcha('forgot_username_captcha',
                                                                self.secret_key))
        if forgot_username_form.form_submit_button('Submit' if 'Submit' not in fields
                                                   else fields['Submit']):
            result = self.authentication_controller.forgot_username(email, callback,
                                                                    captcha, entered_captcha)
            if not two_factor_auth:
                if send_email:
                    self.authentication_controller.send_username(result)
                return result
            self.__two_factor_auth(email, result, widget='forgot_username', fields=fields)
        if two_factor_auth and st.session_state.get('2FA_check_forgot_username'):
            decrypted = self.encryptor.decrypt(st.session_state['2FA_content_forgot_username'])
            result = json.loads(decrypted)
            if send_email:
                self.authentication_controller.send_username(result)
            del st.session_state['2FA_check_forgot_username']
            return result
        return None, email
    def experimental_guest_login(self, button_name: str='Guest login',
                                 location: Literal['main', 'sidebar'] = 'main',
                                 provider: Literal['google', 'microsoft'] = 'google',
                                 oauth2: Optional[Dict[str, Any]] = None,
                                 max_concurrent_users: Optional[int]=None,
                                 single_session: bool=False, roles: Optional[List[str]]=None,
                                 use_container_width: bool=False,
                                 callback: Optional[Callable]=None) -> None:
        """
        Renders a guest login button.

        Parameters
        ----------
        button_name : str, default='Guest login'
            Display name for the guest login button.
        location : {'main', 'sidebar'}, default='main'
            Location where the guest login button is rendered.
        provider : {'google', 'microsoft'}, default='google'
            OAuth2 provider used for authentication.
        oauth2 : dict, optional
            Configuration parameters for OAuth2 authentication.
        max_concurrent_users : int, optional
            Maximum number of users allowed to log in concurrently.
        single_session : bool, default=False
            If True, prevents users from logging into multiple sessions simultaneously.
        roles : list of str, optional
            Roles assigned to guest users.
        use_container_width : bool, default=False
            If True, the button width matches the container.
        callback : Callable, optional
            Function to execute when the button is pressed.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if provider not in ['google', 'microsoft']:
            raise ValueError("Provider must be one of 'google' or 'microsoft'")
        if not st.session_state.get('authentication_status'):
            token = self.cookie_controller.get_cookie()
            if token:
                self.authentication_controller.login(token=token)
            time.sleep(self.attrs.get('login_sleep_time', params.PRE_LOGIN_SLEEP_TIME))
            if not st.session_state.get('authentication_status'):
                auth_endpoint = \
                    self.authentication_controller.guest_login(cookie_controller=\
                                                                self.cookie_controller,
                                                                provider=provider,
                                                                oauth2=oauth2,
                                                                max_concurrent_users=\
                                                                max_concurrent_users,
                                                                single_session=single_session,
                                                                roles=roles,
                                                                callback=callback)
                if location == 'main' and auth_endpoint:
                    st.link_button(button_name, url=auth_endpoint,
                                   use_container_width=use_container_width)
                if location == 'sidebar' and auth_endpoint:
                    st.sidebar.link_button(button_name, url=auth_endpoint,
                                           use_container_width=use_container_width)
    def login(self, location: Literal['main', 'sidebar', 'unrendered'] = 'main',
              max_concurrent_users: Optional[int] = None, max_login_attempts: Optional[int] = None,
              fields: Optional[Dict[str, str]] = None, captcha: bool = False,
              single_session: bool=False, clear_on_submit: bool = False, key: str = 'Login',
              callback: Optional[Callable] = None
              ) -> Optional[Tuple[Optional[str], Optional[bool], Optional[str]]]:
        """
        Renders a login widget.

        Parameters
        ----------
        location : {'main', 'sidebar', 'unrendered'}, default='main'
            Location where the login widget is rendered.
        max_concurrent_users : int, optional
            Maximum number of users allowed to log in concurrently.
        max_login_attempts : int, optional
            Maximum number of failed login attempts allowed.
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=False
            If True, requires captcha validation.
        single_session : bool, default=False
            If True, prevents users from logging into multiple sessions simultaneously.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Login'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.

        Returns
        -------
        tuple[str, bool, str] or None
            - If `location='unrendered'`, returns (user's name, authentication status, username).
            - Otherwise, returns None.
        """
        if fields is None:
            fields = {'Form name':'Login', 'Username':'Username', 'Password':'Password',
                      'Login':'Login', 'Captcha':'Captcha'}
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if not st.session_state.get('authentication_status'):
            token = self.cookie_controller.get_cookie()
            if token:
                self.authentication_controller.login(token=token)
            time.sleep(self.attrs.get('login_sleep_time', params.PRE_LOGIN_SLEEP_TIME))
            if not st.session_state.get('authentication_status'):
                if location == 'main':
                    login_form = st.form(key=key, clear_on_submit=clear_on_submit)
                elif location == 'sidebar':
                    login_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
                elif location == 'unrendered':
                    return (st.session_state['name'], st.session_state['authentication_status'],
                            st.session_state['username'])
                login_form.subheader('Login' if 'Form name' not in fields else fields['Form name'])
                username = login_form.text_input('Username' if 'Username' not in fields
                                                 else fields['Username'], autocomplete='off')
                if 'password_hint' in st.session_state:
                    password = login_form.text_input('Password' if 'Password' not in fields
                                                     else fields['Password'], type='password',
                                                     help=st.session_state['password_hint'],
                                                     autocomplete='off')
                else:
                    password = login_form.text_input('Password' if 'Password' not in fields
                                                     else fields['Password'], type='password',
                                                     autocomplete='off')
                entered_captcha = None
                if captcha:
                    entered_captcha = login_form.text_input('Captcha' if 'Captcha' not in fields
                                                            else fields['Captcha'],
                                                            autocomplete='off')
                    login_form.image(Helpers.generate_captcha('login_captcha', self.secret_key))
                if login_form.form_submit_button('Login' if 'Login' not in fields
                                                 else fields['Login']):
                    if self.authentication_controller.login(username, password,
                                                            max_concurrent_users,
                                                            max_login_attempts,
                                                            single_session=single_session,
                                                            callback=callback, captcha=captcha,
                                                            entered_captcha=entered_captcha):
                        self.cookie_controller.set_cookie()
                        if self.path and self.cookie_controller.get_cookie():
                            st.rerun()
    def logout(self, button_name: str = 'Logout',
               location: Literal['main', 'sidebar', 'unrendered'] = 'main',
               key: str = 'Logout', use_container_width: bool = False,
               callback: Optional[Callable] = None) -> None:
        """
        Renders a logout button.

        Parameters
        ----------
        button_name : str, default='Logout'
            Display name for the logout button.
        location : {'main', 'sidebar', 'unrendered'}, default='main'
            Location where the logout button is rendered.
        key : str, default='Logout'
            Unique key for the widget, useful in multi-page applications.
        use_container_width : bool, default=False
            If True, the button width matches the container.
        callback : Callable, optional
            Function to execute when the button is pressed.
        """
        if not st.session_state.get('authentication_status'):
            raise LogoutError('User must be logged in to use the logout button')
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if location == 'main':
            if st.button(button_name, key=key, use_container_width=use_container_width):
                self.authentication_controller.logout(callback)
                self.cookie_controller.delete_cookie()
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key=key, use_container_width=use_container_width):
                self.authentication_controller.logout(callback)
                self.cookie_controller.delete_cookie()
        elif location == 'unrendered':
            if st.session_state.get('authentication_status'):
                self.authentication_controller.logout()
                self.cookie_controller.delete_cookie()
    def register_user(self, location: Literal['main', 'sidebar'] = 'main',
                      pre_authorized: Optional[List[str]] = None,
                      domains: Optional[List[str]] = None, fields: Optional[Dict[str, str]] = None,
                      captcha: bool = True, roles: Optional[List[str]] = None,
                      merge_username_email: bool = False, password_hint: bool = True,
                      two_factor_auth: bool = False, clear_on_submit: bool = False,
                      key: str = 'Register user', callback: Optional[Callable] = None
                      ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Renders a register new user widget.

        Parameters
        ----------
        location : {'main', 'sidebar'}, default='main'
            Location where the registration widget is rendered.
        pre_authorized : list of str, optional
            List of emails of unregistered users who are authorized to register.
        domains : list of str, optional
            List of allowed email domains (e.g., ['gmail.com', 'yahoo.com']).
        fields : dict, optional
            Custom labels for form fields and buttons.
        captcha : bool, default=True
            If True, requires captcha validation.
        roles : list of str, optional
            User roles for registered users.
        merge_username_email : bool, default=False
            If True, uses the email as the username.
        password_hint : bool, default=True
            If True, includes a password hint field.
        two_factor_auth : bool, default=False
            If True, enables two-factor authentication.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Register user'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.

        Returns
        -------
        tuple[str, str, str] or (None, None, None)
            - Email associated with the new user.
            - Username associated with the new user.
            - Name associated with the new user.
        """
        if isinstance(pre_authorized, bool) or isinstance(pre_authorized, dict):
            raise DeprecationError(f"""Please note that the 'pre_authorized' parameter now
                                   requires a list of pre-authorized emails. For further
                                   information please refer to {params.REGISTER_USER_LINK}.""")
        if fields is None:
            fields = {'Form name':'Register user', 'First name':'First name',
                      'Last name':'Last name', 'Email':'Email', 'Username':'Username',
                      'Password':'Password', 'Repeat password':'Repeat password',
                      'Password hint':'Password hint', 'Captcha':'Captcha', 'Register':'Register',
                      'Dialog name':'Verification code', 'Code':'Code', 'Submit':'Submit',
                      'Error':'Code is incorrect'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            register_user_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            register_user_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        register_user_form.subheader('Register user' if 'Form name' not in fields
                                     else fields['Form name'])
        col1_1, col2_1 = register_user_form.columns(2)
        new_first_name = col1_1.text_input('First name' if 'First name' not in fields
                                         else fields['First name'], autocomplete='off')
        new_last_name = col2_1.text_input('Last name' if 'Last name' not in fields
                                        else fields['Last name'], autocomplete='off')
        if merge_username_email:
            new_email = register_user_form.text_input('Email' if 'Email' not in fields
                                        else fields['Email'], autocomplete='off')
            new_username = new_email
        else:
            new_email = col1_1.text_input('Email' if 'Email' not in fields
                                        else fields['Email'], autocomplete='off')
            new_username = col2_1.text_input('Username' if 'Username' not in fields
                                        else fields['Username'], autocomplete='off')
        col1_2, col2_2 = register_user_form.columns(2)
        password_instructions = self.attrs.get('password_instructions',
                                               params.PASSWORD_INSTRUCTIONS)
        new_password = col1_2.text_input('Password' if 'Password' not in fields
                                       else fields['Password'], type='password',
                                       help=password_instructions, autocomplete='off')
        new_password_repeat = col2_2.text_input('Repeat password' if 'Repeat password' not in fields
                                              else fields['Repeat password'], type='password',
                                              autocomplete='off')
        if password_hint:
            password_hint = register_user_form.text_input('Password hint' if 'Password hint' not in
                                                        fields else fields['Password hint'],
                                                        autocomplete='off')
        entered_captcha = None
        if captcha:
            entered_captcha = register_user_form.text_input('Captcha' if 'Captcha' not in fields
                                                            else fields['Captcha'],
                                                            autocomplete='off').strip()
            register_user_form.image(Helpers.generate_captcha('register_user_captcha',
                                                              self.secret_key))
        if register_user_form.form_submit_button('Register' if 'Register' not in fields
                                                 else fields['Register']):
            if two_factor_auth:
                self.__two_factor_auth(new_email, widget='register', fields=fields)
            else:
                return self.authentication_controller.register_user(new_first_name, new_last_name,
                                                                    new_email, new_username,
                                                                    new_password,
                                                                    new_password_repeat,
                                                                    password_hint, pre_authorized,
                                                                    domains, roles, callback,
                                                                    captcha, entered_captcha)
        if two_factor_auth and st.session_state.get('2FA_check_register'):
            del st.session_state['2FA_check_register']
            return self.authentication_controller.register_user(new_first_name, new_last_name,
                                                                new_email, new_username,
                                                                new_password, new_password_repeat,
                                                                password_hint, pre_authorized,
                                                                domains, roles, callback, captcha,
                                                                entered_captcha)
        return None, None, None
    def reset_password(self, username: str, location: Literal['main', 'sidebar'] = 'main',
                       fields: Optional[Dict[str, str]] = None, clear_on_submit: bool = False,
                       key: str = 'Reset password', callback: Optional[Callable] = None
                       ) -> Optional[bool]:
        """
        Renders a password reset widget.

        Parameters
        ----------
        username : str
            Username of the user whose password is being reset.
        location : {'main', 'sidebar'}, default='main'
            Location where the password reset widget is rendered.
        fields : dict, optional
            Custom labels for form fields and buttons.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Reset password'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.

        Returns
        -------
        bool or None
            - True if the password reset was successful.
            - None if the reset failed or was not attempted.
        """
        if not st.session_state.get('authentication_status'):
            raise ResetError('User must be logged in to use the reset password widget')
        if fields is None:
            fields = {'Form name':'Reset password', 'Current password':'Current password',
                      'New password':'New password','Repeat password':'Repeat password',
                      'Reset':'Reset'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            reset_password_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        reset_password_form.subheader('Reset password' if 'Form name' not in fields
                                      else fields['Form name'])
        password = reset_password_form.text_input('Current password'
                                                  if 'Current password' not in fields
                                                  else fields['Current password'],
                                                  type='password', autocomplete='off').strip()
        password_instructions = self.attrs.get('password_instructions',
                                               params.PASSWORD_INSTRUCTIONS)
        new_password = reset_password_form.text_input('New password'
                                                      if 'New password' not in fields
                                                      else fields['New password'],
                                                      type='password',
                                                      help=password_instructions,
                                                      autocomplete='off').strip()
        new_password_repeat = reset_password_form.text_input('Repeat password'
                                                             if 'Repeat password' not in fields
                                                             else fields['Repeat password'],
                                                             type='password',
                                                             autocomplete='off').strip()
        if reset_password_form.form_submit_button('Reset' if 'Reset' not in fields
                                                  else fields['Reset']):
            if self.authentication_controller.reset_password(username, password, new_password,
                                                          new_password_repeat, callback):
                return True
        return None
    def __two_factor_auth(self, email: str, content: Optional[Dict[str, Any]] = None,
                          fields: Optional[Dict[str, str]] = None, widget: Optional[str] = None
                          ) -> None:
        """
        Renders a two-factor authentication widget.

        Parameters
        ----------
        email : str
            Email address to which the two-factor authentication code is sent.
        content : dict, optional
            Optional content to save in session state.
        fields : dict, optional
            Custom labels for form fields and buttons.
        widget : str, optional
            Widget name used as a key in session state variables.
        """
        self.authentication_controller.generate_two_factor_auth_code(email, widget)
        @st.dialog('Verification code' if 'Dialog name' not in fields else fields['Dialog name'])
        def two_factor_auth_form():
            code = st.text_input('Code' if 'Code' not in fields else fields['Code'],
                                 help='Please enter the code sent to your email'
                                 if 'Instructions' not in fields else fields['Instructions'],
                                 autocomplete='off')
            if st.button('Submit' if 'Submit' not in fields else fields['Submit']):
                if self.authentication_controller.check_two_factor_auth_code(code, content, widget):
                    st.rerun()
                else:
                    st.error('Code is incorrect' if 'Error' not in fields else fields['Error'])
        two_factor_auth_form()
    def update_user_details(self, username: str, location: Literal['main', 'sidebar'] = 'main',
                            fields: Optional[Dict[str, str]] = None,
                            clear_on_submit: bool = False, key: str = 'Update user details',
                            callback: Optional[Callable] = None) -> bool:
        """
        Renders an update user details widget.

        Parameters
        ----------
        username : str
            Username of the user whose details are being updated.
        location : {'main', 'sidebar'}, default='main'
            Location where the update user details widget is rendered.
        fields : dict, optional
            Custom labels for form fields and buttons.
        clear_on_submit : bool, default=False
            If True, clears input fields after form submission.
        key : str, default='Update user details'
            Unique key for the widget to prevent duplicate WidgetID errors.
        callback : Callable, optional
            Function to execute when the form is submitted.

        Returns
        -------
        bool or None
            - True if user details were successfully updated.
            - None if the update failed or was not attempted.
        """
        if not st.session_state.get('authentication_status'):
            raise UpdateError('User must be logged in to use the update user details widget')
        if fields is None:
            fields = {'Form name':'Update user details', 'Field':'Field', 'First name':'First name',
                      'Last name':'Last name', 'Email':'Email', 'New value':'New value',
                      'Update':'Update'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            update_user_details_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        update_user_details_form.subheader('Update user details' if 'Form name' not in fields
                                           else fields['Form name'])
        update_user_details_form_fields = ['First name' if 'First name' not in fields else \
                                           fields['First name'],
                                           'Last name' if 'Last name' not in fields else \
                                            fields['Last name'],
                                           'Email' if 'Email' not in fields else fields['Email']]
        field = update_user_details_form.selectbox('Field' if 'Field' not in fields
                                                   else fields['Field'],
                                                   update_user_details_form_fields)
        new_value = update_user_details_form.text_input('New value' if 'New value' not in fields
                                                        else fields['New value'],
                                                        autocomplete='off').strip()
        if update_user_details_form_fields.index(field) == 0:
            field = 'first_name'
        elif update_user_details_form_fields.index(field) == 1:
            field = 'last_name'
        elif update_user_details_form_fields.index(field) == 2:
            field = 'email'
        if update_user_details_form.form_submit_button('Update' if 'Update' not in fields
                                                       else fields['Update']):
            if self.authentication_controller.update_user_details(username, field, new_value,
                                                                  callback):
                # self.cookie_controller.set_cookie()
                return True
