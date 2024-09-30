"""
Script description: This module renders the login, logout, register user, reset password,
forgot password, forgot username, and modify user details widgets. 

Libraries imported:
- time: Module implementing the sleep function.
- typing: Module implementing standard typing notations for Python functions.
- streamlit: Framework used to build pure Python web applications.
"""

import time
from typing import Any, Callable, Dict, List, Optional, Union

import streamlit as st

from ..controllers import AuthenticationController, CookieController
from .. import params
from ..utilities import DeprecationError, Helpers, LogoutError, ResetError, UpdateError, Validator

class Authenticate:
    """
    This class renders login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: Union[dict, str], cookie_name: str='some_cookie_name',
                 cookie_key: str='some_key', cookie_expiry_days: float=30.0,
                 validator: Optional[Validator]=None, auto_hash: bool=True,
                 **kwargs: Optional[Dict[str, Any]]):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        credentials: dict, str
            Dictionary of usernames, names, passwords, emails, and other user data; or path
            pointing to the location of the config file.
        cookie_name: str
            Name of the re-authentication cookie stored on the client's browser for password-less 
            re-authentication.
        cookie_key: str
            Key to be used to hash the signature of the re-authentication cookie.
        cookie_expiry_days: float
            Number of days before the re-authentication cookie automatically expires on the client's 
            browser.       
        validator: Validator, optional
            Validator object that checks the validity of the username, name, and email fields.
        auto_hash: bool
            Automatic hashing requirement for passwords, 
            True: plain text passwords will be automatically hashed,
            False: plain text passwords will not be automatically hashed.
        **kwargs : dict, optional
            Arguments to pass to the Authenticate class.
        """
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
                                                                     self.path)
        self.attrs = kwargs
    def forgot_password(self, location: str='main', fields: Optional[Dict[str, str]]=None,
                        captcha: bool=False, clear_on_submit: bool=False,
                        key: str='Forgot password', callback: Optional[Callable]=None) -> tuple:
        """
        Renders a forgot password widget.

        Parameters
        ----------
        location: str
            Location of the forgot password widget i.e. main or sidebar.
        fields: dict, optional
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the forgot password widget, 
            True: captcha required,
            False: captcha removed.
        clear_on_submit: bool
            Clear on submit setting, 
            True: clears inputs on submit, 
            False: keeps inputs on submit.
        key: str
            Unique key provided to widget to avoid duplicate WidgetID errors.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        str
            Username associated with the forgotten password.
        str
            Email associated with the forgotten password.
        str
            New plain text password that should be transferred to the user securely.
        """
        if fields is None:
            fields = {'Form name':'Forgot password', 'Username':'Username', 'Captcha':'Captcha',
                      'Submit':'Submit'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_password_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        forgot_password_form.subheader('Forget password' if 'Form name' not in fields
                                       else fields['Form name'])
        username = forgot_password_form.text_input('Username' if 'Username' not in fields
                                                   else fields['Username'])
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_password_form.text_input('Captcha' if 'Captcha' not in fields
                                                              else fields['Captcha'])
            forgot_password_form.image(Helpers.generate_captcha('forgot_password_captcha'))
        if forgot_password_form.form_submit_button('Submit' if 'Submit' not in fields
                                                   else fields['Submit']):
            return self.authentication_controller.forgot_password(username, callback,
                                                                  captcha, entered_captcha)
        return None, None, None
    def forgot_username(self, location: str='main', fields: Optional[Dict[str, str]]=None,
                        captcha: bool=False, clear_on_submit: bool=False,
                        key: str='Forgot username', callback: Optional[Callable]=None) -> tuple:
        """
        Renders a forgot username widget.

        Parameters
        ----------
        location: str
            Location of the forgot username widget i.e. main or sidebar.
        fields: dict, optional
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the forgot username widget, 
            True: captcha required,
            False: captcha removed.
        clear_on_submit: bool
            Clear on submit setting, 
            True: clears inputs on submit, 
            False: keeps inputs on submit.
        key: str
            Unique key provided to widget to avoid duplicate WidgetID errors.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        str
            Forgotten username that should be transferred to the user securely.
        str
            Email associated with the forgotten username.
        """
        if fields is None:
            fields = {'Form name':'Forgot username', 'Email':'Email', 'Captcha':'Captcha',
                      'Submit':'Submit'}
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            forgot_username_form = st.form(key=key, clear_on_submit=clear_on_submit)
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
        forgot_username_form.subheader('Forget username' if 'Form name' not in fields
                                       else fields['Form name'])
        email = forgot_username_form.text_input('Email' if 'Email' not in fields
                                                else fields['Email'])
        entered_captcha = None
        if captcha:
            entered_captcha = forgot_username_form.text_input('Captcha' if 'Captcha' not in fields
                                                              else fields['Captcha'])
            forgot_username_form.image(Helpers.generate_captcha('forgot_username_captcha'))
        if forgot_username_form.form_submit_button('Submit' if 'Submit' not in fields
                                                   else fields['Submit']):
            return self.authentication_controller.forgot_username(email, callback,
                                                                  captcha, entered_captcha)
        return None, email
    def experimental_guest_login(self, button_name: str='Guest login', location: str='main',
                                 provider: str='google', oauth2: Optional[dict]=None,
                                 max_concurrent_users: Optional[int]=None,
                                 single_session: bool=False, roles: Optional[List[str]]=None,
                                 callback: Optional[Callable]=None):
        """
        Renders a guest login button.

        Parameters
        ----------
        button_name: str
            Rendered name of the guest login button.
        location: str
            Location of the guest login button i.e. main or sidebar.
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
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if provider not in ['google', 'microsoft']:
            raise ValueError("Provider must be one of 'google' or 'microsoft'")
        if not st.session_state['authentication_status']:
            token = self.cookie_controller.get_cookie()
            if token:
                self.authentication_controller.login(token=token)
            time.sleep(params.PRE_LOGIN_SLEEP_TIME if 'login_sleep_time' not in self.attrs \
                       else self.attrs['login_sleep_time'])
            if not st.session_state['authentication_status']:
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
                    st.link_button(button_name, url=auth_endpoint)
                if location == 'sidebar' and auth_endpoint:
                    st.sidebar.link_button(button_name, url=auth_endpoint)
    def login(self, location: str='main', max_concurrent_users: Optional[int]=None,
              max_login_attempts: Optional[int]=None, fields: Optional[Dict[str, str]]=None,
              captcha: bool=False, single_session: bool=False, clear_on_submit: bool=False,
              key: str='Login', callback: Optional[Callable]=None):
        """
        Renders a login widget.

        Parameters
        ----------
        location: str
            Location of the logout button i.e. main, sidebar or unrendered.
        max_concurrent_users: int, optional
            Maximum number of users allowed to login concurrently.
        max_login_attempts: int, optional
            Maximum number of failed login attempts a user can make.
        fields: dict, optional
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the login widget, 
            True: captcha required,
            False: captcha removed.
        single_session: bool
            Disables the ability for the same user to log in multiple sessions,
            True: single session allowed,
            False: multiple sessions allowed.
        clear_on_submit: bool
            Clear on submit setting, 
            True: clears inputs on submit, 
            False: keeps inputs on submit.
        key: str
            Unique key provided to widget to avoid duplicate WidgetID errors.
        callback: callable, optional
            Callback function that will be invoked on form submission.
        """
        if fields is None:
            fields = {'Form name':'Login', 'Username':'Username', 'Password':'Password',
                      'Login':'Login', 'Captcha':'Captcha'}
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if not st.session_state['authentication_status']:
            token = self.cookie_controller.get_cookie()
            if token:
                self.authentication_controller.login(token=token)
            time.sleep(params.PRE_LOGIN_SLEEP_TIME if 'login_sleep_time' not in self.attrs \
                       else self.attrs['login_sleep_time'])
            if not st.session_state['authentication_status']:
                if location == 'main':
                    login_form = st.form(key=key, clear_on_submit=clear_on_submit)
                elif location == 'sidebar':
                    login_form = st.sidebar.form(key=key, clear_on_submit=clear_on_submit)
                elif location == 'unrendered':
                    return (st.session_state['name'], st.session_state['authentication_status'],
                            st.session_state['username'])
                login_form.subheader('Login' if 'Form name' not in fields else fields['Form name'])
                username = login_form.text_input('Username' if 'Username' not in fields
                                                 else fields['Username'])
                if 'password_hint' in st.session_state:
                    password = login_form.text_input('Password' if 'Password' not in fields
                                                     else fields['Password'], type='password',
                                                     help=st.session_state['password_hint'])
                else:
                    password = login_form.text_input('Password' if 'Password' not in fields
                                                     else fields['Password'], type='password')
                entered_captcha = None
                if captcha:
                    entered_captcha = login_form.text_input('Captcha' if 'Captcha' not in fields
                                                            else fields['Captcha'])
                    login_form.image(Helpers.generate_captcha('login_captcha'))
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
    def logout(self, button_name: str='Logout', location: str='main', key: str='Logout',
               callback: Optional[Callable]=None):
        """
        Renders a logout button.

        Parameters
        ----------
        button_name: str
            Rendered name of the logout button.
        location: str
            Location of the logout button i.e. main, sidebar or unrendered.
        key: str
            Unique key to be used in multi-page applications.
        callback: callable, optional
            Callback function that will be invoked on button press.
        """
        if not st.session_state['authentication_status']:
            raise LogoutError('User must be logged in to use the logout button')
        if location not in ['main', 'sidebar', 'unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if location == 'main':
            if st.button(button_name, key=key):
                self.authentication_controller.logout(callback)
                self.cookie_controller.delete_cookie()
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key=key):
                self.authentication_controller.logout(callback)
                self.cookie_controller.delete_cookie()
        elif location == 'unrendered':
            if st.session_state['authentication_status']:
                self.authentication_controller.logout()
                self.cookie_controller.delete_cookie()
    def register_user(self, location: str='main', pre_authorized: Optional[List[str]]=None,
                      domains: Optional[List[str]]=None, fields: Optional[Dict[str, str]]=None,
                      captcha: bool=True, roles: Optional[List[str]]=None,
                      merge_username_email: bool=False, clear_on_submit: bool=False,
                      key: str='Register user', callback: Optional[Callable]=None) -> tuple:
        """
        Renders a register new user widget.

        Parameters
        ----------
        location: str
            Location of the register new user widget i.e. main or sidebar.
        pre-authorized: list, optional
            List of emails of unregistered users who are authorized to register. 
        domains: list, optional
            Required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: required list of domains, 
            None: any domain is allowed.
        fields: dict, optional
            Rendered names of the fields/buttons.
        captcha: bool
            Captcha requirement for the register user widget, 
            True: captcha required,
            False: captcha removed.
        roles: list, optional
            User roles for registered users.
        merge_username_email: bool
            Merges username into email field,
            True: username will be the same as the email,
            False: username and email will be independent.
        clear_on_submit: bool
            Clear on submit setting, 
            True: clears inputs on submit, 
            False: keeps inputs on submit.
        key: str
            Unique key provided to widget to avoid duplicate WidgetID errors.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        str
            Email associated with the new user.
        str
            Username associated with the new user.
        str
            Name associated with the new user.
        """
        if isinstance(pre_authorized, bool) or isinstance(pre_authorized, dict):
            raise DeprecationError(f"""Please note that the 'pre_authorized' parameter now
                                   requires a list of pre-authorized emails. For further
                                   information please refer to {params.REGISTER_USER_LINK}.""")
        if fields is None:
            fields = {'Form name':'Register user', 'First name':'First name',
                      'Last name':'Last name', 'Email':'Email', 'Username':'Username',
                      'Password':'Password', 'Repeat password':'Repeat password',
                      'Password hint':'Password hint', 'Captcha':'Captcha', 'Register':'Register'}
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
                                         else fields['First name'])
        new_last_name = col2_1.text_input('Last name' if 'Last name' not in fields
                                        else fields['Last name'])
        if merge_username_email:
            new_email = register_user_form.text_input('Email' if 'Email' not in fields
                                        else fields['Email'])
            new_username = new_email
        else:
            new_email = col1_1.text_input('Email' if 'Email' not in fields
                                        else fields['Email'])
            new_username = col2_1.text_input('Username' if 'Username' not in fields
                                        else fields['Username'])
        col1_2, col2_2 = register_user_form.columns(2)
        password_instructions = params.PASSWORD_INSTRUCTIONS if 'password_instructions' \
            not in self.attrs else self.attrs['password_instructions']
        new_password = col1_2.text_input('Password' if 'Password' not in fields
                                       else fields['Password'], type='password',
                                       help=password_instructions)
        new_password_repeat = col2_2.text_input('Repeat password' if 'Repeat password' not in fields
                                              else fields['Repeat password'], type='password')
        password_hint = register_user_form.text_input('Password hint' if 'Password hint' not in
                                                      fields else fields['Password hint'])
        entered_captcha = None
        if captcha:
            entered_captcha = register_user_form.text_input('Captcha' if 'Captcha' not in fields
                                                            else fields['Captcha']).strip()
            register_user_form.image(Helpers.generate_captcha('register_user_captcha'))
        if register_user_form.form_submit_button('Register' if 'Register' not in fields
                                                 else fields['Register']):
            return self.authentication_controller.register_user(new_first_name, new_last_name,
                                                                new_email, new_username,
                                                                new_password, new_password_repeat,
                                                                password_hint, pre_authorized if \
                                                                    pre_authorized else None,
                                                                domains, roles, callback, captcha,
                                                                entered_captcha)
        return None, None, None
    def reset_password(self, username: str, location: str='main',
                       fields: Optional[Dict[str, str]]=None, clear_on_submit: bool=False,
                       key: str='Reset password', callback: Optional[Callable]=None) -> bool:
        """
        Renders a password reset widget.

        Parameters
        ----------
        username: str
            Username of the user to reset the password for.
        location: str
            Location of the password reset widget i.e. main or sidebar.
        fields: dict, optional
            Rendered names of the fields/buttons.
        clear_on_submit: bool
            Clear on submit setting, 
            True: clears inputs on submit, 
            False: keeps inputs on submit.
        key: str
            Unique key provided to widget to avoid duplicate WidgetID errors.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            Status of resetting the password.
        """
        if not st.session_state['authentication_status']:
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
                                                  type='password').strip()
        password_instructions = params.PASSWORD_INSTRUCTIONS if 'password_instructions' \
            not in self.attrs else self.attrs['password_instructions']
        new_password = reset_password_form.text_input('New password'
                                                      if 'New password' not in fields
                                                      else fields['New password'],
                                                      type='password',
                                                      help=password_instructions).strip()
        new_password_repeat = reset_password_form.text_input('Repeat password'
                                                             if 'Repeat password' not in fields
                                                             else fields['Repeat password'],
                                                             type='password').strip()
        if reset_password_form.form_submit_button('Reset' if 'Reset' not in fields
                                                  else fields['Reset']):
            if self.authentication_controller.reset_password(username, password, new_password,
                                                          new_password_repeat, callback):
                return True
        return None
    def update_user_details(self, username: str, location: str='main',
                            fields: Optional[Dict[str, str]]=None,
                            clear_on_submit: bool=False, key: str='Update user details',
                            callback: Optional[Callable]=None) -> bool:
        """
        Renders a update user details widget.

        Parameters
        ----------
        username: str
            Username of the user to update user details for.
        location: str
            Location of the update user details widget i.e. main or sidebar.
        fields: dict, optional
            Rendered names of the fields/buttons.
        clear_on_submit: bool
            Clear on submit setting, 
            True: clears inputs on submit, 
            False: keeps inputs on submit.
        key: str
            Unique key provided to widget to avoid duplicate WidgetID errors.
        callback: callable, optional
            Callback function that will be invoked on form submission.

        Returns
        -------
        bool
            Status of updating the user details.
        """
        if not st.session_state['authentication_status']:
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
                                                        else fields['New value']).strip()
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
