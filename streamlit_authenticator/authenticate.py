import jwt
import bcrypt
import streamlit as st
from typing import Optional
from datetime import datetime, timedelta
import extra_streamlit_components as stx

from .hasher import Hasher
from .validator import Validator
from .utils import generate_random_pw
from .exceptions import CredentialsError, DeprecationError, ForgotError, LoginError, RegisterError, ResetError, UpdateError

class Authenticate:
    """
    This class will create login, logout, register user, reset password, forgot password, 
    forgot username, and modify user details widgets.
    """
    def __init__(self, credentials: dict, cookie_name: str, key: str, cookie_expiry_days: float=30.0, 
        preauthorized: Optional[list]=None, validator: Optional[Validator]=None):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        credentials: dict
            The dictionary of usernames, names, passwords, emails, and other user data.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for passwordless reauthentication.
        key: str
            The key to be used to hash the signature of the JWT cookie.
        cookie_expiry_days: float
            The number of days before the reauthentication cookie automatically expires on the client's browser.
        preauthorized: list
            The list of emails of unregistered users who are authorized to register.
        validator: Validator
            A Validator object that checks the validity of the username, name, and email fields.
        """
        self.credentials                =   credentials
        self.credentials['usernames']   =   {key.lower(): value for key, value in credentials['usernames'].items()}
        self.cookie_name                =   cookie_name
        self.key                        =   key
        self.cookie_expiry_days         =   cookie_expiry_days
        self.preauthorized              =   preauthorized
        self.cookie_manager             =   stx.CookieManager()
        self.validator                  =   validator if validator is not None else Validator()

        for username, _ in self.credentials['usernames'].items():
            if 'logged_in' not in self.credentials['usernames'][username]:
                self.credentials['usernames'][username]['logged_in'] = False
            if not Hasher._is_hash(self.credentials['usernames'][username]['password']):
                self.credentials['usernames'][username]['password'] = Hasher._hash(self.credentials['usernames'][username]['password'])
        
        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None
        if 'failed_login_attempts' not in st.session_state:
            st.session_state['failed_login_attempts'] = {}

    def _token_encode(self) -> str:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode({'username': st.session_state['username'],
            'exp_date': self.exp_date}, self.key, algorithm='HS256')

    def _token_decode(self) -> str:
        """
        Decodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        try:
            return jwt.decode(self.token, self.key, algorithms=['HS256'])
        except:
            return False

    def _set_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def _check_pw(self) -> bool:
        """
        Checks the validity of the entered password.

        Returns
        -------
        bool
            The validity of the entered password by comparing it to the hashed password on disk.
        """
        return bcrypt.checkpw(self.password.encode(), 
            self.credentials['usernames'][self.username]['password'].encode())

    def _check_cookie(self):
        """
        Checks the validity of the reauthentication cookie.
        """
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self._token_decode()
            if self.token is not False:
                if not st.session_state['logout']:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        if 'username' in self.token:
                            st.session_state['username'] = self.token['username']
                            st.session_state['name'] = self.credentials['usernames'][self.token['username']]['name']
                            st.session_state['authentication_status'] = True
                            self.credentials['usernames'][self.token['username']]['logged_in'] = True
    
    def _record_failed_login_attempts(self, reset: bool=False):
        """
        Records the number of failed login attempts for a given username.
        
        Parameters
        ----------
        reset: bool            
            The reset failed login attempts option, True: number of failed login attempts for the user will be reset to 0, 
            False: number of failed login attempts for the user will be incremented.
        """
        if self.username not in st.session_state['failed_login_attempts']:
            st.session_state['failed_login_attempts'][self.username] = 0
        if reset:
            st.session_state['failed_login_attempts'][self.username] = 0
        else:
            st.session_state['failed_login_attempts'][self.username] += 1
            
    def _check_credentials(self, inplace: bool=True) -> bool:
        """
        Checks the validity of the entered credentials.

        Parameters
        ----------
        inplace: bool
            Inplace setting, True: authentication status will be stored in session state, 
            False: authentication status will be returned as bool.

        Returns
        -------
        bool
            Validity of entered credentials.
        """
        if isinstance(self.max_concurrent_users, int):
            if self._count_concurrent_users() > self.max_concurrent_users - 1:
                raise(LoginError('Maximum number of concurrent users exceeded'))
        if self.username in self.credentials['usernames']:
            try:
                if self._check_pw():
                    if inplace:
                        st.session_state['name'] = self.credentials['usernames'][self.username]['name']
                        self.exp_date = self._set_exp_date()
                        self.token = self._token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                        st.session_state['authentication_status'] = True
                    else:
                        return True
                    self._record_failed_login_attempts(reset=True)
                    self.credentials['usernames'][self.username]['logged_in'] = True
                else:
                    if inplace:
                        st.session_state['authentication_status'] = False
                    else:
                        return False
                    self._record_failed_login_attempts()
            except Exception as e:
                print(e)
        else:
            if inplace:
                st.session_state['authentication_status'] = False
            else:
                return False
            self._record_failed_login_attempts()

    def _count_concurrent_users(self):
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

    def login(self, location: str='main', max_concurrent_users: Optional[int]=None, fields: dict={'Form name':'Login', 
                                                                                                  'Username':'Username', 
                                                                                                  'Password':'Password',
                                                                                                  'Login':'Login'}) -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        location: str
            The location of the login widget i.e. main or sidebar.
        max_concurrent_users: int
            The number of maximum users allowed to login concurrently.
        fields: dict
            The rendered names of the fields/buttons.

        Returns
        -------
        str
            Name of the authenticated user.
        bool
            The status of authentication, None: no credentials entered, 
            False: incorrect credentials, True: correct credentials.
        str
            Username of the authenticated user.
        """
        self.max_concurrent_users = max_concurrent_users

        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until later releases
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been replaced
                                   with the 'fields' parameter. For further information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticatelogin""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'") 
        if not st.session_state['authentication_status']:
            self._check_cookie()
            if not st.session_state['authentication_status']:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')
                login_form.subheader('Login' if 'Form name' not in fields else fields['Form name'])
                self.username = login_form.text_input('Username' if 'Username' not in fields else fields['Username']).lower()
                st.session_state['username'] = self.username
                self.password = login_form.text_input('Password' if 'Password' not in fields else fields['Password'],
                                                       type='password')

                if login_form.form_submit_button('Login' if 'Login' not in fields else fields['Login']):
                    self._check_credentials()

        return st.session_state['name'], st.session_state['authentication_status'], st.session_state['username']

    def _implement_logout(self):
        """
        Clears cookie and session state variables associated with the logged in user.
        """
        self.cookie_manager.delete(self.cookie_name)
        self.credentials['usernames'][st.session_state['username']]['logged_in'] = False
        st.session_state['logout'] = True
        st.session_state['name'] = None
        st.session_state['username'] = None
        st.session_state['authentication_status'] = None

    def logout(self, button_name: str='Logout', location: str='main', key: Optional[str]=None):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar or unrendered.
        key: str
            A unique key to be used in multipage applications.
        """
        if location not in ['main', 'sidebar','unrendered']:
            raise ValueError("Location must be one of 'main' or 'sidebar' or 'unrendered'")
        if location == 'main':
            if st.button(button_name, key):
                self._implement_logout()
        elif location == 'sidebar':
            if st.sidebar.button(button_name, key):
                self._implement_logout()
        elif location == 'unrendered':
            if st.session_state['authentication_status']:
                self._implement_logout()

    def _update_password(self, username: str, password: str):
        """
        Updates credentials dictionary with user's reset hashed password.

        Parameters
        ----------
        username: str
            The username of the user to update the password for.
        password: str
            The updated plain text password.
        """
        self.credentials['usernames'][username]['password'] = Hasher([password]).generate()[0]

    def reset_password(self, username: str, location: str='main', fields: dict={'Form name':'Reset password', 
                                                                                'Current password':'Current password', 
                                                                                'New password':'New password',
                                                                                'Repeat password':'Repeat password',
                                                                                'Reset':'Reset'} ) -> bool:
        """
        Creates a password reset widget.

        Parameters
        ----------
        username: str
            The username of the user to reset the password for.
        location: str
            The location of the password reset widget i.e. main or sidebar.
        fields: dict
            The rendered names of the fields/buttons.

        Returns
        -------
        bool
            The status of resetting the password.
        """
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until later releases
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been replaced
                                   with the 'fields' parameter. For further information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticatereset_password""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'") 
        if location == 'main':
            reset_password_form = st.form('Reset password')
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password')
        
        reset_password_form.subheader('Reset password' if 'Form name' not in fields else fields['Form name'])
        self.username = username.lower()
        self.password = reset_password_form.text_input('Current password' if 'Current password' not in fields else fields['Current password'], 
                                                       type='password')
        new_password = reset_password_form.text_input('New password' if 'New password' not in fields else fields['New password'], 
                                                      type='password')
        new_password_repeat = reset_password_form.text_input('Repeat password' if 'Repeat password' not in fields else fields['Repeat password'], 
                                                             type='password')

        if reset_password_form.form_submit_button('Reset' if 'Reset' not in fields else fields['Reset']):
            if self._check_credentials(inplace=False):
                if len(new_password) == 0:
                    raise ResetError('No new password provided')
                if new_password != new_password_repeat:
                    raise ResetError('Passwords do not match')
                if self.password != new_password: 
                    self._update_password(self.username, new_password)
                    return True
                else:
                    raise ResetError('New and current passwords are the same')                                            
            else:
                raise CredentialsError('password')
    
    def _credentials_contains_value(self, value):
        """
        Checks to see if a value is present in the credentials dictionary.

        Parameters
        ----------
        value: str
            The value being checked.

        Returns
        -------
        bool
            The presence/absence of the value, True: value present, False value absent.
        """
        return any(value in d.values() for d in self.credentials['usernames'].values())

    def _register_credentials(self, username: str, name: str, password: str, email: str, preauthorization: bool,
                               domains: list):
        """
        Adds to credentials dictionary the new user's information.

        Parameters
        ----------
        username: str
            The username of the new user.
        name: str
            The name of the new user.
        password: str
            The password of the new user.
        email: str
            The email of the new user.
        preauthorization: bool
            The preauthorization requirement, True: user must be preauthorized to register, 
            False: any user can register.
        domains: list
            The required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
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
        self.credentials['usernames'][username] = {'name': name, 'password': Hasher([password]).generate()[0], 
                                                   'email': email, 'logged_in': False}
        if preauthorization:
            self.preauthorized['emails'].remove(email)

    def register_user(self, location: str='main', preauthorization: bool=True, domains: Optional[list]=None, 
                      fields: dict={'Form name':'Register User', 
                                    'Email':'Email', 
                                    'Username':'Username', 
                                    'Password':'Password', 
                                    'Repeat password':'Repeat password',
                                    'Register':'Register'}) -> bool:
        """
        Creates a register new user widget.

        Parameters
        ----------
        location: str
            The location of the register new user widget i.e. main or sidebar.
        preauthorization: bool
            The preauthorization requirement, True: user must be preauthorized to register, 
            False: any user can register.
        domains: list
            The required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], 
            list: the required list of domains, None: any domain is allowed.
        fields: dict
            The rendered names of the fields/buttons.

        Returns
        -------
        str
            Email associated with the new user.
        str
            Username associated with the new user.
        str
            Name associated with the new user.
        """
        if preauthorization:
            if not self.preauthorized:
                raise ValueError("preauthorization argument must not be None")
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until later releases
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been replaced
                                   with the 'fields' parameter. For further information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateregister_user""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'") 
        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_user_form.subheader('Register User' if 'Form name' not in fields else fields['Form name'])
        new_email = register_user_form.text_input('Email' if 'Email' not in fields else fields['Email'])
        new_username = register_user_form.text_input('Username' if 'Username' not in fields else fields['Username']).lower()
        new_name = register_user_form.text_input('Name' if 'Name' not in fields else fields['Name'])
        new_password = register_user_form.text_input('Password' if 'Password' not in fields else fields['Password'], type='password')
        new_password_repeat = register_user_form.text_input('Repeat password' if 'Repeat password' not in fields else fields['Repeat password'],
                                                             type='password')
        
        if register_user_form.form_submit_button('Register' if 'Register' not in fields else fields['Register']):
            if len(new_password) == 0 or len(new_password_repeat) == 0:
                raise RegisterError('Password/repeat password fields cannot be empty')
            if new_password != new_password_repeat:
                raise RegisterError('Passwords do not match')
            if preauthorization:
                if new_email in self.preauthorized['emails']:
                    self._register_credentials(new_username, new_name, new_password, new_email, 
                                               preauthorization, domains)
                    return new_email, new_username, new_name
                else:
                    raise RegisterError('User not preauthorized to register')
            else:
                self._register_credentials(new_username, new_name, new_password, new_email, 
                                           preauthorization, domains)
                return new_email, new_username, new_name
        return None, None, None                                                               

    def _set_random_password(self, username: str) -> str:
        """
        Updates credentials dictionary with user's hashed random password.

        Parameters
        ----------
        username: str
            Username of user to set random password for.

        Returns
        -------
        str
            New plain text password that should be transferred to user securely.
        """
        self.random_password = generate_random_pw()
        self.credentials['usernames'][username]['password'] = Hasher([self.random_password]).generate()[0]
        return self.random_password

    def forgot_password(self, location: str='main', fields: dict={'Form name':'Forgot password', 
                                                                  'Username':'Username', 
                                                                  'Submit':'Submit'}, ) -> tuple:
        """
        Creates a forgot password widget.

        Parameters
        ----------
        location: str
            The location of the forgot password widget i.e. main or sidebar.
        fields: dict
            The rendered names of the fields/buttons.

        Returns
        -------
        str
            Username associated with the forgotten password.
        str
            Email associated with the forgotten password.
        str
            New plain text password that should be transferred to the user securely.
        """
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until later releases
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been replaced
                                   with the 'fields' parameter. For further information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateforgot_password""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'") 
        if location == 'main':
            forgot_password_form = st.form('Forgot password')
        elif location == 'sidebar':
            forgot_password_form = st.sidebar.form('Forgot password')

        forgot_password_form.subheader('Forget password' if 'Form name' not in fields else fields['Form name'])
        username = forgot_password_form.text_input('Username' if 'Username' not in fields else fields['Username']).lower()

        if forgot_password_form.form_submit_button('Submit' if 'Submit' not in fields else fields['Submit']):
            if len(username) > 0:
                if username in self.credentials['usernames']:
                    return username, self.credentials['usernames'][username]['email'], self._set_random_password(username)
                else:
                    return False, None, None
            else:
                raise ForgotError('Username not provided')
        return None, None, None

    def _get_username(self, key: str, value: str) -> str:
        """
        Retrieves username based on a provided entry.

        Parameters
        ----------
        key: str
            Name of the credential to query i.e. "email".
        value: str
            Value of the queried credential i.e. "jsmith@gmail.com".

        Returns
        -------
        str
            Username associated with given key, value pair i.e. "jsmith".
        """
        for username, values in self.credentials['usernames'].items():
            if values[key] == value:
                return username
        return False

    def forgot_username(self, location: str='main', fields: dict={'Form name':'Forgot username', 
                                                                  'Email':'Email', 
                                                                  'Submit':'Submit'}) -> tuple:
        """
        Creates a forgot username widget.

        Parameters
        ----------
        location: str
            The location of the forgot username widget i.e. main or sidebar.
        fields: dict
            The rendered names of the fields/buttons.

        Returns
        -------
        str
            Forgotten username that should be transferred to user securely.
        str
            Email associated with forgotten username.
        """
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until later releases
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been replaced
                                   with the 'fields' parameter. For further information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateforgot_username""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'") 
        if location == 'main':
            forgot_username_form = st.form('Forgot username')
        elif location == 'sidebar':
            forgot_username_form = st.sidebar.form('Forgot username')

        forgot_username_form.subheader('Forget username' if 'Form name' not in fields else fields['Form name'])
        email = forgot_username_form.text_input('Email' if 'Email' not in fields else fields['Email'])

        if forgot_username_form.form_submit_button('Submit' if 'Submit' not in fields else fields['Submit']):
            if len(email) > 0:
                return self._get_username('email', email), email
            else:
                raise ForgotError('Email not provided')
        return None, email

    def _update_entry(self, username: str, key: str, value: str):
        """
        Updates credentials dictionary with user's updated entry.

        Parameters
        ----------
        username: str
            The username of the user to update the entry for.
        key: str
            The updated entry key i.e. "email".
        value: str
            The updated entry value i.e. "jsmith@gmail.com".
        """
        self.credentials['usernames'][username][key] = value

    def update_user_details(self, username: str, location: str='main', fields: dict={'Form name':'Update user details',
                                                                                     'Field':'Field',
                                                                                     'Name':'Name', 
                                                                                     'Email':'Email', 
                                                                                     'New value':'New value', 
                                                                                     'Update':'Update'}) -> bool:
        """
        Creates a update user details widget.

        Parameters
        ----------
        username: str
            The username of the user to update user details for.
        location: str
            The location of the update user details widget i.e. main or sidebar.
        fields: dict
            The rendered names of the fields/buttons.

        Returns
        -------
        bool
            The status of updating the user details.
        """
        if location not in ['main', 'sidebar']:
            # Temporary deprecation error to be displayed until later releases
            raise DeprecationError("""Likely deprecation error, the 'form_name' parameter has been replaced
                                   with the 'fields' parameter. For further information please refer to 
                                   https://github.com/mkhorasani/Streamlit-Authenticator/tree/main?tab=readme-ov-file#authenticateupdate_user_details""")
            # raise ValueError("Location must be one of 'main' or 'sidebar'") 
        if location == 'main':
            update_user_details_form = st.form('Update user details')
        elif location == 'sidebar':
            update_user_details_form = st.sidebar.form('Update user details')
        
        update_user_details_form.subheader('Update user details' if 'Form name' not in fields else fields['Form name'])
        self.username = username.lower()
        update_user_details_form_fields = ['Name' if 'Name' not in fields else fields['Name'],
                                           'Email' if 'Email' not in fields else fields['Email']]
        field = update_user_details_form.selectbox('Field' if 'Field' not in fields else fields['Field'], 
                                                   update_user_details_form_fields)
        new_value = update_user_details_form.text_input('New value' if 'New value' not in fields else fields['New value'])

        if update_user_details_form_fields.index(field) == 0:
            field = 'name'
        elif update_user_details_form_fields.index(field) == 1:
            field = 'email'

        if update_user_details_form.form_submit_button('Update' if 'Update' not in fields else fields['Update']):
            if len(new_value) > 0:
                if field == 'name':
                    if not self.validator.validate_name(new_value):
                        raise UpdateError('Name is not valid')
                if field == 'email':
                    if not self.validator.validate_email(new_value):
                        raise UpdateError('Email is not valid')
                    if self._credentials_contains_value(new_value):
                        raise UpdateError('Email already taken')
                if new_value != self.credentials['usernames'][self.username][field]:
                    self._update_entry(self.username, field, new_value)
                    if field == 'name':
                            st.session_state['name'] = new_value
                            self.exp_date = self._set_exp_date()
                            self.token = self._token_encode()
                            self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                    return True
                else:
                    raise UpdateError('New and current values are the same')
            if len(new_value) == 0:
                raise UpdateError('New value not provided')
