import jwt
import yaml
import bcrypt
import streamlit as st
from yaml.loader import SafeLoader
from datetime import datetime, timedelta
import extra_streamlit_components as stx
import streamlit.components.v1 as components

_RELEASE = True

class Hasher:
    def __init__(self, passwords: list):
        """
        Create a new instance of "Hasher".

        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        """
        self.passwords = passwords


    def hash(self, password: str) -> str:
        """
        Hashes the plain text password.

        Parameters
        ----------
        password: str
            The plain text password to be hashed.
        Returns
        -------
        str
            The hashed password.
        """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


    def generate(self) -> list:
        """
        Hashes the list of plain text passwords.

        Returns
        -------
        list
            The list of hashed passwords.
        """
        hashedpw = []

        for password in self.passwords:
            hashedpw.append(self.hash(password))
        return hashedpw


class Authenticate:
    def __init__(self, credentials: dict, cookie_name: str, key: str, cookie_expiry_days: int=30, register: list=None):
        """
        Create a new instance of "Authenticate".

        Parameters
        ----------
        credentials: dict
            The dictionary of usernames, names, passwords, and emails.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for passwordless reauthentication.
        key: str
            The key to be used for hashing the signature of the JWT cookie.
        cookie_expiry_days: int
            The number of days before the cookie expires on the client's browser.
        register: list
            The list of emails of unregistered users allowed to register.
        """
        self.credentials = credentials
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days
        self.register = register
        self.cookie_manager = stx.CookieManager()

        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None
        if 'logout' not in st.session_state:
            st.session_state['logout'] = None


    def token_encode(self) -> str:
        """
        Encodes the contents of the reauthentication cookie.

        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode({'name':st.session_state['name'],
        'username':st.session_state['username'],
        'exp_date':self.exp_date}, self.key, algorithm='HS256')


    def token_decode(self) -> str:
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


    def set_exp_date(self) -> str:
        """
        Creates the reauthentication cookie's expiry date.

        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()


    def check_pw(self) -> bool:
        """
        Checks the validity of the entered password.

        Returns
        -------
        bool
            The validation state for the entered password by comparing it to the hashed password on disk.
        """
        return bcrypt.checkpw(self.password.encode(), self.credentials['usernames'][self.username]['password'].encode())


    def check_cookie(self):
        """
        Checks the validity of the reauthentication cookie.
        """
        self.token = self.cookie_manager.get(self.cookie_name)
        if self.token is not None:
            self.token = self.token_decode()
            if self.token is not False:
                if not st.session_state['logout']:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        if 'name' and 'username' in self.token:
                            st.session_state['name'] = self.token['name']
                            st.session_state['username'] = self.token['username']
                            st.session_state['authentication_status'] = True


    def check_credentials(self, inplace: bool=True) -> bool:
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
        if self.username in self.credentials['usernames']:
            try:
                if self.check_pw():
                    if inplace:
                        st.session_state['name'] = self.credentials['usernames'][self.username]['name']
                        self.exp_date = self.set_exp_date()
                        self.token = self.token_encode()
                        self.cookie_manager.set(self.cookie_name, self.token,
                            expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                        st.session_state['authentication_status'] = True
                    else:
                        return True
                else:
                    if inplace:
                        st.session_state['authentication_status'] = False
                    else:
                        return False
            except Exception as e:
                print(e)
        else:
            if inplace:
                st.session_state['authentication_status'] = False
            else:
                return False


    def login(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a login widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
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
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if not st.session_state['authentication_status']:
            self.check_cookie()
            if st.session_state['authentication_status'] != True:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')

                login_form.subheader(form_name)
                self.username = login_form.text_input('Username')
                st.session_state['username'] = self.username
                self.password = login_form.text_input('Password', type='password')

                if login_form.form_submit_button('Login'):
                    self.check_credentials()

        return st.session_state['name'], st.session_state['authentication_status'], st.session_state['username']


    def logout(self, button_name: str, location: str='main'):
        """
        Creates a logout button.

        Parameters
        ----------
        button_name: str
            The rendered name of the logout button.
        location: str
            The location of the logout button i.e. main or sidebar.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            if st.button(button_name):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None
        elif location == 'sidebar':
            if st.sidebar.button(button_name):
                self.cookie_manager.delete(self.cookie_name)
                st.session_state['logout'] = True
                st.session_state['name'] = None
                st.session_state['username'] = None
                st.session_state['authentication_status'] = None


    def _reset_credentials(self):
        """
        Updates credentials dictionary with user's reset hashed password.

        Returns
        -------
        str
            The status of resetting the password.
        """
        if self.check_credentials(inplace=False):
            if len(self.new_password) > 0:
                if self.new_password == self.new_password_repeat:
                    self.credentials['usernames'][self.username]['password'] = Hasher([self.new_password]).generate()[0]
                    return 'Password reset successfully'
                else:
                    return 'Passwords do not match'
            else:
                return 'Please enter a new password'
        else:
            return 'Username/password is incorrect'


    def reset_password(self, form_name: str, location: str='main') -> tuple:
        """
        Creates a password reset widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        Returns
        -------
        dict
            Credentials dictionary with reset hashed password.
        """
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            reset_password_form = st.form('Reset password')
        elif location == 'sidebar':
            reset_password_form = st.sidebar.form('Reset password')
        
        reset_status = {'Password reset successfully': reset_password_form.success, 
            'Passwords do not match': reset_password_form.warning, 
            'Please enter a new password': reset_password_form.warning, 
            'Username/password is incorrect': reset_password_form.error}

        reset_password_form.subheader(form_name)
        self.username = reset_password_form.text_input('Username')
        self.password = reset_password_form.text_input('Current password', type='password')
        self.new_password = reset_password_form.text_input('New password', type='password')
        self.new_password_repeat = reset_password_form.text_input('Repeat password', type='password')

        if reset_password_form.form_submit_button('Reset'):
            status = self._reset_credentials()
            reset_status[status](status)
    

    def _register_credentials(self):
        """
        Updates credentials dictionary with new user's information.

        Returns
        -------
        str
            The status of registering the new user.
        """
        if len(self.new_username) and len(self.new_name) and len(self.new_password) > 0:
            if self.new_username not in self.credentials['usernames']:
                if self.new_password == self.new_password_repeat:
                    self.credentials['usernames'][self.new_username] = {'name': self.new_name, 
                        'password': Hasher([self.new_password]).generate()[0], 'email': self.registered_email}
                    if self.preauthorization:
                        self.register['emails'].remove(self.registered_email)
                    return 'User registered successfully'
                else:
                    return 'Passwords do not match'
            else:
                return 'Username already taken'
        else:
            return 'Please enter a new username, name, and password'


    def register_user(self, form_name: str, location: str='main', preauthorization=True):
        """
        Creates a password reset widget.

        Parameters
        ----------
        form_name: str
            The rendered name of the password reset form.
        location: str
            The location of the password reset form i.e. main or sidebar.
        preauthorization: bool
            The pre-authorization requirement, True: user must be pre-authorized to register, 
            False: any user can register.
        Returns
        -------
        dict
            Credentials dictionary with registered user.
        """
        if not self.register:
            raise ValueError("Register argument must not be None")
        if location not in ['main', 'sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")
        if location == 'main':
            register_user_form = st.form('Register user')
        elif location == 'sidebar':
            register_user_form = st.sidebar.form('Register user')

        register_status = {'User registered successfully': register_user_form.success, 
            'Passwords do not match': register_user_form.warning, 
            'Username already taken': register_user_form.warning, 
            'Please enter a new username, name and password': register_user_form.warning}

        register_user_form.subheader(form_name)
        self.registered_email = register_user_form.text_input('Email')
        self.new_username = register_user_form.text_input('Username')
        self.new_name = register_user_form.text_input('Name')
        self.new_password = register_user_form.text_input('Password', type='password')
        self.new_password_repeat = register_user_form.text_input('Repeat password', type='password')
        self.preauthorization = preauthorization

        if register_user_form.form_submit_button('Register'):
            if self.preauthorization:
                if self.registered_email in self.register['emails']:
                    status = self._register_credentials()
                    register_status[status](status)
                else:
                    register_user_form.error('Email not allowed to register')
            else:
                status = self._register_credentials()
                register_status[status](status)

if not _RELEASE:
    #hashed_passwords = Hasher(['123', '456']).generate()
    with open('../config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    authenticator = Authenticate(
        config['credentials'],
        config['cookie']['name'], 
        config['cookie']['key'], 
        config['cookie']['expiry_days'],
        config['register']
    )

    name, authentication_status, username = authenticator.login('Login', 'main')

    if authentication_status:
        authenticator.logout('Logout', 'main')
        st.write(f'Welcome *{name}*')
        st.title('Some content')
    elif authentication_status == False:
        st.error('Username/password is incorrect')
    elif authentication_status == None:
        st.warning('Please enter your username and password')

    authenticator.reset_password('Reset password')
    authenticator.register_user('Register user', preauthorization=True)

    with open('../config.yaml', 'w') as file:
        yaml.dump(config, file, default_flow_style=False)

    # Alternatively you use st.session_state['name'] and
    # st.session_state['authentication_status'] to access the name and
    # authentication_status.

    # if st.session_state['authentication_status']:
    #     authenticator.logout('Logout', 'main')
    #     st.write(f'Welcome *{st.session_state["name"]}*')
    #     st.title('Some content')
    # elif st.session_state['authentication_status'] == False:
    #     st.error('Username/password is incorrect')
    # elif st.session_state['authentication_status'] == None:
    #     st.warning('Please enter your username and password')
