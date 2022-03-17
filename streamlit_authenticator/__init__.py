import os
import jwt
import bcrypt
import streamlit as st
from datetime import datetime, timedelta
import extra_streamlit_components as stx
import streamlit.components.v1 as components

_RELEASE = True

class Hasher:
    def __init__(self,passwords):
        """Create a new instance of "Hasher".
        Parameters
        ----------
        passwords: list
            The list of plain text passwords to be hashed.
        Returns
        -------
        list
            The list of hashed passwords.
        """
        self.passwords = passwords

    def hash(self,password):
        """
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

    def generate(self):
        """
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
    def __init__(self,names,usernames,passwords,cookie_name,key,cookie_expiry_days=30):
        """Create a new instance of "Authenticate".
        Parameters
        ----------
        names: list
            The list of names of users.
        usernames: list
            The list of usernames in the same order as names.
        passwords: list
            The list of hashed passwords in the same order as names.
        cookie_name: str
            The name of the JWT cookie stored on the client's browser for passwordless reauthentication.
        key: str
            The key to be used for hashing the signature of the JWT cookie.
        cookie_expiry_days: int
            The number of days before the cookie expires on the client's browser.
        Returns
        -------
        str
            Name of authenticated user.
        boolean
            The status of authentication, None: no credentials entered, False: incorrect credentials, True: correct credentials.
        """
        self.names = names
        self.usernames = usernames
        self.passwords = passwords
        self.cookie_name = cookie_name
        self.key = key
        self.cookie_expiry_days = cookie_expiry_days

    def token_encode(self):
        """
        Returns
        -------
        str
            The JWT cookie for passwordless reauthentication.
        """
        return jwt.encode({'name':st.session_state['name'],
        'username':st.session_state['username'],
        'exp_date':self.exp_date},self.key,algorithm='HS256')

    def token_decode(self):
        """
        Returns
        -------
        str
            The decoded JWT cookie for passwordless reauthentication.
        """
        return jwt.decode(self.token,self.key,algorithms=['HS256'])

    def exp_date(self):
        """
        Returns
        -------
        str
            The JWT cookie's expiry timestamp in Unix epoch.
        """
        return (datetime.utcnow() + timedelta(days=self.cookie_expiry_days)).timestamp()

    def check_pw(self):
        """
        Returns
        -------
        Boolean
            The validation state for the input password by comparing it to the hashed password on disk.
        """
        return bcrypt.checkpw(self.password.encode(),self.passwords[self.index].encode())

    def login(self,form_name,location='main'):
        """Create a new instance of "authenticate".
        Parameters
        ----------
        form_name: str
            The rendered name of the login form.
        location: str
            The location of the login form i.e. main or sidebar.
        Returns
        -------
        str
            Name of authenticated user.
        boolean
            The status of authentication, None: no credentials entered, False: incorrect credentials, True: correct credentials.
        """

        if location not in ['main','sidebar']:
            raise ValueError("Location must be one of 'main' or 'sidebar'")

        cookie_manager = stx.CookieManager()

        if 'name' not in st.session_state:
            st.session_state['name'] = None
        if 'authentication_status' not in st.session_state:
            st.session_state['authentication_status'] = None
        if 'username' not in st.session_state:
            st.session_state['username'] = None

        if st.session_state['authentication_status'] != True:
            try:
                self.token = cookie_manager.get(self.cookie_name)
                self.token = self.token_decode()

                if 'logout' not in st.session_state:
                    st.session_state['logout'] = None

                if st.session_state['logout'] != True:
                    if self.token['exp_date'] > datetime.utcnow().timestamp():
                        st.session_state['name'] = self.token['name']
                        st.session_state['authentication_status'] = True
                        st.session_state['username'] = self.token['username']
            except:
                pass

            if st.session_state['authentication_status'] != True:
                if location == 'main':
                    login_form = st.form('Login')
                elif location == 'sidebar':
                    login_form = st.sidebar.form('Login')

                login_form.subheader(form_name)
                self.username = login_form.text_input('Username')
                st.session_state['username'] = self.username
                self.password = login_form.text_input('Password',type='password')

                if login_form.form_submit_button('Login'):
                    self.index = None
                    for i in range(0,len(self.usernames)):
                        if self.usernames[i] == self.username:
                            self.index = i
                    if self.index != None:
                        try:
                            if self.check_pw():
                                st.session_state['name'] = self.names[self.index]
                                self.exp_date = self.exp_date()
                                self.token = self.token_encode()
                                cookie_manager.set(self.cookie_name, self.token,
                                expires_at=datetime.now() + timedelta(days=self.cookie_expiry_days))
                                st.session_state['authentication_status'] = True
                            else:
                                st.session_state['authentication_status'] = False
                        except Exception as e:
                            print(e)
                    else:
                        st.session_state['authentication_status'] = False

        if st.session_state['authentication_status'] == True:
            if location == 'main':
                if st.button('Logout'):
                    cookie_manager.delete(self.cookie_name)
                    st.session_state['logout'] = True
                    st.session_state['name'] = None
                    st.session_state['username'] = None
                    st.session_state['authentication_status'] = None
            elif location == 'sidebar':
                if st.sidebar.button('Logout'):
                    cookie_manager.delete(self.cookie_name)
                    st.session_state['logout'] = True
                    st.session_state['name'] = None
                    st.session_state['username'] = None
                    st.session_state['authentication_status'] = None

        return st.session_state['name'], st.session_state['authentication_status'], st.session_state['username']

if not _RELEASE:
    names = ['John Smith','Rebecca Briggs']
    usernames = ['jsmith','rbriggs']
    passwords = ['123','456']

    hashed_passwords = Hasher(passwords).generate()

    authenticator = Authenticate(names,usernames,hashed_passwords,
    'some_cookie_name','some_signature_key',cookie_expiry_days=30)
    name, authentication_status, username = authenticator.login('Login','main')

    if authentication_status:
        st.write('Welcome *%s*' % (name))
        st.title('Some content')
    elif authentication_status == False:
        st.error('Username/password is incorrect')
    elif authentication_status == None:
        st.warning('Please enter your username and password')

    # Alternatively you use st.session_state['name'] and
    # st.session_state['authentication_status'] to access the name and
    # authentication_status.

    #authenticator.login('Login','main')

    #if st.session_state['authentication_status']:
    #    st.write('Welcome *%s*' % (st.session_state['name']))
    #    st.title('Some content')
    #elif st.session_state['authentication_status'] == False:
    #    st.error('Username/password is incorrect')
    #elif st.session_state['authentication_status'] == None:
    #    st.warning('Please enter your username and password')
