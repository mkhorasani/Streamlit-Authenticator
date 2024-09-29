"""
Script description: This script imports the main module of this library
and also provides unit testing commands for development. 

Libraries imported:
- yaml: Module implementing the data serialization used for human readable documents.
- streamlit: Framework used to build pure Python web applications.
"""

import yaml
import streamlit as st
import streamlit.components.v1 as components
from yaml.loader import SafeLoader

from .views import Authenticate
from .utilities import (CredentialsError,
                        ForgotError,
                        Hasher,
                        LoginError,
                        RegisterError,
                        ResetError,
                        UpdateError)

_RELEASE = True

if not _RELEASE:
    # Loading config file
    with open('../config.yaml', 'r', encoding='utf-8') as file:
        config = yaml.load(file, Loader=SafeLoader)

    # Pre-hashing all plain text passwords once
    # Hasher.hash_passwords(config['credentials'])

    # Creating the authenticator object
    authenticator = Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days']
    )

    # authenticator = Authenticate(
    #     '../config.yaml'
    # )

    # Creating a login widget
    try:
        authenticator.login()
    except LoginError as e:
        st.error(e)

    # Creating a guest login button
    try:
        authenticator.experimental_guest_login('Login with Google', provider='google',
                                               oauth2=config['oauth2'])
        authenticator.experimental_guest_login('Login with Microsoft', provider='microsoft',
                                               oauth2=config['oauth2'])
    except LoginError as e:
        st.error(e)

    # Authenticating user
    if st.session_state['authentication_status']:
        authenticator.logout()
        st.write(f'Welcome *{st.session_state["name"]}*')
        st.title('Some content')
    elif st.session_state['authentication_status'] is False:
        st.error('Username/password is incorrect')
    elif st.session_state['authentication_status'] is None:
        st.warning('Please enter your username and password')

    # Creating a password reset widget
    if st.session_state['authentication_status']:
        try:
            if authenticator.reset_password(st.session_state['username']):
                st.success('Password modified successfully')
        except (CredentialsError, ResetError) as e:
            st.error(e)

    # Creating a new user registration widget
    try:
        (email_of_registered_user,
         username_of_registered_user,
         name_of_registered_user) = authenticator.register_user()
        if email_of_registered_user:
            st.success('User registered successfully')
    except RegisterError as e:
        st.error(e)

    # Creating a forgot password widget
    try:
        (username_of_forgotten_password,
         email_of_forgotten_password,
         new_random_password) = authenticator.forgot_password()
        if username_of_forgotten_password:
            st.success('New password sent securely')
            # Random password to be transferred to the user securely
        elif not username_of_forgotten_password:
            st.error('Username not found')
    except ForgotError as e:
        st.error(e)

    # Creating a forgot username widget
    try:
        (username_of_forgotten_username,
         email_of_forgotten_username) = authenticator.forgot_username()
        if username_of_forgotten_username:
            st.success('Username sent securely')
            # Username to be transferred to the user securely
        elif not username_of_forgotten_username:
            st.error('Email not found')
    except ForgotError as e:
        st.error(e)

    # Creating an update user details widget
    if st.session_state['authentication_status']:
        try:
            if authenticator.update_user_details(st.session_state['username']):
                st.success('Entry updated successfully')
        except UpdateError as e:
            st.error(e)

    # Saving config file
    with open('../config.yaml', 'w', encoding='utf-8') as file:
        yaml.dump(config, file, default_flow_style=False)
