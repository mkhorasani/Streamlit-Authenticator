import yaml
import streamlit as st
from yaml.loader import SafeLoader
import streamlit.components.v1 as components

from .hasher import Hasher
from .authenticate import Authenticate

_RELEASE = True

if not _RELEASE:
    # hashed_passwords = Hasher(['123', '456']).generate()

    # Loading config file
    with open('../config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    # Creating the authenticator object
    authenticator = Authenticate(
        config['credentials'],
        config['cookie']['name'], 
        config['cookie']['key'], 
        config['cookie']['expiry_days'],
        config['preauthorized']
    )

    # creating a login widget
    name, authentication_status, username = authenticator.login('Login', 'main')
    if authentication_status:
        authenticator.logout('Logout', 'main')
        st.write(f'Welcome *{name}*')
        st.title('Some content')
    elif authentication_status == False:
        st.error('Username/password is incorrect')
    elif authentication_status == None:
        st.warning('Please enter your username and password')

    # Creating a password reset widget
    if authentication_status:
        try:
            if authenticator.reset_password(username, 'Reset password'):
                st.success('Password modified successfully')
        except Exception as e:
            st.error(e)

    # Creating a new user registration widget
    try:
        if authenticator.register_user('Register user', preauthorization=False):
            st.success('User registered successfully')
    except Exception as e:
        st.error(e)

    # Creating a forgot password widget
    try:
        username_forgot_pw, email_forgot_password, random_password = authenticator.forgot_password('Forgot password')
        if username_forgot_pw:
            st.success('New password sent securely')
            # Random password to be transferred to user securely
        elif username_forgot_pw == False:
            st.error('Username not found')
    except Exception as e:
        st.error(e)

    # Creating a forgot username widget
    try:
        username_forgot_username, email_forgot_username = authenticator.forgot_username('Forgot username')
        if username_forgot_username:
            st.success('Username sent securely')
            # Username to be transferred to user securely
        elif username_forgot_username == False:
            st.error('Email not found')
    except Exception as e:
        st.error(e)

    # Creating an update user details widget
    if authentication_status:
        try:
            if authenticator.update_user_details(username, 'Update user details'):
                st.success('Entries updated successfully')
        except Exception as e:
            st.error(e)

    # Saving config file
    with open('../config.yaml', 'w') as file:
        yaml.dump(config, file, default_flow_style=False)

    # Alternatively you may use st.session_state['name'], st.session_state['authentication_status'], 
    # and st.session_state['username'] to access the name, authentication_status, and username. 

    # if st.session_state['authentication_status']:
    #     authenticator.logout('Logout', 'main')
    #     st.write(f'Welcome *{st.session_state["name"]}*')
    #     st.title('Some content')
    # elif st.session_state['authentication_status'] == False:
    #     st.error('Username/password is incorrect')
    # elif st.session_state['authentication_status'] == None:
    #     st.warning('Please enter your username and password')
