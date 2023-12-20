<img src="https://raw.githubusercontent.com/mkhorasani/Streamlit-Authenticator/main/graphics/logo.png" alt="Streamlit Authenticator logo" style="margin-top:50px;width:450px"></img>

**User login and authentication for Streamlit apps**
<br/><br/><br/>
<a href="https://amzn.to/3eQwEEn"><img src="https://raw.githubusercontent.com/mkhorasani/streamlit_authenticator_test/main/Web%20App%20Web%20Dev%20with%20Streamlit%20-%20Cover.png" width="300" height="450">

###### _To learn more please refer to my book [Web Application Development with Streamlit](https://amzn.to/3eQwEEn)._


## Installation

Streamlit-Authenticator is distributed via [PyPI](https://pypi.org/project/streamlit-authenticator/):

```python
pip install streamlit-authenticator
```

## Example

Using Streamlit-Authenticator is as simple as importing the module and calling it to verify your
predefined users' credentials.

```python
import streamlit as st
import streamlit_authenticator_test as stauth
```

Then create an authentication object. This is the base class and will be used to create all the
widgets.

```python
authenticator = stauth.Authenticate(
    credentials, name, key, expiry_days, preauthorized
)
```

### 1. Creating a new user registration widget

* You may use the **register_user** widget to allow a user to sign up to your application as 
  shown below. If you require the user to be preauthorized, set the **preauthorization** 
  argument to True and add their email to the **preauthorized** list. Once they have registered, 
  their email will be automatically removed from the **preauthorized** list and you will need to 
  resave this list. Alternatively, to allow anyone to sign up, set the **preauthorization** 
  argument to False. The password entered here will be automatically hashed. 

```python
try:
    if authenticator.register_user('Register user', preauthorization=False):
        st.success('User registered successfully')
except Exception as e:
    st.error(e)
```

_Please remember to update your preauthorized list after you use this widget._

### 2. Creating a login widget

* Render the login module as follows. Here you will need to provide a name for the login form, 
  and specify where the form should be located i.e. main body or sidebar
  (will default to main body).

```python
authenticator.login('Login', 'main')
```

_Please remember to save the updated login info after you use this widget._

### 3. Creating a forgot username widget

* You may use the **forgot_username** widget to allow a user to retrieve their forgotten username.
  The widget will return the username and email of the user which should then be transferred to 
  them securely.

```python
try:
    username_of_forgotten_username, email_of_forgotten_username = authenticator.forgot_username('Forgot username')
    if username_of_forgotten_username:
        st.success('Username to be sent securely')
        # Username should be transferred to user securely
    else:
        st.error('Email not found')
except Exception as e:
    st.error(e)
```

_Please remember to save the updated username after you use this widget._

### 4. Creating a forgot password widget

* You may use the **forgot_password** widget to allow a user to generate a new random password.
  This password will be automatically hashed. The widget will return the username, email, and 
  new random password of the user which should then be transferred to them securely.

```python
try:
    username_of_forgotten_password, email_of_forgotten_password, new_random_password = authenticator.forgot_password('Forgot password')
    if username_of_forgotten_password:
        st.success('New password to be sent securely')
        # Random password should be transferred to user securely
    else:
        st.error('Username not found')
except Exception as e:
    st.error(e)
```

_Please remember to save the updated password after you use this widget._

### 5. Creating a password reset widget

* You may use the **reset_password** widget to allow a logged in user to modify their password
  as shown below. This password will be automatically hashed.

```python
if st.session_state["authentication_status"]:
    try:
        if authenticator.reset_password(st.session_state["username"], 'Reset password'):
            st.success('Password modified successfully')
    except Exception as e:
        st.error(e)
```

_Please remember to save the new password after you use this widget._

### 6. Creating an update user details widget

* You may use the **update_user_details** widget to allow a logged in user to update their name
  and/or email. The widget will automatically save the updated details in both the configuration 
  file and reauthentication cookie.

```python
if st.session_state["authentication_status"]:
    try:
        if authenticator.update_user_details(st.session_state["username"], 'Update user details'):
            st.success('Entries updated successfully')
    except Exception as e:
        st.error(e)
```

_Please remember to save the changes after you use this widget._

### 7. Logging out

* You may use the **logout** widget to allow a logged in user to log out of your application.
  This will revert the authentication status to **None** and will delete the associated 
  reauthentication cookie as well.

```python
authenticator.logout('Logout', 'main', key='unique_key')
```

### 8. Hashing passwords

* Independently from the Authenticator class, you can use the Hasher module to convert the 
  plain text passwords into hashed passwords. This is done automatically when you use the
  **register_user**, **forgot_password** and **reset_password** widgets. However, if you would 
  like to hash the passwords manually, you can do so as follows.

```python
hashed_passwords = stauth.Hasher(['abc', 'def']).generate()
```

### 9. Authenticating users

* You can retrieve the name, authentication status, and username from Streamlit's session state
  using **st.session_state["name"]**, **st.session_state["authentication_status"]**, and **st.
  session_state["username"]** to allow a verified user to proceed to any restricted content.

```python
if st.session_state["authentication_status"]:
    authenticator.logout('Logout', 'main', key='unique_key')
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please enter your username and password')
```


## Credits
- Mohamed Abdou for the highly versatile cookie manager in [Extra-Streamlit-Components](https://github.com/Mohamed-512/Extra-Streamlit-Components).
