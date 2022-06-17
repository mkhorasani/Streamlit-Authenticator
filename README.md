# Streamlit-Authenticator [![Downloads](https://pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator) [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/khorasani)
A secure authentication module to validate user credentials in a Streamlit application.

## Installation

Streamlit-Authenticator is distributed via [PyPI](https://pypi.org/project/streamlit-authenticator/):

```python
pip install streamlit-authenticator
```

## Example

Using Streamlit-Authenticator is as simple as importing the module and calling it to verify your predefined users' credentials.

```python
import streamlit as st
import streamlit_authenticator as stauth
```

### 1. Hashing passwords

* Initially create a YAML configuration file and define your users' credentials (names, usernames, and plain text passwords). In addition, enter a name, random key, and number of days to expiry for a JWT cookie that will be stored on the client's browser to enable passwordless reauthentication. If you do not require reauthentication, you may set the number of days to expiry to 0.

```python
credentials:
  names: ['John Smith', 'Rebecca Briggs']
  usernames: ['jsmith', 'rbriggs']
  passwords: ['123', '456'] # To be replaced with hashed passwords
cookie:
  name: 'some_cookie_name'
  key: 'some_signature_key'
  expiry_days: 30
```

* Then use the Hasher module to convert the plain text passwords into hashed passwords.

```python
hashed_passwords = stauth.Hasher(['123', '456']).generate()
```

* Finally replace the plain text passwords in the configuration file with the hashed passwords.

### 2. Creating login widget

* Subsequently import the configuration file into your script and create an authentication object.

```python
with open('../config.yaml') as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config['credentials']['names'],
    config['credentials']['usernames'],
    config['credentials']['passwords'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days']
)
```

* Then finally render the login module as follows. Here you will need to provide a name for the login form, and specify where the form should be located i.e. main body or sidebar (will default to main body).

```python
name, authentication_status, username = authenticator.login('Login', 'main')
```
![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/login_form.PNG)

### 3. Authenticating users

* You can then use the returned name and authentication status to allow your verified user to proceed to any restricted content. In addition, you have the ability to add an optional logout button at any location on your main body or sidebar (will default to main body).

```python
if authentication_status:
    authenticator.logout('Logout', 'main')
    st.write(f'Welcome *{name}*')
    st.title('Some content')
elif authentication_status == False:
    st.error('Username/password is incorrect')
elif authentication_status == None:
    st.warning('Please enter your username and password')
```

* Should you require access to the persistent name, authentication status, and username variables, you may retrieve them through Streamlit's session state using **st.session_state["name"]**, **st.session_state["authentication_status"]**, and **st.session_state["username"]**. This way you can use Streamlit-Authenticator to authenticate users across multiple pages.

```python
if st.session_state["authentication_status"]:
    authenticator.logout('Logout', 'main')
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state["authentication_status"] == False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] == None:
    st.warning('Please enter your username and password')
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/logged_in.PNG)

Or prompt an unverified user to enter a correct username and password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/incorrect_login.PNG)

Please note that logging out will revert the authentication status to **None** and will delete the associated reauthentication cookie as well.

## Credits
- Mohamed Abdou for the highly versatile cookie manager in [Extra-Streamlit-Components](https://github.com/Mohamed-512/Extra-Streamlit-Components).
