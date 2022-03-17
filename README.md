# Streamlit-Authenticator [![Downloads](https://pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator) [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/khorasani)
A secure authentication module to validate user credentials in a Streamlit application.

## Installation

Streamlit-Authenticator is distributed via [PyPI](https://pypi.org/project/streamlit-authenticator/):

```python
pip install streamlit-authenticator
```

## Example

Using Streamlit-Authenticator is as simple as importing the module and using it to verify your predefined users' credentials.

```python
import streamlit as st
import streamlit_authenticator as stauth
```

* Initially define your users' names, usernames, and plain text passwords.

```python
names = ['John Smith','Rebecca Briggs']
usernames = ['jsmith','rbriggs']
passwords = ['123','456']
```

* Then use the hasher module to convert the plain text passwords to hashed passwords, and remove all plain text passwords from your source code.

```python
hashed_passwords = stauth.Hasher(passwords).generate()
```

* Subsequently use the hashed passwords to create an authentication object. Here you will need to enter a name for the JWT cookie that will be stored on the client's browser and used to reauthenticate the user without re-entering their credentials. In addition, you will need to provide any random key to be used to hash the cookie's signature. Finally, you will need to specify the number of days to use the cookie for, if you do not require passwordless reauthentication, you may set this to 0.

```python
authenticator = stauth.Authenticate(names,usernames,hashed_passwords,
    'some_cookie_name','some_signature_key',cookie_expiry_days=30)
```

* Then finally render the login module as follows. Here you will need to provide a name for the login form, and specify where the form should be located i.e. main body or sidebar (will default to main body).

```python
name, authentication_status, username = authenticator.login('Login','main')
```
![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/login_form.PNG)

* You can then use the returned name and authentication status to allow your verified user to proceed to any restricted content.

```python
if authentication_status:
    st.write('Welcome *%s*' % (name))
    st.title('Some content')
elif authentication_status == False:
    st.error('Username/password is incorrect')
elif authentication_status == None:
    st.warning('Please enter your username and password')
```

* Should you require access to the persistent name and authentication status variables, you may retrieve them through Streamlit's session state using **st.session_state['name']** and **st.session_state['authentication_status']**. This way you can use Streamlit-Authenticator to authenticate users across multiple pages.

```python
if st.session_state['authentication_status']:
    st.write('Welcome *%s*' % (st.session_state['name']))
    st.title('Some content')
elif st.session_state['authentication_status'] == False:
    st.error('Username/password is incorrect')
elif st.session_state['authentication_status'] == None:
    st.warning('Please enter your username and password')
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/logged_in.PNG)

Or prompt an unverified user to enter a correct username and password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/incorrect_login.PNG)

Please note that logging out will revert the authentication status to **None** and will delete the associated reauthentication cookie as well.

## Credits
- Mohamed Abdou for the highly versatile cookie manager in [Extra-Streamlit-Components](https://github.com/Mohamed-512/Extra-Streamlit-Components). 
