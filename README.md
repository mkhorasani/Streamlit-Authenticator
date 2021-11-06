# Streamlit-Authenticator
A secure authenticaton module to validate users' credentials in your Streamlit application.

## Installation

Streamlit-Authenticator is distributed via [PyPI](https://pypi.org/project/streamlit-authenticator/):

```python
pip install streamlit-authenticator
```

## Example

Using streamlit-authenticator is as simple as importing the module and using it to verify your predefined users' credentials.

```python
import streamlit as st
import streamlit_authenticator as stauth
```

Initially define your users' names, usernames, and plain text passwords.

```python
names = ['John Smith','Rebecca Briggs']
usernames = ['jsmith','rbriggs']
passwords = ['123','456']
```

Then use the hasher module to convert the plain text passwords to hashed passwords.

```python
hashed_passwords = stauth.hasher(passwords).generate()
```

Subsequently use the hashed passwords to create an authentication object.

```python
authenticator = stauth.authenticate(names,usernames,hashed_passwords,'some_cookie_name','some_signature_key',cookie_expiry_days=30)
```

Then finally render the login module as follows.

```python
name, authentication_status = authenticator.login('Login','main')
```

You can then use the returned name and authentication status to allow your verified user to proceed to any restricted content, or to prompt the user to enter a correct username and password.

```python
if authentication_status:
    st.write('Welcome *%s*' % (name))
elif authentication_status == False:
    st.error('Username/password is incorrect')
elif authentication_status == None:
    st.warning('Please enter your username and password')
```
