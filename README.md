# Streamlit-Authenticator [![Downloads](https://pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator) 
<!--- [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/khorasani) --->
**A secure authentication module to validate user credentials in a Streamlit application.**

<a href="https://amzn.to/3eQwEEn"><img src="https://raw.githubusercontent.com/mkhorasani/streamlit_authenticator_test/main/Web%20App%20Web%20Dev%20with%20Streamlit%20-%20Cover.png" width="300" height="450"> 
 
###### _To learn more please refer to my book [Web Application Development with Streamlit](https://amzn.to/3eQwEEn)._

  
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

* Initially create a YAML configuration file and define your users' credentials (names, usernames, and plain text passwords). In addition, enter a name, random key, and number of days to expiry for a JWT cookie that will be stored on the client's browser to enable passwordless reauthentication. If you do not require reauthentication, you may set the number of days to expiry to 0. Finally, define a list of preauthorized emails of users who can register and add their credentials to the configuration file with the use of the **register_user** widget.

```python
credentials:
  usernames:
    jsmith:
      email: jsmith@gmail.com
      name: John Smith
      password: 123 # To be replaced with hashed password
    rbriggs:
      email: rbriggs@gmail.com
      name: Rebecca Briggs
      password: 456 # To be replaced with hashed password
cookie:
  expiry_days: 30
  key: some_signature_key
  name: some_cookie_name
preauthorized:
  emails:
  - melsby@gmail.com
```

* Then use the Hasher module to convert the plain text passwords into hashed passwords.

```python
hashed_passwords = stauth.Hasher(['123', '456']).generate()
```

* Finally replace the plain text passwords in the configuration file with the hashed passwords.

### 2. Creating a login widget

* Subsequently import the configuration file into your script and create an authentication object.

```python
with open('../config.yaml') as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
    config['preauthorized']
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

* Or prompt an unverified user to enter a correct username and password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/incorrect_login.PNG)

* Please note that logging out will revert the authentication status to **None** and will delete the associated reauthentication cookie as well.

### 4. Creating a password reset widget

* You may use the **reset_password** widget to allow a logged in user to modify their password as shown below.

```python
if authentication_status:
    try:
        if authenticator.reset_password(username, 'Reset password'):
            st.success('Password modified successfully')
    except Exception as e:
        st.error(e)
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/reset_password.PNG)

### 5. Creating a new user registration widget

* You may use the **register_user** widget to allow a user to sign up to your application as shown below. If you require the user to be preauthorized, set the **preauthorization** argument to True and add their email to the **preauthorized** list in the configuration file. Once they have registered, their email will be automatically removed from the **preauthorized** list in the configuration file. Alternatively, to allow anyone to sign up, set the **preauthorization** argument to False.

```python
try:
    if authenticator.register_user('Register user', preauthorization=False):
        st.success('User registered successfully')
except Exception as e:
    st.error(e)
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/register_user.PNG)

### 6. Creating a forgot password widget

* You may use the **forgot_password** widget to allow a user to generate a new random password. This password will be automatically hashed and saved in the configuration file. The widget will return the username, email, and new random password of the user which should then be transferred to them securely.

```python
try:
    username_forgot_pw, email_forgot_password, random_password = authenticator.forgot_password('Forgot password')
    if username_forgot_pw:
        st.success('New password sent securely')
        # Random password to be transferred to user securely
    elif username_forgot_pw == False:
        st.error('Username not found')
except Exception as e:
    st.error(e)
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/forgot_password.PNG)

### 7. Creating a forgot username widget

* You may use the **forgot_username** widget to allow a user to retrieve their forgotten username. The widget will return the username and email of the user which should then be transferred to them securely.

```python
try:
    username_forgot_username, email_forgot_username = authenticator.forgot_username('Forgot username')
    if username_forgot_username:
        st.success('Username sent securely')
        # Username to be transferred to user securely
    elif username_forgot_username == False:
        st.error('Email not found')
except Exception as e:
    st.error(e)
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/forgot_username.PNG)

### 8. Creating an update user details widget

* You may use the **update_user_details** widget to allow a logged in user to update their name and/or email. The widget will automatically save the updated details in both the configuration file and reauthentication cookie.

```python
if authentication_status:
    try:
        if authenticator.update_user_details(username, 'Update user details'):
            st.success('Entries updated successfully')
    except Exception as e:
        st.error(e)
```

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/update_user_details.PNG)

### 9. Updating the configuration file

* Please ensure that the configuration file is resaved anytime the credentials are updated or whenever the **reset_password**, **register_user**, **forgot_password**, or **update_user_details** widgets are used.

```python
with open('../config.yaml', 'w') as file:
    yaml.dump(config, file, default_flow_style=False)
```

## Credits
- Mohamed Abdou for the highly versatile cookie manager in [Extra-Streamlit-Components](https://github.com/Mohamed-512/Extra-Streamlit-Components).
