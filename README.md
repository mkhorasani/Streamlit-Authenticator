<img src="https://raw.githubusercontent.com/mkhorasani/Streamlit-Authenticator/main/graphics/logo.png" alt="Streamlit Authenticator logo" style="margin-top:50px;width:450px"></img>
<!--- [![Downloads](https://pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator) --->
<!--- [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/khorasani) --->

**A secure authentication module to manage user access in a Streamlit application**

[![Downloads](https://static.pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator)
[![Downloads](https://static.pepy.tech/badge/streamlit-authenticator/month)](https://pepy.tech/project/streamlit-authenticator)
[![Downloads](https://static.pepy.tech/badge/streamlit-authenticator/week)](https://pepy.tech/project/streamlit-authenticator)
<!--- <br/><br/><br/> ---?
<!--- <a href="http://tinyurl.com/2p8mw32d"><img src="https://raw.githubusercontent.com/mkhorasani/streamlit_authenticator_test/main/Web%20App%20Web%20Dev%20with%20Streamlit%20-%20Cover.png" width="300" height="450"> --->

<!--- ###### _To learn more please refer to my book [Web Application Development with Streamlit](http://tinyurl.com/2p8mw32d)._ --->

## Table of Contents
- [Quickstart](#1-quickstart)
- [Installation](#2-installation)
- [Creating a config file](#3-creating-a-config-file)
- [Setup](#4-setup)
- [Creating a login widget](#5-creating-a-login-widget)
- [Creating a guest login button](#6-creating-a-guest-login-button) 🚀 **NEW**
- [Authenticating users](#7-authenticating-users)
- [Creating a reset password widget](#8-creating-a-reset-password-widget)
- [Creating a new user registration widget](#9-creating-a-new-user-registration-widget)
- [Creating a forgot password widget](#10-creating-a-forgot-password-widget)
- [Creating a forgot username widget](#11-creating-a-forgot-username-widget)
- [Creating an update user details widget](#12-creating-an-update-user-details-widget)
- [Updating the config file](#13-updating-the-config-file)
- [License](#license)

### 1. Quickstart

* Check out the [demo app](https://demo-app-v0-3-3.streamlit.app/).
* Feel free to visit the [API reference](https://streamlit-authenticator.readthedocs.io/en/stable/).
* And finally follow the tutorial below.

### 2. Installation

Streamlit-Authenticator is distributed via [PyPI](https://pypi.org/project/streamlit-authenticator/):

```python
pip install streamlit-authenticator
```

Using Streamlit-Authenticator is as simple as importing the module and calling it to verify your user's credentials.

```python
import streamlit as st
import streamlit_authenticator as stauth
```

### 3. Creating a config file

* Create a YAML config file and add to it your user's credentials: including username, email, first name, last name, and password (plain text passwords will be hashed automatically).
* Enter a name, random key, and number of days to expiry, for a re-authentication cookie that will be stored on the client's browser to enable password-less re-authentication. If you do not require re-authentication, you may set the number of days to expiry to 0.
* Define an optional list of pre-authorized emails of users who are allowed to register and add their credentials to the config file using the **register_user** widget.
* Add the optional configuration parameters for OAuth2 if you wish to use the **experimental_guest_login** button.
* **_Please remember to update the config file (as shown in step 13) after you use the reset_password, register_user, forgot_password, or update_user_details widgets._**

```python
cookie:
  expiry_days: 30
  key: some_signature_key # Must be a string
  name: some_cookie_name
credentials:
  usernames:
    jsmith:
      email: jsmith@gmail.com
      failed_login_attempts: 0 # Will be managed automatically
      first_name: John
      last_name: Smith
      logged_in: False # Will be managed automatically
      password: abc # Will be hashed automatically
      roles: # Optional
      - admin
      - editor
      - viewer
    rbriggs:
      email: rbriggs@gmail.com
      failed_login_attempts: 0 # Will be managed automatically
      first_name: Rebecca
      last_name: Briggs
      logged_in: False # Will be managed automatically
      password: def # Will be hashed automatically
      roles: # Optional
      - viewer
oauth2: # Optional
  google: # Follow instructions: https://developers.google.com/identity/protocols/oauth2
    client_id: # To be filled
    client_secret: # To be filled
    redirect_uri: # URL to redirect to after OAuth2 authentication
  microsoft: # Follow instructions: https://learn.microsoft.com/en-us/graph/auth-register-app-v2
    client_id: # To be filled
    client_secret: # To be filled
    redirect_uri: # URL to redirect to after OAuth2 authentication
    tenant_id: # To be filled
pre-authorized: # Optional
  emails:
  - melsby@gmail.com
```

* _Please note that the 'failed_login_attempts' and 'logged_in' fields corresponding to each user's number of failed login attempts and log-in status in the credentials will be added and managed automatically._

### 4. Setup

* Subsequently import the config file into your script and create an authentication object.

```python
import yaml
from yaml.loader import SafeLoader

with open('../config.yaml') as file:
    config = yaml.load(file, Loader=SafeLoader)

# Pre-hashing all plain text passwords once
# stauth.Hasher.hash_passwords(config['credentials'])

authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days']
)
```

* Plain text passwords will be hashed automatically by default, however, for a large number of users it is recommended to pre-hash the passwords in the credentials using the **Hasher.hash_passwords** function.
* If you choose to pre-hash the passwords, please set the **auto_hash** parameter in the **Authenticate** class to False.

> ### Hasher.hash_passwords
> #### Parameters:
>  - **credentials:** _dict_
>    - The credentials dict with plain text passwords.
> #### Returns:
> - _dict_
>   - The credentials dict with hashed passwords.

> ### Authenticate
> #### Parameters:
>  - **credentials:** _dict, str_
>    - Dictionary with the usernames, names, passwords, and emails, and other user data, or path pointing to the location of the config file.
>  - **cookie_name:** _str_
>    - Specifies the name of the re-authentication cookie stored on the client's browser for password-less re-authentication.
>  - **cookie_key:** _str_
>    - Specifies the key that will be used to hash the signature of the re-authentication cookie.
>  - **cookie_expiry_days:** _float, default 30.0_
>    - Specifies the number of days before the re-authentication cookie automatically expires on the client's browser.
>  - **validator:** _Validator, optional, default None_
>    - Provides a validator object that will check the validity of the username, name, and email fields.
>  - **auto_hash:** _bool, default True_
>    - Automatic hashing requirement for passwords, True: plain text passwords will be hashed automatically, False: plain text passwords will not be hashed automatically.
>  - ****kwargs:** _dict, optional_
>    - Arguments to pass to the Authenticate class.

* **_Please remember to pass the authenticator object to each and every page in a multi-page application as a session state variable._**

### 5. Creating a login widget

* You can render the **login** widget as follows.

```python
try:
    authenticator.login()
except LoginError as e:
    st.error(e)
```

> ### Authenticate.login
> #### Parameters:
>  - **location:** _str, {'main', 'sidebar', 'unrendered'}, default 'main'_
>    - Specifies the location of the login widget.
>  - **max_concurrent_users:** _int, optional, default None_
>    - Limits the number of concurrent users. If not specified there will be no limit to the number of concurrently logged in users.
>  - **max_login_attempts:** _int, optional, default None_
>    - Limits the number of failed login attempts. If not specified there will be no limit to the number of failed login attempts.
>  - **fields:** _dict, optional, default {'Form name':'Login', 'Username':'Username', 'Password':'Password', 'Login':'Login', 'Captcha':'Captcha'}_
>    - Customizes the text of headers, buttons and other fields.
>  - **captcha:** _bool, default False_
>    - Specifies the captcha requirement for the login widget, True: captcha required, False: captcha removed.
>  - **single_session:** _bool, default False_
>    - Disables the ability for the same user to log in multiple sessions, True: single session allowed, False: multiple sessions allowed.
>  - **clear_on_submit:** _bool, default False_
>    - Specifies the clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
>  - **key:** _str, default 'Login'_
>    - Unique key provided to widget to avoid duplicate WidgetID errors.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/login_form.JPG)

* **_Please remember to re-invoke an 'unrendered' login widget on each and every page in a multi-page application._**

### 6. Creating a guest login button

* You may use the **experimental_guest_login** button to log in non-registered users with their Google or Microsoft accounts using OAuth2.
* To create the client ID and client secret parameters for Google OAuth2 please refer to [Google's documentation](https://developers.google.com/identity/protocols/oauth2).
* To create the client ID, client secret, and tenant ID parameters for Microsoft OAuth2 please refer to [Microsoft's documentation](https://learn.microsoft.com/en-us/graph/auth-register-app-v2).
* Once you have created the OAuth2 configuration parameters, add them to the config file as shown in step 3.

```python
try:
    authenticator.experimental_guest_login('Login with Google',
                                           provider='google',
                                           oauth2=config['oauth2'])
    authenticator.experimental_guest_login('Login with Microsoft',
                                           provider='microsoft',
                                           oauth2=config['oauth2'])
except LoginError as e:
    st.error(e)
```

> ### Authenticate.experimental_guest_login
> #### Parameters:
>  - **button_name:** _str, default 'Guest login'_
>    - Rendered name of the guest login button.
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the guest login button.
>  - **provider:** _str, {'google', 'microsoft'}, default 'google'_
>    - Selection for OAuth2 provider, Google or Microsoft.
>  - **oauth2:** _dict, optional, default None_
>    - Configuration parameters to implement an OAuth2 authentication.
>  - **max_concurrent_users:** _int, optional, default None_
>    - Limits the number of concurrent users. If not specified there will be no limit to the number of concurrently logged in users.
>  - **single_session:** _bool, default False_
>    - Disables the ability for the same user to log in multiple sessions, True: single session allowed, False: multiple sessions allowed.
>  - **roles:** _list, optional, default None_
>    - User roles for guest users.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on button press with a dict as a parameter.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/guest_login_buttons.JPG)

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/guest_login_google.JPG)

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/guest_login_microsoft.JPG)

* Please note that upon successful login, the guest user's name, email, and other information will be registered in the credentials dictionary and their re-authentication cookie will be saved automatically.

### 7. Authenticating users

* You can then retrieve the name, authentication status, and username from Streamlit's session state using **st.session_state['name']**, **st.session_state['authentication_status']**, **st.session_state['username']**, and **st.session_state['roles']** to allow a verified user to access restricted content.
* You may also render a logout button, or may choose not to render the button if you only need to implement the logout logic programmatically.
* The optional **key** parameter for the logout button should be used with multi-page applications to prevent Streamlit from throwing duplicate key errors.

```python
if st.session_state['authentication_status']:
    authenticator.logout()
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state['authentication_status'] is False:
    st.error('Username/password is incorrect')
elif st.session_state['authentication_status'] is None:
    st.warning('Please enter your username and password')
```

> ### Authenticate.logout
> #### Parameters:
>  - **button_name:** _str, default 'Logout'_
>    - Customizes the button name.
>  - **location:** _str, {'main', 'sidebar', 'unrendered'}, default 'main'_
>    - Specifies the location of the logout button. If 'unrendered' is passed, the logout logic will be executed without rendering the button.
>  - **key:** _str, default None_
>    - Unique key that should be used in multi-page applications.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/logged_in.JPG)

* Or prompt an unverified user to enter a correct username and password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/incorrect_login.JPG)

* You may also retrieve the number of failed login attempts a user has made by accessing **st.session_state['failed_login_attempts']** which returns a dictionary with the username as key and the number of failed attempts as the value.

### 8. Creating a reset password widget

* You may use the **reset_password** widget to allow a logged in user to modify their password as shown below.

```python
if st.session_state['authentication_status']:
    try:
        if authenticator.reset_password(st.session_state['username']):
            st.success('Password modified successfully')
    except Exception as e:
        st.error(e)
```

> ### Authenticate.reset_password
> #### Parameters:
>  - **username:** _str_
>    - Specifies the username of the user to reset the password for.
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the reset password widget.
>  - **fields:** _dict, optional, default {'Form name':'Reset password', 'Current password':'Current password', 'New password':'New password', 'Repeat password': 'Repeat password', 'Reset':'Reset'}_
>    - Customizes the text of headers, buttons and other fields.
>  - **clear_on_submit:** _bool, default False_
>    - Specifies the clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
>  - **key:** _str, default 'Reset password'_
>    - Unique key provided to widget to avoid duplicate WidgetID errors.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.
> #### Returns::
> - _bool_
>   - Status of resetting the password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/reset_password.JPG)

* **_Please remember to update the config file (as shown in step 13) after you use this widget._**

### 9. Creating a new user registration widget

* You may use the **register_user** widget to allow a user to sign up to your application as shown below.
* If you require the user to be pre-authorized, define a **pre_authorized** list of emails that are allowed to register, and add it to the config file or provide it as a parameter to the **register_user** widget.
* Once they have registered, their email will be automatically removed from the **pre_authorized** list.
* Alternatively, to allow anyone to sign up, do not provide a **pre_authorized** list.

```python
try:
    email_of_registered_user, \
    username_of_registered_user, \
    name_of_registered_user = authenticator.register_user(pre_authorized=config['pre-authorized'])
    if email_of_registered_user:
        st.success('User registered successfully')
except Exception as e:
    st.error(e)
```

> ### Authenticate.register_user
> #### Parameters:
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the register user widget.
>  - **pre_authorized:** _list, optional, default None_
>    - List of emails of unregistered users who are authorized to register. If no list is provided, all users will be allowed to register.
>  - **domains:** _list, optional, default None_
>    - Specifies the required list of domains a new email must belong to i.e. ['gmail.com', 'yahoo.com'], list: the required list of domains, None: any domain is allowed.
>  - **fields:** _dict, optional, default {'Form name':'Register user', 'Email':'Email', 'Username':'Username', 'Password':'Password', 'Repeat password':'Repeat password', 'Password hint':'Password hint', 'Captcha':'Captcha', 'Register':'Register'}_
>    - Customizes the text of headers, buttons and other fields.
>  - **captcha:** _bool, default True_
>    - Specifies the captcha requirement for the register user widget, True: captcha required, False: captcha removed.
>  - **roles:** _list, optional, default None_
>    - User roles for registered users.
>  - **merge_username_email:** _bool, default False_
>    - Merges username into email field, True: username will be the same as the email, False: username and email will be independent.
>  - **clear_on_submit:** _bool, default False_
>    - Specifies the clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
>  - **key:** _str, default 'Register user'_
>    - Unique key provided to widget to avoid duplicate WidgetID errors.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.
> #### Returns:
> - _str_
>   - Email associated with the new user.
> - _str_
>   - Username associated with the new user.
> - _str_
>   - Name associated with the new user.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/register_user.JPG)

* **_Please remember to update the config file (as shown in step 13) after you use this widget._**

### 10. Creating a forgot password widget

* You may use the **forgot_password** widget to allow a user to generate a new random password.
* The new password will be automatically hashed and saved in the credentials dictionary.
* The widget will return the username, email, and new random password which the developer should then transfer to the user securely.

```python
try:
    username_of_forgotten_password, \
    email_of_forgotten_password, \
    new_random_password = authenticator.forgot_password()
    if username_of_forgotten_password:
        st.success('New password to be sent securely')
        # The developer should securely transfer the new password to the user.
    elif username_of_forgotten_password == False:
        st.error('Username not found')
except Exception as e:
    st.error(e)
```

> ### Authenticate.forgot_password
> #### Parameters
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the forgot password widget.
>  - **fields:** _dict, optional, default {'Form name':'Forgot password', 'Username':'Username',  'Captcha':'Captcha', 'Submit':'Submit'}_
>    - Customizes the text of headers, buttons and other fields.
>  - **captcha:** _bool, default False_
>    - Specifies the captcha requirement for the forgot password widget, True: captcha required, False: captcha removed.
>  - **clear_on_submit:** _bool, default False_
>    - Specifies the clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
>  - **key:** _str, default 'Forgot password'_
>    - Unique key provided to widget to avoid duplicate WidgetID errors.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.
> #### Returns:
> - _str_
>   - Username associated with the forgotten password.
> - _str_
>   - Email associated with the forgotten password.
> - _str_
>   - New plain text password that should be transferred to the user securely.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/forgot_password.JPG)

* **_Please remember to update the config file (as shown in step 13) after you use this widget._**

### 11. Creating a forgot username widget

* You may use the **forgot_username** widget to allow a user to retrieve their forgotten username.
* The widget will return the username and email which the developer should then transfer to the user securely.

```python
try:
    username_of_forgotten_username, \
    email_of_forgotten_username = authenticator.forgot_username()
    if username_of_forgotten_username:
        st.success('Username to be sent securely')
        # The developer should securely transfer the username to the user.
    elif username_of_forgotten_username == False:
        st.error('Email not found')
except Exception as e:
    st.error(e)
```

> ### Authenticate.forgot_username
> #### Parameters
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the forgot username widget.
>  - **fields:** _dict, optional, default {'Form name':'Forgot username', 'Email':'Email', 'Captcha':'Captcha', 'Submit':'Submit'}_
>    - Customizes the text of headers, buttons and other fields.
>  - **captcha:** _bool, default False_
>    - Specifies the captcha requirement for the forgot username widget, True: captcha required, False: captcha removed.
>  - **clear_on_submit:** _bool, default False_
>    - Specifies the clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
>  - **key:** _str, default 'Forgot username'_
>    - Unique key provided to widget to avoid duplicate WidgetID errors.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.
> #### Returns:
> - _str_
>   - Forgotten username that should be transferred to the user securely.
> - _str_
>   - Email associated with the forgotten username.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/forgot_username.JPG)

### 12. Creating an update user details widget

* You may use the **update_user_details** widget to allow a logged in user to update their name and/or email.
* The widget will automatically save the updated details in both the credentials dictionary and re-authentication cookie.

```python
if st.session_state['authentication_status']:
    try:
        if authenticator.update_user_details(st.session_state['username']):
            st.success('Entries updated successfully')
    except Exception as e:
        st.error(e)
```

> ### Authenticate.update_user_details
> #### Parameters
>  - **username:** _str_
>    - Specifies the username of the user to update user details for.
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the update user details widget.
>  - **fields:** _dict, optional, default {'Form name':'Update user details', 'Field':'Field', 'First name':'First name', 'Last name':'Last name', 'Email':'Email', 'New value':'New value', 'Update':'Update'}_
>    - Customizes the text of headers, buttons and other fields.
>  - **clear_on_submit:** _bool, default False_
>    - Specifies the clear on submit setting, True: clears inputs on submit, False: keeps inputs on submit.
>  - **key:** _str, default 'Update user details'_
>    - Unique key provided to widget to avoid duplicate WidgetID errors.
>  - **callback:** _callable, optional, default None_
>    - Callback function that will be invoked on form submission with a dict as a parameter.
> #### Returns:
> - _bool_
>   - Status of updating the user details.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/update_user_details.JPG)

* **_Please remember to update the config file (as shown in step 13) after you use this widget._**

### 13. Updating the config file

* Please ensure that the config file is re-saved anytime the credentials are updated or whenever the **reset_password**, **register_user**, **forgot_password**, or **update_user_details** widgets are used.

```python
with open('../config.yaml', 'w') as file:
    yaml.dump(config, file, default_flow_style=False)
```

## License

This project is proprietary software. The use of this software is governed by the terms specified in the [LICENSE](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/LICENSE) file. Unauthorized copying, modification, or distribution of this software is prohibited.
