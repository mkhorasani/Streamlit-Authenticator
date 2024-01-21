<img src="https://raw.githubusercontent.com/mkhorasani/Streamlit-Authenticator/main/graphics/logo.png" alt="Streamlit Authenticator logo" style="margin-top:50px;width:450px"></img>
<!--- [![Downloads](https://pepy.tech/badge/streamlit-authenticator)](https://pepy.tech/project/streamlit-authenticator) --->
<!--- [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/khorasani) --->

**A secure authentication module to validate user credentials in a Streamlit application.**
<br/><br/><br/>
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

### 1. Creating a configuration file

* Initially create a YAML configuration file and define your user's credentials: including names, usernames, and passwords (plain text passwords will be hashed automatically).
* In addition, enter a name, random key, and number of days to expiry for a JWT cookie that will be stored on the client's browser to enable passwordless reauthentication. If you do not require reauthentication, you may set the number of days to expiry to 0.
* Finally, define a list of preauthorized emails of users who can register and add their credentials to the configuration file with the use of the **register_user** widget.

```python
credentials:
  usernames:
    jsmith:
      email: jsmith@gmail.com
      name: John Smith
      password: abc # Will be hashed automatically
    rbriggs:
      email: rbriggs@gmail.com
      name: Rebecca Briggs
      password: def # Will be hashed automatically
cookie:
  expiry_days: 30
  key: some_signature_key # Must be string
  name: some_cookie_name
preauthorized:
  emails:
  - melsby@gmail.com
```

_Please note that other fields including 'id' and 'logged_in' corresponding to the unique user ID and log in status will be added automatically to each user's dictionary._

### 2. Creating a login widget

* Subsequently import the configuration file into your script and create an authentication object.

```python
import yaml
from yaml.loader import SafeLoader

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

> ### Authenticate
> ### Parameters:
>  - **credentials:** _dict_
>    - Provides the usernames, names, passwords, and emails, and other user data.
>  - **cookie_name:** _str, default None_
>    - Specifies the name of the JWT cookie stored on the client's browser for passwordless reauthentication.
>  - **key:** _str_
>    - Specifies the key that will be used to hash the signature of the JWT cookie.
>  - **cookie_expiry_days:** _float, default 30.0_
>    - Specifies the number of days before the reauthentication cookie automatically expires on the client's browser.
>  - **preauthorized:** _list, default None_
>    - Provides the list of emails of unregistered users who are authorized to register.
>  - **validator:** _object, default None_
>    - Provides a validator object that will check the validity of the username, name, and email fields..

* Then render the login module as follows.

```python
authenticator.login()
```

> ### Authenticate.login
> #### Parameters:
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the login widget.
>  - **max_concurrent_users:** _int, default None_
>    - Limits the number of concurrent users. If not specified there will be no limit to the number of users.
>  - **fields:** _dict, default {'Form name':'Login', 'Username':'Username', 'Password':'Password', 'Login':'Login'}_
>    - Customizes the text of headers, buttons and other fields.
> #### Returns:
> - _str_
>   - The name of the authenticated user.
> - _bool_
>   - The status of authentication, None: no credentials entered, False: incorrect credentials, True: correct credentials.
> - _str_
>   - The username of the authenticated user.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/login_form.PNG)

### 3. Authenticating users

* You can then retrieve the name, authentication status, and username from Streamlit's session state using **st.session_state["name"]**, **st.session_state["authentication_status"]**, and **st.session_state["username"]** to allow a verified user to proceed to any restricted content.
* You may also render a logout button, or may choose not to render the button if you only need to implement the logout logic programmatically.
* The optional **key** parameter for the logout button should be used with multipage applications to prevent Streamlit from throwing duplicate key errors.

```python
if st.session_state["authentication_status"]:
    authenticator.logout()
    st.write(f'Welcome *{st.session_state["name"]}*')
    st.title('Some content')
elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please enter your username and password')
```

> ### Authenticate.logout
> #### Parameters:
>  - **button_name:** _str, default 'Logout'_
>    - Customizes button name.
>  - **location:** _str, {'main', 'sidebar','unrendered'}, default 'main'_
>    - Specifies the location of the logout button. If 'unrendered' is passed, the logout logic will be implemented without rendering the button.
>  - **key:** _str, default None_
>    - A unique key that should be used in multipage applications.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/logged_in.PNG)

* Or prompt an unverified user to enter a correct username and password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/incorrect_login.PNG)


### 4. Creating a password reset widget

* You may use the **reset_password** widget to allow a logged in user to modify their password as shown below.

```python
if st.session_state["authentication_status"]:
    try:
        if authenticator.reset_password(st.session_state["username"], 'Reset password'):
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
>  - **fields:** _dict, default {'Form name':'Reset password', 'Current password':'Current password', 'New password':'New password', 'Repeat password': 'Repeat password', 'Reset':'Reset'}_
>    - Customizes the text of headers, buttons and other fields.
> #### Returns::
> - _bool_
>   - The status of resetting the password.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/reset_password.PNG)

_Please remember to update the config file (as shown in step 9) after you use this widget._

### 5. Creating a new user registration widget

* You may use the **register_user** widget to allow a user to sign up to your application as shown below. If you require the user to be preauthorized, set the **preauthorization** argument to True and add their email to the **preauthorized** list in the configuration file. Once they have registered, their email will be automatically removed from the **preauthorized** list in the configuration file. Alternatively, to allow anyone to sign up, set the **preauthorization** argument to False.

```python
try:
    if authenticator.register_user('Register user', preauthorization=False):
        st.success('User registered successfully')
except Exception as e:
    st.error(e)
```

> ### Authenticate.register_user
> #### Parameters:
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the register user widget.
>  - **preauthorization:** _bool, default True_
>    - Specifies the preauthorization requirement, True: user must be preauthorized to register, False: any user can register.
>  - **domains:** _list, default None_
>    - Specifies the required list of domains a new email must belong to i.e. gmail.com, list: the required list of domains None: any domain is allowed.
>  - **fields:** _dict, default {'Form name':'Register user', 'Email':'Email', 'Username':'Username', 'Password':'Password', 'Repeat password':'Repeat password', 'Register':'Register'}_
>    - Customizes the text of headers, buttons and other fields.
> #### Returns:
> - _str_
>   - The email associated with new user.
> - _str_
>   - The username associated with new user.
> - _str_
>   - The name associated with new user.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/register_user.PNG)

_Please remember to update the config file (as shown in step 9) after you use this widget._

### 6. Creating a forgot password widget

* You may use the **forgot_password** widget to allow a user to generate a new random password. This password will be automatically hashed and saved in the configuration file. The widget will return the username, email, and new random password of the user which should then be transferred to them securely.

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

> ### Authenticate.forgot_password
> #### Parameters
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the forgot password widget.
>  - **fields:** _dict, default {'Form name':'Forgot password', 'Username':'Username', 'Submit':'Submit'}_
>    - Customizes the text of headers, buttons and other fields.
> #### Returns:
> - _str_
>   - The username associated with the forgotten password.
> - _str_
>   - The email associated with the forgotten password.
> - _str_
>   - The new plain text password that should be transferred to user securely.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/forgot_password.PNG)

_Please remember to update the config file (as shown in step 9) after you use this widget._

### 7. Creating a forgot username widget

* You may use the **forgot_username** widget to allow a user to retrieve their forgotten username. The widget will return the username and email of the user which should then be transferred to them securely.

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

> ### Authenticate.forgot_username
> #### Parameters
>  - **location:** _str, {'main', 'sidebar'}, default 'main'_
>    - Specifies the location of the forgot username widget.
>  - **fields:** _dict, default {'Form name':'Forgot username', 'Email':'Email', 'Submit':'Submit'}_
>    - Customizes the text of headers, buttons and other fields.
> #### Returns:
> - _str_
>   - The forgotten username that should be transferred to user securely.
> - _str_
>   - The email associated with the forgotten username.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/forgot_username.PNG)

### 8. Creating an update user details widget

* You may use the **update_user_details** widget to allow a logged in user to update their name and/or email. The widget will automatically save the updated details in both the configuration file and reauthentication cookie.

```python
if st.session_state["authentication_status"]:
    try:
        if authenticator.update_user_details(st.session_state["username"], 'Update user details'):
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
>  - **fields:** _dict, default {'Form name':'Update user details', 'Field':'Field', 'Name':'Name', 'Email':'Email', 'New value':'New value', 'Update':'Update'}_
>    - Customizes the text of headers, buttons and other fields.
> #### Returns:
> - _bool_
>   - The status of updating the user details.

![](https://github.com/mkhorasani/Streamlit-Authenticator/blob/main/graphics/update_user_details.PNG)

_Please remember to update the config file (as shown in step 9) after you use this widget._

### 9. Updating the configuration file

* Please ensure that the configuration file is resaved anytime the credentials are updated or whenever the **reset_password**, **register_user**, **forgot_password**, or **update_user_details** widgets are used.

```python
with open('../config.yaml', 'w') as file:
    yaml.dump(config, file, default_flow_style=False)
```

<!--- ## Credits
- Mohamed Abdou for the highly versatile cookie manager in [Extra-Streamlit-Components](https://github.com/Mohamed-512/Extra-Streamlit-Components). --->
