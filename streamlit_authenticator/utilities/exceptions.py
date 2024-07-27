"""
Script description: This module raises the Credentials, Deprecation, Forgot, Login,
Register, Reset, and Update errors. 
"""

class AuthenticateError(Exception):
    """
    Exceptions raised for the Authenticate class.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class CredentialsError(Exception):
    """
    Exception raised for incorrect credentials.
    """
    def __init__(self, credential_type: str=''):
        if credential_type == 'username':
            super().__init__('Username is incorrect')
        elif credential_type == 'password':
            super().__init__('Password is incorrect')
        else:
            super().__init__('Username/password is incorrect')

class DeprecationError(Exception):
    """
    Exceptions raised for deprecations.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class ForgotError(Exception):
    """
    Exceptions raised for the forgotten username/password widgets.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class LoginError(Exception):
    """
    Exceptions raised for the Login widget.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class LogoutError(Exception):
    """
    Exceptions raised for the Logout button.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class RegisterError(Exception):
    """
    Exceptions raised for the register user widget.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class ResetError(Exception):
    """
    Exceptions raised for the password reset widget.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)

class UpdateError(Exception):
    """
    Exceptions raised for the update user details widget.

    Attributes
    ----------
    message: str
        The custom error message to display.
    """
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
        