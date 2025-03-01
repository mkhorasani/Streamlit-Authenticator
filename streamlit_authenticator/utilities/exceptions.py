"""
Script description: Handles custom exceptions for errors occurring in authentication processes,
such as login failures, incorrect credentials, deprecated functionality, and 
issues related to password resets and user updates.
"""


class AuthenticateError(Exception):
    """
    Exceptions raised in the Authenticate class.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class CredentialsError(Exception):
    """
    Exception raised for incorrect credentials.

    Parameters
    ----------
    credential_type : str, optional
        Type of credential that caused the error ('username' or 'password').
    """
    def __init__(self, credential_type: str='') -> None:
        error_message = {
            'username': 'Username is incorrect',
            'password': 'Password is incorrect'
        }.get(credential_type, 'Username/password is incorrect')

        super().__init__(error_message)


class CloudError(Exception):
    """
    Exception raised for cloud-related errors.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class DeprecationError(Exception):
    """
    Exception raised for deprecated functionality.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ForgotError(Exception):
    """
    Exception raised for errors in the forgotten username/password process.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class LoginError(Exception):
    """
    Exception raised for login-related errors.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class LogoutError(Exception):
    """
    Exception raised for errors related to the logout process.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RegisterError(Exception):
    """
    Exception raised for errors in the user registration process.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ResetError(Exception):
    """
    Exception raised for errors in the password reset process.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class TwoFactorAuthError(Exception):
    """
    Exception raised for errors in two-factor authentication.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class UpdateError(Exception):
    """
    Exception raised for errors in updating user details.

    Parameters
    ----------
    message : str
        The custom error message to display.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
