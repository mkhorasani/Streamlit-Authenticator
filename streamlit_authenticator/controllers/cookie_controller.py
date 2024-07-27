"""
Script description: This module controls requests made to the cookie model for password-less
re-authentication. 
"""

from ..models import CookieModel

class CookieController:
    """
    This class controls all requests made to the cookie model for password-less re-authentication, 
    including deleting, getting, and setting the cookie.
    """
    def __init__(self, cookie_name: str, cookie_key: str, cookie_expiry_days: float):
        """
        Create a new instance of "CookieController".

        Parameters
        ----------
        cookie_name: str
            Name of the cookie stored on the client's browser for password-less re-authentication.
        cookie_key: str
            Key to be used to hash the signature of the re-authentication cookie.
        cookie_expiry_days: float
            Number of days before the re-authentication cookie automatically expires on the client's 
            browser.
        """
        self.cookie_model = CookieModel(cookie_name,
                                        cookie_key,
                                        cookie_expiry_days)
    def delete_cookie(self):
        """
        Deletes the re-authentication cookie.
        """
        self.cookie_model.delete_cookie()
    def get_cookie(self):
        """
        Gets the re-authentication cookie.

        Returns
        -------
        str
            Re-authentication cookie.
        """
        return self.cookie_model.get_cookie()
    def set_cookie(self):
        """
        Sets the re-authentication cookie.
        """
        self.cookie_model.set_cookie()
