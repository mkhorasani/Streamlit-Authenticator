"""
Script description: This module controls requests made to the CookieModel for password-less
re-authentication.

Libraries imported:
- typing: Provides standard type hints for Python functions.
"""

from typing import Any, Dict, Optional

from ..models import CookieModel


class CookieController:
    """
    Controls all requests made to the CookieModel for password-less re-authentication,
    including deleting, retrieving, and setting cookies.
    """
    def __init__(
            self,
            cookie_name: Optional[str] = None,
            cookie_key: Optional[str] = None,
            cookie_expiry_days: Optional[float] = None,
            path: Optional[str] = None
            ) -> None:
        """
        Initializes the CookieController instance.

        Parameters
        ----------
        cookie_name : str, optional
            Name of the cookie stored in the client's browser for password-less re-authentication.
        cookie_key : str, optional
            Secret key used for signing and verifying the authentication cookie.
        cookie_expiry_days : float, optional
            Number of days before the re-authentication cookie automatically expires.
        path : str, optional
            Path to the configuration file.
        """
        self.cookie_model = CookieModel(cookie_name,
                                        cookie_key,
                                        cookie_expiry_days,
                                        path)
    def delete_cookie(self) -> None:
        """
        Deletes the re-authentication cookie from the user's browser.
        """
        self.cookie_model.delete_cookie()
    def get_cookie(self) -> Optional[Dict[str, Any]]:
        """
        Retrieves the re-authentication cookie.

        Returns
        -------
        dict or None
            If valid, returns a dictionary containing the cookie's data.
            Returns None if the cookie is expired or invalid.
        """
        return self.cookie_model.get_cookie()
    def set_cookie(self) -> None:
        """
        Creates and stores the re-authentication cookie in the user's browser.
        """
        self.cookie_model.set_cookie()
