"""
Script description: This script provides string validations for various user inputs. 

Libraries imported:
- re: Module implementing regular expressions.
"""

import re

class Validator:
    """
    This class will check the validity of the entered username, name, and email for a 
    newly registered user.
    """
    def __init__(self):
        pass
    def validate_email(self, email: str) -> bool:
        """
        Checks the validity of the entered email.

        Parameters
        ----------
        email: str
            The email to be validated.
            
        Returns
        -------
        bool
            Validity of entered email.
        """
        pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        return 2 < len(email) < 320 and bool(re.match(pattern, email))
    def validate_name(self, name: str) -> bool:
        """
        Checks the validity of the entered name.
        
        Parameters
        ----------
        name: str
            The name to be validated.
            
        Returns
        -------
        bool
            Validity of entered name.
        """
        pattern = r"^[A-Za-z ]+$"
        return 1 <= len(name) <= 100 and bool(re.match(pattern, name))
    def validate_length(self, variable: str, min_length: int=0, max_length: int=100) -> bool:
        """
        Checks the length of a variable.
        
        Parameters
        ----------
        variable: str
            The variable to be validated.
        min_length: str
            The minimum required length for the variable.
        max_length: str
            The maximum required length for the variable.

        Returns
        -------
        bool
            Validity of entered variable.
        """
        return min_length <= len(variable) <= max_length
    def validate_username(self, username: str) -> bool:
        """
        Checks the validity of the entered username.

        Parameters
        ----------
        username: str
            The username to be validated.
            
        Returns
        -------
        bool
            Validity of entered username.
        """
        pattern = r"^[a-zA-Z0-9_-]{1,20}$"
        return bool(re.match(pattern, username))
    