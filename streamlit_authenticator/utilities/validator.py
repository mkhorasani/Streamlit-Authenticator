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
    def diagnose_password(self, password: str) -> str:
        """
        Diagnoses the validity of the entered password.
    
        Parameters
        ----------
        password: str
            The password to be diagnosed.
            
        Returns
        -------
        str
            Error message.
        """
        min_length = 8
        max_length = 20
        errors = []
        if not min_length <= len(password) <= max_length:
            errors.append(f'Password must be between {min_length} and {max_length} characters long')
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        if not re.search(r'\d', password):
            errors.append('Password must contain at least one digit')
        if not re.search(r'[@$!%*?&]', password):
            errors.append('Password must contain at least one special character (@$!%*?&)')
        return 'Password is not valid: ' + '; '.join(errors)
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
        pattern = r"^[a-zA-Z0-9._%+-]{1,254}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63}$"
        return bool(re.match(pattern, email))
    def validate_length(self, variable: str, min_length: int=0, max_length: int=254) -> bool:
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
        pattern = rf"^.{{{min_length},{max_length}}}$"
        return bool(re.match(pattern, variable))
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
        pattern = r"^[A-Za-z. ]{2,100}$"
        return bool(re.match(pattern, name))
    def validate_password(self, password: str) -> bool:
        """
        Checks the validity of the entered password.
    
        Parameters
        ----------
        password: str
            The password to be validated.
            
        Returns
        -------
        bool
            Validity of entered password.
        """
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$"
        return bool(re.match(pattern, password))
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
        pattern = r"^([a-zA-Z0-9_-]{1,20}|[a-zA-Z0-9._%+-]{1,254}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,63})$"
        return bool(re.match(pattern, username))
