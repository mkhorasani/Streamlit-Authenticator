import re


class Validator:
    def validate_username(self, username: str) -> bool:
        """
        Returns True if the username is 1-20 chars and only alphanumerics and - _
        """
        pattern = r"^[a-zA-Z0-9_-]{1,20}$"
        return bool(re.match(pattern, username))

    def validate_name(self, name: str) -> bool:
        """
        Returns true if the name is between 1-100 chars
        """
        return 1 < len(name) < 100

    def validate_email(self, email: str) -> bool:
        """
        Returns true if the email is between 3-320 chars and has an @ symbol
        """
        return "@" in email and 2 < len(email) < 320
