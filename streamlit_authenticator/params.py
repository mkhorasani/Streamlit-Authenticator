"""
Configuration parameters and links for the Streamlit-Authenticator package.
"""
# GENERAL
AUTO_HASH_MAX_USERS:        int     =   30
AUTO_HASH_MAX_USERS_LINK:   str     =   "https://github.com/mkhorasani/Streamlit-Authenticator?tab=readme-ov-file#2-setup"
PASSWORD_INSTRUCTIONS:      str     =   """
                                        **Password must be:**
                                        - Between 8 and 20 characters long.
                                        - Contain at least one lowercase letter.
                                        - Contain at least one uppercase letter.
                                        - Contain at least one digit.
                                        - Contain at least one special character from [@$!%*?&].
                                        """
PRE_GUEST_LOGIN_SLEEP_TIME: float   =   0.7
PRE_LOGIN_SLEEP_TIME:       float   =   0.7
REGISTER_USER_LINK:         str     =   "https://github.com/mkhorasani/Streamlit-Authenticator?tab=readme-ov-file#authenticateregister_user"
