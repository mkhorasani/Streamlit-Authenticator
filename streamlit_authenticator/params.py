"""
Configuration parameters and links for the Streamlit-Authenticator package.
"""
# GENERAL
AUTO_HASH_MAX_USERS:        int     =   30
AUTO_HASH_MAX_USERS_LINK:   str     =   "https://github.com/mkhorasani/Streamlit-Authenticator?tab=readme-ov-file#4-setup"
PASSWORD_INSTRUCTIONS:      str     =   """
                                        **Password must be:**
                                        - Between 8 and 20 characters long.
                                        - Contain at least one lowercase letter.
                                        - Contain at least one uppercase letter.
                                        - Contain at least one digit.
                                        - Contain at least one special character from !@#$%^&*()_+-=[]{};:'\"\\|,.<>/?`~.
                                        """
PRE_GUEST_LOGIN_SLEEP_TIME: float   =   0.7
PRE_LOGIN_SLEEP_TIME:       float   =   0.7
REGISTER_USER_LINK:         str     =   "https://github.com/mkhorasani/Streamlit-Authenticator?tab=readme-ov-file#authenticateregister_user"
REMOTE_VARIABLES_LINK:      str     =   "https://raw.githubusercontent.com/mkhorasani/streamlit_authenticator_variables/main/variables"
TWO_FACTOR_AUTH_LINK:       str     =   "https://github.com/mkhorasani/Streamlit-Authenticator?tab=readme-ov-file#8-enabling-two-factor-authentication"

# CLOUD
SEND_EMAIL:                 str     =   "/send_email"
SERVER_URL:                 str     =   "https://mkhorasani.pythonanywhere.com"
TIMEOUT:                    int     =   30
