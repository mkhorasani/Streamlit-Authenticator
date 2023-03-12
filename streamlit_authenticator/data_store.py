from deta import Deta

class DetaDataStore:
    """Stores the cookies, credentials, and preauthorized users in a Deta Base."""
    def __init__(self, deta_project_key: str, cookie_key: str, cookie_name: str) -> None:
        """Creates a Deta Base and stores the cookie, credentials, and  data in it.

        Args:
            deta_project_key (str): The Deta project key
            cookie_key (str): The cookie encryption key

        """
        deta = Deta(deta_project_key)
        self.db = deta.Base("user_credentials")

        cookies = self.db.get("cookies")
        if cookies is None:
            cookies = {
                "expiry_days": 0,
                "encryption_key": cookie_key,
                "name": cookie_name,
            }
            self.db.put(cookies, "cookies")

        credentials = self.db.get("credentials")
        if credentials is None:
            credentials = {
                "usernames": {
                    "place_holder": {
                    }
                }
            }
            self.db.put(credentials, "credentials")

        preauthorized = self.db.get("preauthorized")
        if preauthorized is None:
            preauthorized = {"domains": [], "emails": []}
            self.db.put(preauthorized, "preauthorized")

    def put_cred_and_preauthorized(self, credentials: dict, preauthorized: dict):
        """Updates the Deta Base with the new credentials and preauthorized users.

        Args:
            db (_description_): The Db to update
            credentials (_description_): The new credentials dict
            preauthorized (_description_): The new preauthorized dict
        """
        self.db.put(credentials, "credentials")
        self.db.put(preauthorized, "preauthorized")

    def get_config(self):
        """Retrieves the current credentials and preauthorized users.

        Returns:
            tuple: _description_
        """
        return (self.db.get("cookies"), self.db.get("credentials"), self.db.get("preauthorized"))
