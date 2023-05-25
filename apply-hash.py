import yaml
import streamlit as st
from yaml.loader import SafeLoader
import streamlit.components.v1 as components

from streamlit_authenticator.hasher import Hasher
from streamlit_authenticator.authenticate import Authenticate

if __name__ == "__main__":
    # Loading config file
    with open("config.source.yaml") as file:
        config = yaml.load(file, Loader=SafeLoader)

    # hash passwords
    users = config["credentials"]["usernames"]
    for username in users:
        user = users[username]
        user["password"] = Hasher([user["password"]]).generate()[0]
        print(user)

    # save config file
    with open("config.yaml", "w") as file:
        yaml.dump(config, file, default_flow_style=False)
