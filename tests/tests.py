"""
Script description: This script imports tests the Streamlit-Authenticator package. 

Libraries imported:
-------------------
- streamlit: Framework used to build pure Python web applications.
"""

from streamlit.testing.v1 import AppTest

def test_login():
    at = AppTest.from_file('tests/app.py').run()
    at.text_input[0].input('jsmith').run()
    at.text_input[1].input('abc').run()
    at.button[0].click().run()
    assert 'jsmith' in at.session_state['username']
