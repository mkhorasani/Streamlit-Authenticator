"""
Tests for the pluggable credential stores (CredentialStore, SQLiteCredentialStore).

Run with: python -m pytest tests/test_credential_store.py
"""

import os
import sqlite3
import threading
import textwrap

import pytest
from streamlit.testing.v1 import AppTest

from streamlit_authenticator import CredentialStore, SQLiteCredentialStore
from streamlit_authenticator.models import AuthenticationModel
from streamlit_authenticator.utilities import Hasher, LoginError

USERS = {
    'usernames': {
        'jsmith': {'email': 'jsmith@gmail.com', 'first_name': 'John', 'last_name': 'Smith',
                   'password': 'abc', 'roles': ['admin']},
        'rbriggs': {'email': 'rbriggs@gmail.com', 'first_name': 'Rebecca',
                    'last_name': 'Briggs', 'password': 'def'},
    }
}


@pytest.fixture
def store(tmp_path):
    db = SQLiteCredentialStore(str(tmp_path / 'users.db'))
    db.save({'usernames': {k: dict(v) for k, v in USERS['usernames'].items()}})
    return db


def test_round_trip(store):
    loaded = store.load()
    assert set(loaded['usernames']) == {'jsmith', 'rbriggs'}
    assert loaded['usernames']['jsmith']['roles'] == ['admin']


def test_empty_database_loads_empty(tmp_path):
    assert SQLiteCredentialStore(str(tmp_path / 'empty.db')).load() == {'usernames': {}}


def test_save_only_writes_given_users(store):
    creds = store.load()
    creds['usernames']['jsmith']['email'] = 'new@gmail.com'
    creds['usernames']['rbriggs']['email'] = 'not-saved@gmail.com'
    store.save(creds, ['jsmith'])
    reloaded = store.load()['usernames']
    assert reloaded['jsmith']['email'] == 'new@gmail.com'
    assert reloaded['rbriggs']['email'] == 'rbriggs@gmail.com'


def test_save_ignores_unknown_usernames(store):
    store.save(store.load(), ['ghost'])
    assert 'ghost' not in store.load()['usernames']


def test_rejects_unsafe_table_name(tmp_path):
    with pytest.raises(ValueError):
        SQLiteCredentialStore(str(tmp_path / 'x.db'), table='users; DROP TABLE x')


def test_custom_table_name(tmp_path):
    path = str(tmp_path / 'x.db')
    SQLiteCredentialStore(path, table='app_users').save({'usernames': {'a': {'email': 'a@x'}}})
    conn = sqlite3.connect(path)
    assert conn.execute('SELECT username FROM app_users').fetchall() == [('a',)]
    conn.close()


def test_replicas_do_not_overwrite_each_other(store):
    # Two app instances load the same state, then change different users.
    replica_a, replica_b = store.load(), store.load()
    replica_a['usernames']['jsmith']['failed_login_attempts'] = 3
    replica_b['usernames']['rbriggs']['logged_in'] = True
    store.save(replica_a, ['jsmith'])
    store.save(replica_b, ['rbriggs'])
    users = store.load()['usernames']
    assert users['jsmith']['failed_login_attempts'] == 3
    assert users['rbriggs']['logged_in'] is True


def test_concurrent_registrations_are_all_kept(tmp_path):
    path = str(tmp_path / 'users.db')
    SQLiteCredentialStore(path)

    def register(i):
        db = SQLiteCredentialStore(path)
        creds = db.load()
        creds['usernames'][f'user{i}'] = {'email': f'user{i}@x.com', 'password': 'h'}
        db.save(creds, [f'user{i}'])

    threads = [threading.Thread(target=register, args=(i,)) for i in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(SQLiteCredentialStore(path).load()['usernames']) == 25


class DictStore(CredentialStore):
    """Minimal custom backend, as a user would write for their own database."""
    def __init__(self, data):
        self.data = data
        self.saved = []
    def load(self):
        return {'usernames': {k: dict(v) for k, v in self.data['usernames'].items()}}
    def save(self, credentials, usernames=None):
        names = list(credentials['usernames']) if usernames is None else list(usernames)
        self.saved.append(names)
        for name in names:
            self.data['usernames'][name] = dict(credentials['usernames'][name])


def test_custom_backend_auto_hash_persists_hashes():
    backend = DictStore({'usernames': {k: dict(v) for k, v in USERS['usernames'].items()}})
    AuthenticationModel(backend)
    assert sorted(backend.saved[0]) == ['jsmith', 'rbriggs']
    assert all(Hasher.is_hash(u['password']) for u in backend.data['usernames'].values())


def test_model_persists_login_and_failed_attempts(store):
    model = AuthenticationModel(store)
    assert model.login('jsmith', 'wrong') is False
    assert model.login('jsmith', 'wrong') is False
    assert store.load()['usernames']['jsmith']['failed_login_attempts'] == 2
    # A fresh model (a rerun or another replica) enforces the persisted limit.
    with pytest.raises(LoginError):
        AuthenticationModel(store).login('jsmith', 'abc', max_login_attempts=2)
    assert AuthenticationModel(store).login('rbriggs', 'def') is True
    persisted = store.load()['usernames']['rbriggs']
    assert persisted['logged_in'] is True and persisted['failed_login_attempts'] == 0


def test_model_persists_registration_and_updates(store):
    model = AuthenticationModel(store)
    model.register_user('Ada', 'Lovelace', 'ada@example.com', 'ada', 'Secret#123', 'hint')
    fresh = AuthenticationModel(store)
    assert fresh.check_credentials('ada', 'Secret#123')
    fresh.update_user_details('ada', 'email', 'ada@lovelace.dev')
    fresh._update_password('ada', 'N3w#Secret')
    users = store.load()['usernames']
    assert users['ada']['email'] == 'ada@lovelace.dev'
    assert Hasher.check_pw('N3w#Secret', users['ada']['password'])
    assert set(users) == {'jsmith', 'rbriggs', 'ada'}


def test_path_based_config_still_used(tmp_path):
    config = tmp_path / 'config.yaml'
    config.write_text(textwrap.dedent("""\
        credentials:
          usernames:
            jsmith:
              email: jsmith@gmail.com
              first_name: John
              last_name: Smith
              password: abc
        cookie: {name: c, key: k, expiry_days: 30}
        """), encoding='utf-8')
    model = AuthenticationModel(path=str(config))
    assert model.store is None
    assert model.login('jsmith', 'abc') is True
    assert 'logged_in: true' in config.read_text(encoding='utf-8')


APP = """
import os
import streamlit as st
import streamlit_authenticator as stauth

store = stauth.SQLiteCredentialStore(os.environ['STAUTH_TEST_DB'])
authenticator = stauth.Authenticate(store, 'cookie', 'key', 30)
authenticator.login()
if st.session_state['authentication_status']:
    st.write('Welcome ' + st.session_state['name'])
"""


def test_authenticate_widget_with_sqlite_store(store, tmp_path, monkeypatch):
    monkeypatch.setenv('STAUTH_TEST_DB', store.path)
    app = tmp_path / 'app.py'
    app.write_text(APP, encoding='utf-8')
    at = AppTest.from_file(str(app), default_timeout=30).run()
    # Inputs live in a form, so they are submitted together with the button.
    at.text_input[0].input('jsmith')
    at.text_input[1].input('abc')
    at.button[0].click().run()
    assert not at.exception
    assert at.session_state['username'] == 'jsmith'
    assert any('Welcome John Smith' in m.value for m in at.markdown)
    assert store.load()['usernames']['jsmith']['logged_in'] is True
