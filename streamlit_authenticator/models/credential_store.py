"""
Script description: This module defines pluggable storage backends for user credentials,
so that credentials can live in a database instead of a YAML file.

Libraries imported:
-------------------
- json: Serializes each user's record.
- sqlite3: Built-in SQL database used by SQLiteCredentialStore.
- abc: Defines the CredentialStore interface.
- typing: Implements standard typing notations for Python functions.
"""

import json
import sqlite3
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, Optional


class CredentialStore(ABC):
    """
    Interface for a credentials storage backend.

    Pass an instance as the first argument of Authenticate (instead of a credentials
    dictionary or a config file path) to load users from, and persist changes to, any
    backend. A backend only has to implement two methods:

    - load() returns the credentials in the usual ``{'usernames': {...}}`` shape.
    - save(credentials, usernames) persists the records of the given usernames.

    Saving is done per user, so two app instances that change different users at the
    same time do not overwrite each other's changes.
    """
    @abstractmethod
    def load(self) -> Dict[str, Any]:
        """
        Loads all users.

        Returns
        -------
        dict
            Credentials in the form ``{'usernames': {username: {...}, ...}}``.
        """
    @abstractmethod
    def save(self, credentials: Dict[str, Any],
             usernames: Optional[Iterable[str]] = None) -> None:
        """
        Persists user records.

        Parameters
        ----------
        credentials : dict
            The full in-memory credentials dictionary.
        usernames : iterable of str, optional
            The users whose records changed. If None, all users are saved.
        """


class SQLiteCredentialStore(CredentialStore):
    """
    Stores credentials in a SQLite database, one row per user.

    The table has two columns: ``username`` (primary key) and ``data`` (the user's
    record as JSON, with the same keys as the YAML config, e.g. email, first_name,
    last_name, password, roles, logged_in, failed_login_attempts). Writes are upserts of
    only the users that changed, inside a transaction, so the database stays consistent
    when several sessions or app replicas share it.
    """
    def __init__(self, path: str, table: str = 'credentials', timeout: float = 30.0) -> None:
        """
        Initializes the SQLite credential store, creating the table if needed.

        Parameters
        ----------
        path : str
            File path of the SQLite database (created if it does not exist).
        table : str, default='credentials'
            Name of the table that holds the users.
        timeout : float, default=30.0
            Seconds to wait for a lock held by another writer.
        """
        if not table.replace('_', '').isalnum():
            raise ValueError('table must contain only letters, digits and underscores')
        self.path = path
        self.table = table
        self.timeout = timeout
        with self._connect() as conn:
            conn.execute(f'CREATE TABLE IF NOT EXISTS "{self.table}" ('
                         'username TEXT PRIMARY KEY NOT NULL, data TEXT NOT NULL)')
        conn.close()
    def _connect(self) -> sqlite3.Connection:
        """
        Opens a new connection. Streamlit runs each session in its own thread, so a
        connection is never shared across calls.
        """
        return sqlite3.connect(self.path, timeout=self.timeout)
    def load(self) -> Dict[str, Any]:
        """
        Loads all users from the database.

        Returns
        -------
        dict
            Credentials in the form ``{'usernames': {username: {...}, ...}}``.
        """
        conn = self._connect()
        try:
            rows = conn.execute(f'SELECT username, data FROM "{self.table}"').fetchall()
        finally:
            conn.close()
        return {'usernames': {username: json.loads(data) for username, data in rows}}
    def save(self, credentials: Dict[str, Any],
             usernames: Optional[Iterable[str]] = None) -> None:
        """
        Upserts the records of the given users in a single transaction.

        Parameters
        ----------
        credentials : dict
            The full in-memory credentials dictionary.
        usernames : iterable of str, optional
            The users whose records changed. If None, all users are saved.
        """
        users = credentials.get('usernames') or {}
        names = list(users) if usernames is None else [u for u in usernames if u in users]
        if not names:
            return
        rows = [(name, json.dumps(users[name], default=str)) for name in names]
        conn = self._connect()
        try:
            with conn:
                conn.executemany(f'INSERT INTO "{self.table}" (username, data) VALUES (?, ?) '
                                 'ON CONFLICT(username) DO UPDATE SET data = excluded.data',
                                 rows)
        finally:
            conn.close()
