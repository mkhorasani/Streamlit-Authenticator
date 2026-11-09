"""
Simulates N app sessions (or replicas) that each register a different user at the same
moment, once with a YAML config file and once with SQLiteCredentialStore, and reports how
many users were kept. Run with: python tests/concurrent_registrations.py [N]
"""
import logging
import os
import sys
import tempfile
import threading

logging.disable(logging.WARNING)
import yaml
from streamlit_authenticator import SQLiteCredentialStore
from streamlit_authenticator.models import AuthenticationModel

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
TRIALS = 5
BASE = {'usernames': {'admin': {'email': 'admin@x.com', 'first_name': 'A', 'last_name': 'B',
        'password': '$2b$12$' + 'a' * 53}}}

def run(make_creds, count_users):
    barrier = threading.Barrier(N)
    errors = []
    def worker(i):
        model = make_creds()           # each session loads current state
        barrier.wait()                 # then all submit "register" together
        try:
            model.register_user('F', 'L', f'u{i}@x.com', f'u{i}', 'Secret#123', None)
        except Exception as e:         # session crashed while saving
            errors.append(type(e).__name__)
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    [t.start() for t in ts]; [t.join() for t in ts]
    try:
        kept = count_users() - 1
    except Exception:
        kept = 'CORRUPT'
    return kept, len(errors)

res = {'yaml': [], 'sqlite': []}
for _ in range(TRIALS):
    d = tempfile.mkdtemp()
    cfg = os.path.join(d, 'config.yaml')
    yaml.dump({'credentials': BASE, 'cookie': {'name': 'c', 'key': 'k', 'expiry_days': 30}}, open(cfg, 'w'))
    res['yaml'].append(run(lambda: AuthenticationModel(path=cfg, auto_hash=False),
        lambda: len(yaml.safe_load(open(cfg))['credentials']['usernames'])))
    db = os.path.join(d, 'users.db')
    SQLiteCredentialStore(db).save({'usernames': dict(BASE['usernames'])})
    res['sqlite'].append(run(lambda: AuthenticationModel(SQLiteCredentialStore(db), auto_hash=False),
        lambda: len(SQLiteCredentialStore(db).load()['usernames'])))
for k, v in res.items():
    kept = [x[0] for x in v]; crashed = [x[1] for x in v]
    print(f'{k}: users kept per trial {kept} (of {N}); sessions that raised {crashed}')
