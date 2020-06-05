import psycopg2
from psycopg2 import Warning as DBWarning, Error as DBError
from gevent.lock import RLock
from time import time
from turbo_config import db_host, db_name, db_user, db_pass, db_max_age


class DBSession(object):
    __instance = None

    def __new__(cls):
        if DBSession.__instance is None:
            DBSession.__instance = object.__new__(cls)
        return DBSession.__instance

    def __init__(self):
        self._conn = None
        self._initialized = None
        self._refresh_lock = RLock()

    def is_alive(self):
        return self._conn is not None and self._conn.closed == 0

    def needs_refresh(self):
        return (self._initialized is not None and
                self._initialized + db_max_age < time())

    def close(self):
        if self.is_alive():
            self._conn.close()

    @property
    def connection(self):
        with self._refresh_lock:
            if not self.is_alive() or self.needs_refresh():
                self.close()
                kwargs = {
                    'host': db_host,
                    'database': db_name,
                    'user': db_user,
                    'password': db_pass
                }
                self._conn = psycopg2.connect(**kwargs)
                self._initialized = time()

        return self._conn


DBWarning
DBError
