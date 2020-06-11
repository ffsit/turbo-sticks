import logging
import psycopg2
from psycopg2 import Warning as DBWarning, Error as DBError
from gevent.lock import RLock
from time import time
from turbo_config import db_host, db_name, db_user, db_pass, db_max_age

# Logger
logger = logging.getLogger('sticks.db')


class DBSession(object):
    _instance = None
    _conn = None
    _initialized = None
    _refresh_lock = RLock()

    def __new__(cls):
        if DBSession._instance is None:
            DBSession._instance = object.__new__(cls)
        return DBSession._instance

    def is_alive(self):
        return DBSession._conn is not None and DBSession._conn.closed == 0

    def needs_refresh(self):
        return (DBSession._initialized is None or
                DBSession._initialized + db_max_age < time())

    def close(self):
        if self.is_alive():
            logger.info('Closing DB connection.')
            DBSession._conn.close()

    @property
    def connection(self):
        with DBSession._refresh_lock:
            if not self.is_alive() or self.needs_refresh():
                if not self.needs_refresh():
                    logger.warning('DB connection died before a refresh.')
                self.close()
                logger.info('Opening DB connection.')
                kwargs = {
                    'host': db_host,
                    'database': db_name,
                    'user': db_user,
                    'password': db_pass
                }
                DBSession._conn = psycopg2.connect(**kwargs)
                DBSession._initialized = time()

        return DBSession._conn


DBWarning
DBError
