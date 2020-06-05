import sys

from turbo_db import DBSession
from turbo_util import encrypt, decrypt
this = sys.modules[__name__]

this.cache = {}


def get_property(key, default=''):
    value = this.cache.get(key)
    if value is not None:
        return value
    db = DBSession()
    if db is not None:
        with db.connection as conn:
            with conn.cursor() as cur:
                sql = """
                        SELECT value
                          FROM properties
                         WHERE key = %s"""

                cur.execute(sql, (key,))
                row = cur.fetchone()
                if row is None:
                    return default
                value = decrypt(row[0])
                this.cache[key] = value
                return value


def set_property(key, value):
    if not value or value == get_property(key):
        return

    db = DBSession()
    if db is not None:
        with db.connection as conn:
            with conn.cursor() as cur:
                sql = ''
                if get_property(db, key, None) is None:
                    # Insert
                    sql = """
                            INSERT INTO properties
                            (
                                value,
                                key
                            )
                            VALUES (
                                %s,
                                %s
                            )"""
                else:
                    # Update
                    sql = """
                            UPDATE properties
                               SET value = %s
                             WHERE key = %s"""
                cur.execute(sql, (encrypt(value), key))
                this.cache[key] = value
