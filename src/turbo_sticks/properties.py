from __future__ import annotations

from typing import overload

from turbo_sticks.db import DBSession
from turbo_sticks.util import encrypt, decrypt

_cache: dict[str, str] = {}


@overload
def get_property(key: str, default: None) -> str | None: ...
@overload
def get_property(key: str, default: str = '') -> str: ...


def get_property(key: str, default: str | None = '') -> str | None:
    value = _cache.get(key)
    if value is not None:
        return value
    db = DBSession()
    with db.connection() as conn, conn.cursor() as cur:
        sql = """
                SELECT value
                  FROM properties
                 WHERE key = %s"""

        cur.execute(sql, (key,))
        row: tuple[str] | None = cur.fetchone()
        if row is None:
            return default
        value = decrypt(row[0])
        _cache[key] = value
        return value


def set_property(key: str, value: str) -> None:
    if not value or value == get_property(key):
        return

    db = DBSession()
    with db.connection() as conn, conn.cursor() as cur:
        if get_property(key, None) is None:
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
        _cache[key] = value
