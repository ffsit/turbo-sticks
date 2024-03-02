from __future__ import annotations

import gevent
import gevent.select
import logging
from psycopg import Warning as DBWarning, Error as DBError
from psycopg_pool import ConnectionPool, PoolTimeout
from typing import Any, ClassVar, TYPE_CHECKING

import turbo_sticks.config as config

if TYPE_CHECKING:
    from contextlib import _GeneratorContextManager as ContextManager
    from psycopg import Connection


logger = logging.getLogger('sticks.db')


class DBSession:  # pragma: no cover

    _instance:   ClassVar[DBSession | None] = None
    _pool:       ConnectionPool[Connection[tuple[Any, ...]]] | None
    _check_job:  gevent.greenlet.Greenlet[[], None] | None

    def __new__(cls) -> DBSession:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance._pool = None
            cls._instance._check_job = None
            cls._instance.init_pool()
        return cls._instance

    def init_pool(self) -> None:
        # make sure we don't leave a pool hanging around to be cleaned up
        if self._pool is not None:
            self.close()

        db_pool = config.db_pool
        self._pool = ConnectionPool(
            str(db_pool.uri),
            min_size=db_pool.min_size,
            max_size=db_pool.max_size,
            max_idle=db_pool.max_idle,
            max_lifetime=db_pool.max_age,
        )
        # This will raise an exception if our connection is misconfigured
        # which is what we want to ensure on application start.
        self._pool.wait()

    def start_checks(self) -> None:
        assert self._pool is not None
        if self._check_job is not None:
            return

        def check() -> None:
            while True:
                assert self._pool is not None
                with self._pool.connection() as conn:
                    try:
                        gevent.select.select([conn.fileno()], [], [])[0]
                    except (ValueError, OSError):
                        logger.warning('check greenlet terminated.')
                        break
                # Run a check every time the connection talks to us
                logger.info('Running connection check on DB pool.')
                self._pool.check()

        self._check_job = gevent.spawn(check)

    def close(self) -> None:
        logger.info('Closing DB connection pool.')
        if self._check_job is not None:
            self._check_job.kill()
            self._check_job = None
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def connection(self) -> ContextManager[Connection[Any]]:
        assert self._pool is not None
        return self._pool.connection()


DBWarning
DBError
PoolTimeout
