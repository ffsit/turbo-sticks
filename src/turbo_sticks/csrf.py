from __future__ import annotations

from gevent.lock import RLock
from hashlib import sha256
from time import time

import turbo_sticks.config as config
from turbo_sticks.util import generate_random_token


def sign_token(
    csrf_token: str,
    expires_at: float,
    session_token: str
) -> str:

    token = csrf_token[:32]
    secret = config.app_secret.get_secret_value()
    hash_seed = '%s%s%s%s' % (token, expires_at, session_token, secret)
    return token + sha256(hash_seed.encode('utf-8')).hexdigest()[:32]


class TokenClerk:

    flush_lock: RLock = RLock()
    next_flush: float
    tokens:     dict[str, float]

    def __init__(self) -> None:
        self.flush_lock = RLock()
        self.next_flush = time() + config.csrf.flush_interval
        self.tokens = {}

    # TODO: We could move this to a dedicated greenlet.
    #       But there would honestly probably be no measurable benefit...
    def _flush_if_necessary(self) -> None:
        if self.next_flush <= (now := time()):
            if not TokenClerk.flush_lock.acquire(False):
                # if another greenlet is flushing, we don't need to as well
                return
            try:
                self.tokens = {
                    token: expires_at
                    for token, expires_at in self.tokens.items()
                    if expires_at > now
                }
                self.next_flush = now + config.csrf.flush_interval
            finally:
                TokenClerk.flush_lock.release()

    def register(self, session_token: str) -> str:
        self._flush_if_necessary()
        expires_at = time() + config.csrf.expiration_interval
        seed = generate_random_token(32)
        token = sign_token(seed, expires_at, session_token)
        self.tokens[token] = expires_at
        return token

    def validate(self, session_token: str, csrf_token: str | None) -> bool:
        self._flush_if_necessary()
        if csrf_token is None:
            return False

        time_sig = self.tokens.pop(csrf_token, float('-inf'))
        return csrf_token == sign_token(csrf_token, time_sig, session_token)
