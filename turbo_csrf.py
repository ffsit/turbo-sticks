from time import time
from hashlib import sha256
from gevent.lock import RLock

from turbo_config import app_secret, expiration_interval, flush_interval
from turbo_util import generate_random_token


def sign_token(csrf_token, time_signature, session_token):
    token = csrf_token[:32]
    hash_seed = '%s%s%s%s' % (token, time_signature, session_token, app_secret)
    return token + sha256(hash_seed.encode('utf-8')).hexdigest()[:32]


class TokenClerk:
    flush_lock = RLock()

    def __init__(self):
        self.next_flush = time() + flush_interval
        self.tokens = {}

    def __flush_if_necessary(self):
        if self.next_flush < time():
            if not self.flush_lock.acquire(False):
                # if another greenlet is flushing, we don't need to as well
                return
            try:
                for token in dict(self.tokens):
                    expiration_time = self.tokens[token] + expiration_interval
                    if expiration_time < self.next_flush:
                        del self.tokens[token]
                self.next_flush = time() + flush_interval
            finally:
                self.flush_lock.release()

    def register(self, session_token):
        self.__flush_if_necessary()
        time_signature = time()
        token = sign_token(
            generate_random_token(32), time_signature, session_token)
        self.tokens[token] = time_signature
        return token

    def validate(self, session_token, csrf_token):
        self.__flush_if_necessary()
        if csrf_token is not None:
            time_signature = self.tokens.pop(csrf_token, 0)
            return (csrf_token == sign_token(
                csrf_token, time_signature, session_token))
        return False
