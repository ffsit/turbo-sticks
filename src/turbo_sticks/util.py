from __future__ import annotations

import functools
import json
from collections.abc import Callable, Iterator
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from enum import Enum
from fnmatch import fnmatch
from html import escape
from http.cookies import SimpleCookie
from os import urandom, scandir, path
from urllib.parse import parse_qs, quote_plus, urlencode

import turbo_sticks.config as config


from typing import cast, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from redis import Redis
    from redis.client import Pipeline

    from .types import JSON
    from .types import HTTPHeader
    from .types import MultiDict
    from .types import Response
    from .types import StreamEmbed
    from .types import URLBase


# Exports
escape
quote_plus
urlencode


class Sentinel(Enum):
    sentinel = object()


# faster version of functools.cache, for functions without params
def single_cache[T](func: Callable[[], T]) -> Callable[[], T]:
    computed: T | Sentinel = Sentinel.sentinel

    @functools.wraps(func)
    def wrapper() -> T:
        nonlocal computed
        if computed is Sentinel.sentinel:
            computed = func()
        return computed

    def cache_clear() -> None:
        nonlocal computed
        computed = Sentinel.sentinel

    wrapper.cache_clear = cache_clear  # type:ignore[attr-defined]
    return wrapper


# Crypto Helpers
def generate_random_token(length: int) -> str:
    return urandom(length//2).hex()


def encrypt(plaintext: str) -> str:
    iv = urandom(16)
    key = config.app_secret.get_secret_value().encode('utf-8')[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    ct = cipher.encryptor()
    ciphertext = ct.update(plaintext.encode('utf-8')) + ct.finalize()
    return ciphertext.hex() + iv.hex()


def decrypt(ciphertext: str) -> str:
    iv = bytes.fromhex(ciphertext[-32:])
    key = config.app_secret.get_secret_value().encode('utf-8')[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    ct = cipher.decryptor()
    plaintext = ct.update(bytes.fromhex(ciphertext[:-32])) + ct.finalize()
    return plaintext.decode('utf-8', errors='ignore')


# Web Server Helpers
def sub_title(sub_title: str, title: str = config.page_title) -> str:
    return f'{sub_title} - {title}'


def retrieve_get_vars(env: dict[str, Any]) -> MultiDict:
    return parse_qs(env['QUERY_STRING'], encoding='utf-8')


def retrieve_request_body(env: dict[str, Any]) -> bytes:
    try:
        size = int(env.get('CONTENT_LENGTH', 0))
    except (ValueError, TypeError):
        size = 0
    return env['wsgi.input'].read(size)  # type:ignore[no-any-return]


def retrieve_post_vars(env: dict[str, Any]) -> MultiDict:
    request_body = retrieve_request_body(env)
    return parse_qs(request_body.decode('utf-8'))


def retrieve_cookies(env: dict[str, Any]) -> SimpleCookie:
    cookies = SimpleCookie()
    cookies.load(env.get('HTTP_COOKIE', ''))
    return cookies


def set_cookie_header(name: str, value: str, path: str = '/',
                      max_age: int = config.session.max_age) -> HTTPHeader:
    # TODO: Add SameSite parameter. Needs filter for old Safari versions.
    #       See https://bugs.webkit.org/show_bug.cgi?id=198181
    return (
        'Set-Cookie',
        f'{name}={value}; Domain={config.session.cookie_scope}; '
        f'Max-Age={max_age}; Path={path}; Secure; HttpOnly;'
    )


def unset_cookie_header(name: str, path: str = '/') -> HTTPHeader:
    # NOTE: this might need SameSite as well to unset, once added
    return (
        'Set-Cookie',
        f'{name}=unset; Domain={config.session.cookie_scope}; '
        f'Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path={path}; '
        'Secure; HttpOnly;'
    )


@single_cache
def user_agent() -> str:
    from turbo_sticks import __version__ as version
    return f'TURBOSticks (https://github.com/ffsit/turbo-sticks, {version})'


def basic_response_header(
    response_body: bytes,
    send_length:   bool = True
) -> list[HTTPHeader]:

    if send_length:
        return [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(response_body)))
        ]
    else:
        return [('Content-Type', 'text/html')]


def generate_json_response(data: JSON, status: str = '200 OK') -> Response:
    response_body = json.dumps(data).encode('utf-8')
    response_headers = [
        ('Content-Type', 'application/json'),
        ('Content-Length', str(len(response_body)))
    ]
    return response_body, response_headers, status


def get_default_embed(sources: list[StreamEmbed]) -> str:
    if len(sources) > 0 and sources[0]['embed_type'] == 'html':
        return sources[0]['embed']
    return ''


def generate_video_sources(sources: list[StreamEmbed]) -> str:
    if len(sources) > 0:
        return json.dumps(sources)
    return '[]'


def build_url(
    path:  str,
    base:  URLBase | None = None,
    query: dict[str, str] | None = None
) -> str:

    assert base in [None, 'base', 'api', 'websockets']
    query_str = ''
    if query and isinstance(query, dict):
        query_str = '?' + urlencode(query)
    scheme = config.web_scheme
    base_path = ''
    if base == 'base':
        base_path = config.base_path
    elif base == 'api':
        base_path = config.api_path
    elif base == 'websockets':
        base_path = config.websockets.path
        scheme = config.websockets.scheme
    return f'{scheme}://{config.web_uri}{base_path}{path}{query_str}'


# File Helpers
def files(source_path: str, pattern: str = '*') -> Iterator[str]:
    with scandir(source_path) as scan:
        for entry in scan:
            if not entry.is_file():
                continue

            if fnmatch(entry.name, pattern):
                yield path.join(source_path, entry.name)


@single_cache
def get_css_version() -> int:
    css_version = 0
    pattern = '*.css'
    for file_path in files(config.static_dir, pattern):
        css_version = max(css_version, int(path.getmtime(file_path)))
    return css_version


@single_cache
def get_js_version() -> int:
    js_version = 0
    pattern = '*.js'
    for file_path in files(config.static_dir, pattern):
        js_version = max(js_version, int(path.getmtime(file_path)))
    return js_version


type _Value = bytes | float | int | str


# Custom Redis transactions

# @ImmediatePipeline
# After a watch in a pipeline we enter immediate mode, we pretend we are
# no longer a pipeline using a cast so we get the proper return types

def zhaddex(
    redis:           Redis[bytes],
    key:             str,
    field:           str,
    ttl:             int,
    value:           _Value,
    score:           float,
    max_cardinality: int = 0
) -> None:
    """
    Simulates a sorted hash set with field expiration
    if set contains more elements than max_cardinality
    the elements with the lowest scores get removed
    """

    def _zhaddex(pipe: Pipeline[bytes]) -> None:
        # NOTE: @ImmediatePipeline
        pipe_imm = cast('Redis[bytes]', pipe)
        field_key = f'{{{key}}}{field}'
        if max_cardinality > 0:
            diff = pipe_imm.zcard(key) - max_cardinality
            if diff >= 0:
                remove = pipe_imm.zrange(key, 0, diff)
                pipe_imm.zrem(key, *remove)
                pipe_imm.delete(*remove)

        pipe.multi()
        pipe.zadd(key, {field_key: score})
        pipe.setex(field_key, ttl, value)

    redis.transaction(_zhaddex, key)  # type:ignore[no-untyped-call]


def zhttl(redis: Redis[bytes], key: str, field: str) -> int:
    """
    Returns time to live on sorted hash field
    """
    field_key = f'{{{key}}}{field}'
    return redis.ttl(field_key)


# modifies existing entry, if no entry exists, it does nothing
def zhmod(redis: Redis[bytes], key: str, field: str, value: _Value) -> None:
    """
    Modifies existing entry on sorted hash field
    if no entry exists, it does nothing
    """
    def _zhmod(pipe: Pipeline[bytes]) -> None:
        # NOTE: @ImmediatePipeline
        pipe_imm = cast('Redis[bytes]', pipe)
        field_key = f'{{{key}}}{field}'
        ttl = pipe_imm.ttl(field_key)
        if ttl > 0:
            pipe.setex(field_key, ttl, value)

    redis.transaction(_zhmod, key)  # type:ignore[no-untyped-call]


def zhdel(redis: Redis[bytes], key: str, *fields: str) -> None:
    """
    Deletes simulated sorted hash fields
    """
    field_keys = [f'{{{key}}}{f}' for f in fields]
    with redis.pipeline() as pipe:
        pipe.zrem(key, *field_keys)
        pipe.delete(*field_keys)
        pipe.execute()


def zhgetall(redis: Redis[bytes], key: str) -> list[bytes]:
    """
    Retrieves all sorted values from simulated sorted hash field
    """
    result = []

    def _zhgetall(pipe: Pipeline[bytes]) -> None:
        nonlocal result
        # NOTE: @ImmediatePipeline
        pipe_imm = cast('Redis[bytes]', pipe)
        field_keys = pipe_imm.zrange(key, 0, -1)
        if field_keys:
            values = pipe_imm.mget(*field_keys)
            # remove expired keys from set
            expired = [k for k, v in zip(field_keys, values) if v is None]
            if expired:
                pipe.multi()
                pipe.zrem(key, *expired)
            result = [v for v in values if v is not None]

    redis.transaction(_zhgetall, key)  # type:ignore[no-untyped-call]
    return result


def shaddex(
    redis: Redis[bytes],
    key:   str,
    field: str,
    ttl:   int,
    value: _Value
) -> None:
    """
    Simulates a hash field with expiration, quicker than sorted variant.
    Useful if you don't need to limit members in the hash field.
    """
    field_key = f'{{{key}}}{field}'
    with redis.pipeline() as pipe:
        pipe.sadd(key, field_key)
        pipe.setex(field_key, ttl, value)
        pipe.execute()


def shttl(redis: Redis[bytes], key: str, field: str) -> int:
    """
    Returns time to live on hash field
    """
    field_key = f'{{{key}}}{field}'
    return redis.ttl(field_key)


def shmod(redis: Redis[bytes], key: str, field: str, value: _Value) -> None:
    """
    Modifies existing entry on hash field
    if no entry exists, it does nothing
    """
    def _shmod(pipe: Pipeline[str]) -> None:
        # NOTE: @ImmediatePipeline
        pipe_imm = cast('Redis[str]', pipe)
        field_key = f'{{{key}}}{field}'
        ttl = pipe_imm.ttl(field_key)
        if ttl > 0:
            pipe.setex(field_key, ttl, value)

    redis.transaction(_shmod, key)  # type:ignore[no-untyped-call]


def shdel(redis: Redis[bytes], key: str, *fields: str) -> None:
    """
    Deletes simulated hash fields
    """
    field_keys = [f'{{{key}}}{f}' for f in fields]
    with redis.pipeline() as pipe:
        pipe.srem(key, *field_keys)
        pipe.delete(*field_keys)
        pipe.execute()


def shget(redis: Redis[bytes], key: str, field: str) -> bytes | None:
    """
    Retrieves simulated hash field value for key
    """
    field_key = f'{{{key}}}{field}'
    return redis.get(field_key)


def shgetall(redis: Redis[bytes], key: str) -> list[bytes]:
    """
    Retrieves simulated hash field value list
    """
    result = []

    def _shgetall(pipe: Pipeline[bytes]) -> None:
        nonlocal result
        # NOTE: @ImmediatePipeline
        pipe_imm = cast('Redis[bytes]', pipe)
        field_keys = pipe_imm.smembers(key)
        if field_keys:
            values = pipe_imm.mget(*field_keys)
            # remove expired keys from set
            expired = [k for k, v in zip(field_keys, values) if v is None]
            if expired:
                pipe.multi()
                pipe.srem(key, *expired)
            result = [v for v in values if v is not None]

    redis.transaction(_shgetall, key)  # type:ignore[no-untyped-call]
    return result
