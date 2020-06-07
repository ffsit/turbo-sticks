import sys
import traceback
import json
import http
from Crypto.Cipher import AES
from html import escape
from urllib.parse import parse_qs, quote_plus, urlencode
from os import urandom, listdir, path
from fnmatch import fnmatch
from redis import WatchError

import turbo_config as config

# Exports
escape
quote_plus
urlencode


# General Helpers
def print_info(info, debug_message=True, **kwargs):
    if not debug_message or config.debug_mode:
        print('========================================')
        print(info)
        print('========================================')


def print_exception(title, exception, debug_message=True, **kwargs):
    if not debug_message or config.debug_mode:
        print('========================================')
        print(title)
        print(exception)
        print_traceback = kwargs.get('print_traceback', True)
        if print_traceback or config.debug_mode:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_tb(exc_traceback)
        print('========================================')


def sub_title(sub_title, title=config.page_title):
    return sub_title + ' - ' + title


# Crypto Helpers
def generate_random_token(length):
    return urandom(length//2).hex()


def encrypt(plaintext):
    iv = urandom(16)
    key = config.app_secret.encode('utf-8')[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.encrypt(plaintext.encode('utf-8')).hex() + iv.hex()


def decrypt(ciphertext):
    iv = bytes.fromhex(ciphertext[-32:])
    key = config.app_secret.encode('utf-8')[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(bytes.fromhex(ciphertext[:-32])).decode('utf-8')


# Web Server Helpers
def retrieve_get_vars(env):
    return parse_qs(env['QUERY_STRING'], encoding='utf-8')


def retrieve_request_body(env):
    try:
        request_body_size = int(env.get('CONTENT_LENGTH', 0))
    except (ValueError):
        request_body_size = 0
    return env['wsgi.input'].read(request_body_size)


def retrieve_post_vars(env):
    request_body = retrieve_request_body(env)
    return parse_qs(request_body.decode('utf-8'))


def retrieve_cookies(env):
    cookies = http.cookies.SimpleCookie()
    cookies.load(env.get('HTTP_COOKIE', ''))
    return cookies


def set_cookie_header(name, value, path='/',
                      max_age=config.session_max_age):
    # TODO: Add SameSite parameter. Needs filter for old Safari versions.
    #       See https://bugs.webkit.org/show_bug.cgi?id=198181
    return (
        'Set-Cookie',
        f'{name}={value}; Domain={config.cookie_scope}; '
        f'Max-Age={max_age}; Path={path}; Secure; HttpOnly;'
    )


def unset_cookie_header(name, path='/'):
    # NOTE: this might need SameSite as well to unset, once added
    return (
        'Set-Cookie',
        f'{name}=unset; Domain={config.cookie_scope}; '
        f'Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path={path}; '
        'Secure; HttpOnly;'
    )


def basic_response_header(response_body, send_length=True):
    if(send_length):
        return [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(response_body)))
        ]
    else:
        return [('Content-Type', 'text/html')]


def generate_json_response(data, status='200 OK'):
    response_body = json.dumps(data).encode('utf-8')
    response_headers = [
        ('Content-Type', 'application/json'),
        ('Content-Length', str(len(response_body)))
    ]
    return response_body, response_headers, status


def get_default_embed(sources):
    if(len(sources) > 0 and sources[0]['embed_type'] == 'html'):
        return sources[0]['embed']
    return ''


def generate_video_sources(sources):
    if(len(sources) > 0):
        return json.dumps(sources)
    return '[]'


def build_url(path, base=None, query=None):
    assert base in [None, 'base', 'api', 'websockets']
    query_str = ''
    if isinstance(query, dict):
        query_parts = []
        for key, value in query.items():
            query_parts.append(f'{key}={value}')
        query_str = '&'.join(query_parts)
        query_str = '?' + quote_plus(query_str, '&=')
    scheme = config.web_scheme
    base_path = ''
    if base == 'base':
        base_path = config.base_path
    if base == 'api':
        base_path = config.api_path
    elif base == 'websockets':
        base_path = config.websockets_path
        scheme = config.websockets_scheme
    return f'{scheme}://{config.web_uri}{base_path}{path}{query_str}'


# File Helpers
def files(source_path, pattern='*'):
    for entry in listdir(source_path):
        if fnmatch(entry, pattern):
            file_path = path.join(source_path, entry)
            if path.isfile(file_path):
                yield file_path


css_version = 0
js_version = 0


def get_css_version():
    global css_version
    pattern = '*.css'
    if css_version == 0:
        for file_path in files('./static', pattern):
            css_version = max(css_version, int(path.getmtime(file_path)))
    return css_version


def get_js_version():
    global js_version
    pattern = '*.js'
    if js_version == 0:
        for file_path in files('./static', pattern):
            js_version = max(js_version, int(path.getmtime(file_path)))
    return js_version


# Custom Redis transactions

# simulates a sorted hash set with field expiration
# if set contains more elements than max_cardinality
# the elements with the lowest scores get removed
def zhaddex(redis, key, field, ttl, value, score, max_cardinality=0):
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                field_key = f'{{{key}}}{field}'
                if max_cardinality > 0:
                    diff = pipe.zcard(key) - max_cardinality
                    if diff >= 0:
                        remove = pipe.zrange(key, 0, diff+1)
                        pipe.zrem(key, *remove)
                        pipe.delete(*remove)
                pipe.zadd(key, {field_key: score})
                pipe.setex(field_key, ttl, value)
                break
            except WatchError:
                continue


# return time to live on sorted hash field
def zhttl(redis, key, field):
    field_key = f'{{{key}}}{field}'
    return redis.ttl(field_key)


# modifies existing entry, if no entry exists, it does nothing
def zhmod(redis, key, field, value):
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                field_key = f'{{{key}}}{field}'
                ttl = pipe.ttl(field_key)
                if ttl > 0:
                    pipe.setex(field_key, ttl, value)
                break
            except WatchError:
                continue


# delete simulated sorted hash fields
def zhdel(redis, key, *fields):
    with redis.pipeline() as pipe:
        while True:
            try:
                field_keys = [f'{{{key}}}{f}' for f in fields]
                pipe = redis.pipeline()
                pipe.zrem(key, *field_keys)
                pipe.delete(*field_keys)
                pipe.execute()
                break
            except WatchError:
                continue


# retrieve simulated sorted hash field list
def zhgetall(redis, key):
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                field_keys = pipe.zrange(key, 0, -1)
                if field_keys:
                    values = pipe.mget(*field_keys)
                    # remove expired keys from set
                    expired = [k for k, v in zip(field_keys, values)
                               if v is None]
                    if expired:
                        pipe.zrem(
                            key,
                            *expired
                        )
                    return [v for v in values if v is not None]
                else:
                    return []
            except WatchError:
                continue


# simulates a basic hash field with expiration, quicker than sorted variant.
# useful if you don't need to limit members in the hash field.
def shaddex(redis, key, field, ttl, value):
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                field_key = f'{{{key}}}{field}'
                pipe.sadd(key, field_key)
                pipe.setex(field_key, ttl, value)
                break
            except WatchError:
                continue


# return time to live on hash field
def shttl(redis, key, field):
    field_key = f'{{{key}}}{field}'
    return redis.ttl(field_key)


# modifies existing hash field, if field doesn't exist, it does nothing
def shmod(redis, key, field, value):
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                field_key = f'{{{key}}}{field}'
                ttl = pipe.ttl(field_key)
                if ttl > 0:
                    pipe.setex(field_key, ttl, value)
                break
            except WatchError:
                continue


# delete simulated hash fields
def shdel(redis, key, *fields):
    with redis.pipeline() as pipe:
        while True:
            try:
                field_keys = [f'{{{key}}}{f}' for f in fields]
                pipe = redis.pipeline()
                pipe.srem(key, *field_keys)
                pipe.delete(*field_keys)
                pipe.execute()
                break
            except WatchError:
                continue


# get simulated hash field value
def shget(redis, key, field):
    field_key = f'{{{key}}}{field}'
    return redis.get(field_key)


# retrieve simulated hash field list
def shgetall(redis, key):
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                field_keys = pipe.smembers(key)
                if field_keys:
                    values = pipe.mget(*field_keys)
                    # remove expired keys from set
                    expired = [k for k, v in zip(field_keys, values)
                               if v is None]
                    if expired:
                        pipe.srem(
                            key,
                            *expired
                        )
                    return [v for v in values if v is not None]
                else:
                    return []
            except WatchError:
                continue
