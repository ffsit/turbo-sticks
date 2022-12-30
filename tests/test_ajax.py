import io
import json
import logging
from oauthlib.oauth2 import OAuth2Error

from turbo_sticks.ajax import api_call, auth_api_call, reset_app_password
from turbo_sticks.csrf import TokenClerk
from turbo_sticks.enums import ACL
from turbo_sticks.db import DBError
from turbo_sticks.session import get_session
from turbo_sticks.user import User


def test_api_call(api_calls):
    assert api_calls == {}

    @api_call('test')
    def test(env, csrf_clerk):
        return {'message': 'hello world'}, '200 OK'

    assert len(api_calls) == 1
    assert api_calls['test'] is test
    # we don't really do anyting with the csrf clerk here
    # so we just pass None for simplicity
    body, headers, status = test({}, None)
    assert body == b'{"message": "hello world"}'
    assert headers == [
        ('Content-Type', 'application/json'),
        ('Content-Length', str(len(body))),
    ]
    assert status == '200 OK'


def test_api_call_db_error(caplog):
    @api_call('db_error')
    def db_error(env, csrf_clerk):
        raise DBError()

    caplog.set_level(logging.DEBUG, logger='sticks.api')
    body, headers, status = db_error({}, None)
    assert body == b'{"error": "A database error has occured."}'
    assert status == '500 Internal Server Error'
    assert 'Database Error occured' in caplog.messages[-1]


def test_api_call_oauth_error(caplog):
    @api_call('oauth_error')
    def oauth_error(env, csrf_clerk):
        raise OAuth2Error()

    caplog.set_level(logging.DEBUG, logger='sticks.api')
    body, headers, status = oauth_error({}, None)
    assert body == b'{"error": "Failed to complete OAuth 2.0 handshake."}'
    assert status == '403 Forbidden'
    assert 'OAuth 2.0 Error occured' in caplog.messages[-1]


def test_api_call_unexpected_error(caplog):
    @api_call('unexpected_error')
    def unexpected_error(env, csrf_clerk):
        raise Exception()

    caplog.set_level(logging.DEBUG, logger='sticks.api')
    body, headers, status = unexpected_error({}, None)
    assert body == b'{"error": "An unexpected error has occured."}'
    assert status == '500 Internal Server Error'
    assert 'Unexpected Error occured' in caplog.messages[-1]


def test_auth_api_call(env):
    @auth_api_call('test', status='201 Created')
    def test(post_vars, user):
        return {'username': user.username}

    csrf_clerk = TokenClerk()
    session = get_session(env)
    csrf_token = csrf_clerk.register(session)
    # put csrf token into the request's environment
    request_body = f'csrf_token={csrf_token}'.encode('utf-8')
    env['wsgi.input'] = io.BytesIO(request_body)
    env['CONTENT_LENGTH'] = str(len(request_body))
    body, headers, status = test(env, csrf_clerk)
    assert status == '201 Created'
    data = json.loads(body.decode('utf-8'))
    assert data['username'] == 'test'
    assert data['csrf_token'] != csrf_token
    assert csrf_clerk.validate(session, data['csrf_token'])


def test_auth_api_call_no_csrf_check(env):
    @auth_api_call('test', csrf_check=False)
    def test(post_vars, user):
        return {'username': user.username}

    csrf_clerk = TokenClerk()
    env['wsgi.input'] = io.BytesIO()
    env['CONTENT_LENGTH'] = '0'
    body, headers, status = test(env, csrf_clerk)
    assert body == b'{"username": "test"}'
    assert status == '200 OK'


def test_auth_api_call_invalid_csrf_token(env):
    @auth_api_call('test')
    def test(post_vars, user):
        pass

    csrf_clerk = TokenClerk()
    env['wsgi.input'] = io.BytesIO()
    env['CONTENT_LENGTH'] = '0'
    body, headers, status = test(env, csrf_clerk)
    assert body == b'{"error": "CSRF token verification failed."}'
    assert status == '403 Forbidden'


def test_auth_api_call_no_account():
    @auth_api_call('test')
    def test(post_vars, user):
        pass

    csrf_clerk = TokenClerk()
    body, headers, status = test({'wsgi.input': io.BytesIO()}, csrf_clerk)
    assert body == b'{"error": "Couldn\'t authenticate user."}'
    assert status == '403 Forbidden'


def test_auth_api_call_min_access_level(env):
    # for simplicity we also skip csrf_check
    @auth_api_call('test', min_access_level=ACL.moderator, csrf_check=False)
    def test(post_vars, user):
        pass

    csrf_clerk = TokenClerk()
    env['wsgi.input'] = io.BytesIO()
    env['CONTENT_LENGTH'] = '0'
    body, headers, status = test(env, csrf_clerk)
    assert body == b'{"error": "You do not have the required permissions."}'
    assert status == '403 Forbidden'


def test_reset_app_password(env, user):
    old_password = user.app_password_plain
    csrf_clerk = TokenClerk()
    session = get_session(env)
    csrf_token = csrf_clerk.register(session)
    # put csrf token into the request's environment
    request_body = f'csrf_token={csrf_token}'.encode('utf-8')
    env['wsgi.input'] = io.BytesIO(request_body)
    env['CONTENT_LENGTH'] = str(len(request_body))
    body, headers, status = reset_app_password(env, csrf_clerk)
    data = json.loads(body.decode('utf-8'))
    new_password = data['app_password']
    assert new_password != old_password
    user.reload()
    assert user.app_password_plain == new_password
