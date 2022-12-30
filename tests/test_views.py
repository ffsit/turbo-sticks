import logging
from oauthlib.oauth2 import OAuth2Error

from turbo_sticks.csrf import TokenClerk
from turbo_sticks.db import DBError
from turbo_sticks.enums import ACL
from turbo_sticks.views import (
    View, basic_page_data, view, auth_view, error_view, main_view,
    login_view, logout_view, oauth_callback_view, discord_callback_view,
    account_view, chat_view, headless_chat_view, frash_chat_view,
    stream_view, headless_stream_view, theatre_view, headless_theatre_view,
    theatre_admin_view, patreon_theatre_callback_view, rules_view
)


def unwrap_view(view_):
    # just a little helper to unwrap all the decorated views so
    # we can test just the logic we wrote for that specific view
    while hasattr(view_, '__wrapped__'):
        view_ = view_.__wrapped__
    return view_


def test_init_view():
    view_obj = View('Test', '/test')
    assert view_obj.display_name == 'Test'
    assert view_obj.path == '/test'
    assert view_obj.uri == 'https://example.com/test'
    assert view_obj.view is None
    view_obj = View('Test', '/test', uri='https://somewhere.else')
    assert view_obj.display_name == 'Test'
    assert view_obj.path == '/test'
    assert view_obj.uri == 'https://somewhere.else'
    assert view_obj.view is None


def test_basic_page_data():
    page_data = basic_page_data('main')
    assert page_data['title'] == 'Home - TURBO Sticks'
    assert page_data['description'] == 'Test description.'
    assert page_data['nav'] == ''
    assert page_data['main_path'] == '/'
    assert 'css_version' in page_data
    assert 'js_version' in page_data

    page_data = basic_page_data('bogus')
    assert page_data['title'] == 'Error - TURBO Sticks'


def test_view_with_db_error(caplog):
    @view
    def test(env, csrf_clerk):
        raise DBError()

    caplog.set_level(logging.DEBUG, logger='sticks.views')
    content, headers, status = test({}, None)
    assert b'A database error has occured.' in content
    assert status == '500 Internal Server Error'
    assert 'Database Error occured.' in caplog.messages[-1]


def test_view_with_oauth_error(caplog):
    @view
    def test(env, csrf_clerk):
        raise OAuth2Error()

    caplog.set_level(logging.DEBUG, logger='sticks.views')
    content, headers, status = test({}, None)
    assert b'Failed to complete OAuth 2.0 handshake.' in content
    assert status == '200 OK'
    assert 'OAuth 2.0 Error occured:' in caplog.messages[-1]


def test_view_with_unexpected_error(caplog):
    @view
    def test(env, csrf_clerk):
        raise Exception()

    caplog.set_level(logging.DEBUG, logger='sticks.views')
    content, headers, status = test({}, None)
    assert b'An unexpected error has occured.' in content
    assert status == '500 Internal Server Error'
    assert 'Unexpected Error occured.' in caplog.messages[-1]


def test_auth_view(env):
    _csrf_clerk = TokenClerk()

    @auth_view
    def test(env, get_vars, post_vars, csrf_clerk, session, user):
        assert get_vars == {}
        assert post_vars == {}
        assert csrf_clerk is _csrf_clerk
        assert session is not None
        assert user is not None
        assert user.username == 'test'
        return b'', [], '200 OK'

    assert test(env, _csrf_clerk) == (b'', [], '200 OK')


def test_auth_view_cookie_set(env):
    @auth_view
    def test(env, get_vars, post_vars, csrf_clerk, session, user):
        pass

    env['PATH_INFO'] = '/'
    env['QUERY_STRING'] = 'cookie_set=1'
    csrf_clerk = TokenClerk()
    content, headers, status = test(env, csrf_clerk)
    assert content == b''
    assert headers == [('Location', 'https://example.com/')]
    assert status == '307 Temporary Redirect'


def test_auth_view_access_level(env):
    @auth_view(min_access_level=ACL.moderator)
    def test(env, get_vars, post_vars, csrf_clerk, session, user):
        pass

    csrf_clerk = TokenClerk()
    content, headers, status = test(env, csrf_clerk)
    assert b'Missing Privileges' in content
    assert status == '403 Forbidden'


def test_auth_view_unauthenticated(env):
    @auth_view
    def test(env, get_vars, post_vars, csrf_clerk, session, user):
        pass

    # clear the cookie so we will be unauthenticated
    del env['HTTP_COOKIE']
    env['PATH_INFO'] = '/'
    csrf_clerk = TokenClerk()
    content, headers, status = test(env, csrf_clerk)
    assert content == b''
    assert headers == [('Location', 'https://example.com/mock_authorization')]
    assert status == '307 Temporary Redirect'


def test_auth_view_unauthenticated_cookie_set(env):
    @auth_view
    def test(env, get_vars, post_vars, csrf_clerk, session, user):
        pass

    # clear the cookie so we will be unauthenticated
    del env['HTTP_COOKIE']
    env['QUERY_STRING'] = 'cookie_set=1'
    csrf_clerk = TokenClerk()
    content, headers, status = test(env, csrf_clerk)
    assert b'Failed to create session.' in content


def test_auth_view_unauthenticated_headless(env):
    @auth_view(headless=True)
    def test(env, get_vars, post_vars, csrf_clerk, session, user):
        pass

    # clear the cookie so we will be unauthenticated
    del env['HTTP_COOKIE']
    csrf_clerk = TokenClerk()
    content, headers, status = test(env, csrf_clerk)
    assert b'You are not logged in.' in content
    assert status == '403 Forbidden'


def test_error_view_handles_internal_exception(monkeypatch, caplog):
    # do something that will cause an exception
    monkeypatch.setattr('turbo_sticks.templates.render', None)
    assert error_view('', '') == (b'', [], '500 Internal Server Error')
    assert 'Unexpected Error occured.' in caplog.messages[-1]
