import io
from unittest.mock import Mock

from turbo_sticks.csrf import TokenClerk
from turbo_sticks.session import get_session
from turbo_sticks.wsgi import WSGIApplication


def test_route_main_view(db):
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk)
    start_response = Mock()
    env = {
        'PATH_INFO': '/',
        'QUERY_STRING': '',
        'CONTENT_LENGTH': '0',
        'wsgi.input': io.BytesIO(),
    }
    content_parts = application(env, start_response)
    assert len(content_parts) == 1
    content = content_parts[0]
    start_response.assert_called_once_with(
        '200 OK',
        [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(content))),
        ]
    )
    assert b'Login using TURBO Toot' in content


def test_unknown_route(db):
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk)
    start_response = Mock()
    env = {
        'PATH_INFO': '/unknown',
        'QUERY_STRING': '',
        'CONTENT_LENGTH': '0',
        'wsgi.input': io.BytesIO(),
    }
    content_parts = application(env, start_response)
    assert len(content_parts) == 1
    content = content_parts[0]
    start_response.assert_called_once_with(
        '404 Not Found',
        [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(content))),
        ]
    )
    assert b'The requested page or resource doesn\'t exist' in content


def test_route_api_password_reset(env, user):
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk)
    start_response = Mock()

    session = get_session(env)
    csrf_token = csrf_clerk.register(session)
    # put csrf token into the request's environment
    request_body = f'csrf_token={csrf_token}'.encode('utf-8')
    env['PATH_INFO'] = '/api/reset_app_password'
    env['QUERY_STRING'] = ''
    env['CONTENT_LENGTH'] = str(len(request_body))
    env['wsgi.input'] = io.BytesIO(request_body)
    content_parts = application(env, start_response)
    assert len(content_parts) == 1
    content = content_parts[0]
    start_response.assert_called_once_with(
        '200 OK',
        [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(content))),
        ]
    )
    assert b'"app_password":' in content


def test_route_api_call_unknown(db):
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk)
    start_response = Mock()

    env = {
        'PATH_INFO': '/api/unknown',
        'QUERY_STRING': '',
        'CONTENT_LENGTH': '0',
        'wsgi.input': io.BytesIO(),
    }
    content_parts = application(env, start_response)
    assert len(content_parts) == 1
    content = content_parts[0]
    start_response.assert_called_once_with(
        '404 Not Found',
        [
            ('Content-Type', 'application/json'),
            ('Content-Length', str(len(content))),
        ]
    )
    assert content == b'{"error": "Unknown API call."}'


def test_route_websocket(db, monkeypatch):
    # we don't actually want to open a websocket
    open_websocket = Mock()
    monkeypatch.setattr(
        'turbo_sticks.websockets.Channel.open_websocket',
        open_websocket
    )
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk)
    start_response = Mock()
    env = {
        'PATH_INFO': '/websockets/webchat',
        'QUERY_STRING': '',
        'CONTENT_LENGTH': '0',
        'wsgi.input': io.BytesIO(),
    }
    assert application(env, start_response) == []
    open_websocket.assert_called_once_with(env)
    start_response.assert_not_called()


def test_route_websocket_websockets_disabled(db, monkeypatch):
    # we don't actually want to open a websocket
    open_websocket = Mock()
    monkeypatch.setattr(
        'turbo_sticks.websockets.Channel.open_websocket',
        open_websocket
    )
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk, websockets=False)
    start_response = Mock()
    env = {
        'PATH_INFO': '/websockets/webchat',
        'QUERY_STRING': '',
        'CONTENT_LENGTH': '0',
        'wsgi.input': io.BytesIO(),
    }
    content_parts = application(env, start_response)
    assert len(content_parts) == 1
    content = content_parts[0]
    open_websocket.assert_not_called()
    start_response.assert_called_once_with(
        '404 Not Found',
        [
            ('Content-Type', 'text/html'),
            ('Content-Length', str(len(content))),
        ]
    )


def test_application_shutdown(db, monkeypatch):
    channel = Mock()
    monkeypatch.setattr('turbo_sticks.wsgi.channels', [channel])
    csrf_clerk = TokenClerk()
    application = WSGIApplication(csrf_clerk)
    application.shutdown()
    channel.close.assert_called_once_with()
    db.close.assert_called_once_with()
