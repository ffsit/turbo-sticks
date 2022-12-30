import pytest
from time import sleep
from unittest.mock import Mock

from turbo_sticks.csrf import TokenClerk
from turbo_sticks.session import (
    create_session, delete_session, get_session,
    generate_oauth_state, retrieve_oauth_account,
    retrieve_oauth_state, retrieve_token_from_session,
)
from turbo_sticks.util import encrypt


def test_create_session(db, time_machine):
    time_machine.move_to(0.0, tick=False)
    oauth_token = {
        'access_token': 'access_token',
        'token_type': 'Bearer',
    }
    token_1 = create_session(oauth_token)
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                        SELECT session_token,
                               access_token,
                               refresh_token,
                               token_type,
                               token_expires_on
                          FROM sessions""")
            rows = cur.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == token_1
    assert rows[0][1] == 'access_token'
    assert rows[0][2] == ''
    assert rows[0][3] == 'Bearer'
    assert rows[0][4] == 3600

    time_machine.move_to(3600.0)
    oauth_token['refresh_token'] = 'refresh_token'
    oauth_token['expires_in'] = '1600'
    token_2 = create_session(oauth_token)
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                        SELECT session_token,
                               access_token,
                               refresh_token,
                               token_type,
                               token_expires_on
                          FROM sessions""")
            rows = cur.fetchall()
    assert len(rows) == 2
    assert rows[0][0] == token_1
    assert rows[0][1] == 'access_token'
    assert rows[0][2] == ''
    assert rows[0][3] == 'Bearer'
    assert rows[0][4] == 3600
    assert rows[1][0] == token_2
    assert rows[1][1] == 'access_token'
    assert rows[1][2] == 'refresh_token'
    assert rows[1][3] == 'Bearer'
    assert rows[1][4] == 5200


def test_delete_session(db):
    oauth_token = {
        'access_token': 'access_token',
        'token_type': 'Bearer',
    }
    token = create_session(oauth_token)
    assert retrieve_token_from_session(token) is not None

    delete_session(None)
    assert retrieve_token_from_session(token) is not None

    delete_session(token)
    assert retrieve_token_from_session(token) is None


def test_get_session():
    env = {}
    assert get_session(env) is None

    env['HTTP_COOKIE'] = ''
    assert get_session(env) is None

    env['HTTP_COOKIE'] = 'TB_SESSION=token'
    assert get_session(env) == 'token'


def test_retrieve_token_from_session(db, time_machine):
    time_machine.move_to(0.0, tick=False)
    assert retrieve_token_from_session(None) is None

    oauth_token = {
        'access_token': 'access_token',
        'token_type': 'Bearer',
    }
    token_1 = create_session(oauth_token)
    assert retrieve_token_from_session(token_1) == {
        'access_token': 'access_token',
        'refresh_token': '',
        'token_type': 'Bearer',
        'expires_in': '3600'
    }

    time_machine.move_to(1800.0, tick=False)
    assert retrieve_token_from_session(token_1) == {
        'access_token': 'access_token',
        'refresh_token': '',
        'token_type': 'Bearer',
        'expires_in': '1800'
    }

    oauth_token['refresh_token'] = 'refresh_token'
    oauth_token['expires_in'] = 1600
    token_2 = create_session(oauth_token)
    assert retrieve_token_from_session(token_2) == {
        'access_token': 'access_token',
        'refresh_token': 'refresh_token',
        'token_type': 'Bearer',
        'expires_in': '1600'
    }

    time_machine.move_to(2800.0, tick=False)
    assert retrieve_token_from_session(token_2) == {
        'access_token': 'access_token',
        'refresh_token': 'refresh_token',
        'token_type': 'Bearer',
        'expires_in': '600'
    }


# NOTE: This depends on postgresql time functions, so potentially flaky
@pytest.mark.flaky
def test_retrieve_token_from_session_expiration(db, patch_config):
    with patch_config(session={'max_age': 1}):
        oauth_token = {
            'access_token': 'access_token',
            'token_type': 'Bearer',
        }
        token_1 = create_session(oauth_token)
        sleep(1)
        assert retrieve_token_from_session(token_1) is None


def test_retrieve_oauth_account(db, time_machine, monkeypatch):
    account = {}
    time_machine.move_to(0.0, tick=False)
    mock_response = Mock()
    mock_response.json.return_value = account
    mock_session = Mock()
    mock_session.get.return_value = mock_response
    monkeypatch.setattr(
        'turbo_sticks.session.OAuth2Session',
        Mock(return_value=mock_session)
    )

    assert retrieve_oauth_account(None) is None
    assert retrieve_oauth_account('bogus') is None

    oauth_token = {
        'access_token': 'access_token',
        'token_type': 'Bearer',
        'expires_in': '600'
    }
    token = create_session(oauth_token)
    assert retrieve_oauth_account(token) is None

    account['id'] = '1'
    account['username'] = 'test'
    assert retrieve_oauth_account(token) is None

    account['acct'] = 'test'
    assert retrieve_oauth_account(token) == account

    account['moved'] = {}
    assert retrieve_oauth_account(token) is None

    del account['moved']
    assert retrieve_oauth_account(token) == account

    account['bot'] = True
    assert retrieve_oauth_account(token) is None

    account['bot'] = False
    assert retrieve_oauth_account(token) == account

    account['suspended'] = True
    assert retrieve_oauth_account(token) is None

    account['suspended'] = False
    assert retrieve_oauth_account(token) == account
    mock_session.refresh_token.assert_not_called()

    time_machine.move_to(601.0, tick=False)
    assert retrieve_oauth_account(token) == account
    mock_session.refresh_token.assert_called_once()


def test_generate_oauth_state():
    env = {'QUERY_STRING': '', 'PATH_INFO': '/'}
    clerk = TokenClerk()
    state = generate_oauth_state(env, clerk)
    assert len(clerk.tokens) == 1

    csrf_token, redirect_to = retrieve_oauth_state(state)
    assert csrf_token in clerk.tokens
    assert redirect_to == '/'

    env['QUERY_STRING'] = 'redirect_to=%2Ftheatre'
    state = generate_oauth_state(env, clerk)
    assert len(clerk.tokens) == 2

    csrf_token, redirect_to = retrieve_oauth_state(state)
    assert csrf_token in clerk.tokens
    assert redirect_to == '/theatre'


def test_retrieve_oauth_state():
    assert retrieve_oauth_state('bogus') == (None, None)
    assert retrieve_oauth_state(encrypt('["csrf_token"]')) == (None, None)
    assert retrieve_oauth_state(
        encrypt('["csrf_token", "redirect_to"]')
    ) == ('csrf_token', 'redirect_to')
