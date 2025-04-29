import glob
import json
import io
import os.path
import pytest
from _pytest.monkeypatch import MonkeyPatch
from contextlib import contextmanager
from unittest.mock import Mock


mpatch = MonkeyPatch()
here = os.path.abspath(os.path.dirname(__file__))


def pytest_sessionstart(session):
    # NOTE: We have to patch STICKS_CONFIG at session start
    config_path = os.path.join(here, 'fixtures', 'test-config.yaml')
    mpatch.setenv('STICKS_CONFIG', config_path)


def pytest_sessionfinish(session, exitstatus):
    mpatch.undo()

    # Clean up dpytest attachment files
    files = glob.glob('./dpytest_*.dat')
    for path in files:
        try:
            os.remove(path)
        except Exception as e:
            print(f"Error while deleting file {path}: {e}")


@pytest.fixture
def json_fixture():
    def json_fixture_loader(name):
        with open(os.path.join(here, 'fixtures', name)) as fp:
            return json.loads(fp.read())

    return json_fixture_loader


@pytest.fixture
def patch_config():
    from turbo_sticks.config import patch_config
    yield patch_config


@pytest.fixture
def db(postgresql, monkeypatch):
    import turbo_sticks.db

    class TestDBSession:
        init_pool = Mock()
        start_checks = Mock()
        close = Mock()

        @contextmanager
        def connection(self):
            yield postgresql
            postgresql.commit()

    db_schema = os.path.join(here, '..', 'setup', 'initdb.sql')
    with open(db_schema) as fp:
        with postgresql.cursor() as cur:
            cur.execute(fp.read())
        postgresql.commit()
    db = TestDBSession()
    monkeypatch.setattr(turbo_sticks.db.DBSession, '_instance', db)
    yield db


@pytest.fixture
def account():
    # minimal account object containing all the keys we care about
    return {
        'id': '1',
        'username': 'test',
        'acct': 'test',
        'display_name': 'Test',
        'avatar_static': 'http://example.com/test.png',
        'locked': False,
    }


@pytest.fixture
def env(db, account, monkeypatch):
    # minimal env object for authenticated session
    from turbo_sticks.session import create_session
    session = create_session({
        'access_token': 'access_token',
        'token_type': 'Bearer',
        'expires_in': '600'
    })
    mock_response = Mock()
    mock_response.json.return_value = account
    mock_session = Mock()
    mock_session.get.return_value = mock_response
    mock_session.authorization_url.return_value = (
        'https://example.com/mock_authorization',
        'mock_state',
    )
    monkeypatch.setattr(
        'turbo_sticks.session.OAuth2Session',
        Mock(return_value=mock_session)
    )

    return {
        'HTTP_COOKIE': f'TB_SESSION={session}',
        'QUERY_STRING': '',
        'CONTENT_LENGTH': '0',
        'wsgi.input': io.BytesIO()
    }


@pytest.fixture
def user(db, account):
    from turbo_sticks.user import User
    return User(account)


@pytest.fixture(autouse=True)
def properties(monkeypatch):
    # ensure properties use a fresh cache each test run
    cache = {}
    monkeypatch.setattr('turbo_sticks.properties._cache', cache)
    yield cache


@pytest.fixture(autouse=True)
def api_calls(monkeypatch):
    # ensure api_calls can be added by tests without side-effects
    api_calls = {}
    monkeypatch.setattr('turbo_sticks.ajax.api_calls', api_calls)
    yield api_calls


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    # prevents tests from making live requests
    monkeypatch.delattr('requests.sessions.Session.request')
