import pytest
from unittest.mock import Mock

import turbo_sticks
from turbo_sticks.discord import (
    add_turbo_role, get_avatar_url, get_member, get_role, get_roles, get_user,
    remove_turbo_role, render_roles, render_username, request_headers
)


@pytest.fixture
def mock_get_roles(monkeypatch):
    mock_get_roles = Mock(return_value=[
        {'id': 1, 'name': 'shadow', 'color': 0},
        {'id': 2, 'name': 'turbo', 'color': 0x0000ff},
        {'id': 4, 'name': 'mod', 'color': 0x00ff00},
    ])
    # make sure this gets cleaned up at the end of the test
    monkeypatch.setattr('turbo_sticks.discord._roles', None)
    monkeypatch.setattr('turbo_sticks.discord.get_roles', mock_get_roles)
    return mock_get_roles


def test_request_headers():
    assert 'Authorization' in request_headers
    assert request_headers['Authorization'] == 'Bot test_bot_token'
    assert 'User-Agent' in request_headers
    assert 'TURBOSticks' in request_headers['User-Agent']
    assert turbo_sticks.__version__ in request_headers['User-Agent']


def test_get_member(monkeypatch):
    response = Mock()
    get = Mock(return_value=response)
    monkeypatch.setattr('requests.get', get)
    assert get_member(None) is None
    get.assert_not_called()

    assert isinstance(get_member(12), Mock)
    get.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/12',
        headers=request_headers,
        timeout=(5, 10)
    )
    response.json.assert_called_once()


def test_get_user():
    assert get_user(None) is None

    member = {
        'roles': [],
        'joined_at': '2020-02-04 12:13:14',
        'deaf': False,
        'mute': False,
    }
    assert get_user(member) is None

    user = {
        'id': 1,
        'username': 'test',
        'discriminator': '1234',
        'avatar': None,
    }
    member['user'] = user
    assert get_user(member) == user


def test_get_roles(monkeypatch):
    response = Mock()
    get = Mock(return_value=response)
    monkeypatch.setattr('requests.get', get)
    assert isinstance(get_roles(), Mock)
    get.assert_called_once_with(
        'https://discord.com/test/guilds/1/roles',
        headers=request_headers,
        timeout=(5, 10)
    )
    response.json.assert_called_once()


def test_get_role(mock_get_roles):
    assert get_role(0) == {'name': '', 'color': 0}
    assert get_role(1) == {'id': 1, 'name': 'shadow', 'color': 0}
    assert get_role(2) == {'id': 2, 'name': 'turbo', 'color': 0x0000ff}
    assert get_role(3) == {'name': '', 'color': 0}
    assert get_role(4) == {'id': 4, 'name': 'mod', 'color': 0x00ff00}
    assert get_role(5) == {'name': '', 'color': 0}
    mock_get_roles.assert_called_once()


def test_get_avatar_url():
    assert get_avatar_url(None) == (
        'https://cdn.discordapp.com/embed/avatars/1.png'
    )

    user = {
        'id': 1,
        'username': 'test',
        'discriminator': '0004',
        'avatar': None,
    }
    assert get_avatar_url(user) == (
        'https://cdn.discordapp.com/embed/avatars/4.png'
    )

    user['discriminator'] = '1337'
    assert get_avatar_url(user) == (
        'https://cdn.discordapp.com/embed/avatars/2.png'
    )

    user['avatar'] = 'cafebabe'
    assert get_avatar_url(user) == (
        'https://cdn.discordapp.com/avatars/1/cafebabe.png'
    )

    user['id'] = 22
    assert get_avatar_url(user) == (
        'https://cdn.discordapp.com/avatars/22/cafebabe.png'
    )


def test_render_username():
    assert 'Not connected' in render_username(None)

    user = {
        'id': 1,
        'username': 'test',
        'discriminator': '0004',
        'avatar': None,
    }
    rendered = render_username(user)
    assert 'test' in rendered
    assert '#0004' in rendered


def test_render_roles(mock_get_roles):
    assert render_roles(None) == ''

    member = {
        'roles': [],
        'joined_at': '2020-02-04 12:13:14',
        'deaf': False,
        'mute': False,
    }
    assert render_roles(member) == ''

    member['roles'].append(1)
    rendered = render_roles(member)
    assert 'color:#000000' in rendered
    assert 'shadow' in rendered
    assert '&emsp;' not in rendered

    member['roles'].append(2)
    rendered = render_roles(member)
    assert 'color:#000000' in rendered
    assert 'shadow' in rendered
    assert '&emsp;' in rendered
    assert 'color:#0000FF' in rendered
    assert 'turbo' in rendered


def test_add_turbo_role(monkeypatch):
    response = Mock()
    put = Mock(return_value=response)
    monkeypatch.setattr('requests.put', put)
    response.status_code = 404
    assert add_turbo_role(22) is False
    put.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/22/roles/2',
        json={},
        headers=request_headers,
        timeout=(5, 30)
    )

    put.reset_mock()
    response.status_code = 204
    assert add_turbo_role(14) is True
    put.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/14/roles/2',
        json={},
        headers=request_headers,
        timeout=(5, 30)
    )

    put.reset_mock()
    token = {
        'access_token': 'deadbeef',
        'token_type': 'Bearer',
    }
    assert add_turbo_role(36, token) is True
    assert put.call_count == 2
    put.assert_any_call(
        'https://discord.com/test/guilds/1/members/36',
        json={'access_token': 'deadbeef'},
        headers=request_headers,
        timeout=(5, 30)
    )
    put.assert_any_call(
        'https://discord.com/test/guilds/1/members/36/roles/2',
        json={},
        headers=request_headers,
        timeout=(5, 30)
    )


def test_remove_turbo_role(monkeypatch, caplog):
    get_response = Mock()
    get = Mock(return_value=get_response)
    monkeypatch.setattr('requests.get', get)
    delete_response = Mock()
    delete = Mock(return_value=delete_response)
    monkeypatch.setattr('requests.delete', delete)

    get_response.json.return_value = {}
    get_response.status_code = 404
    assert remove_turbo_role(12) is True
    get.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/12',
        headers=request_headers,
        timeout=(5, 10)
    )
    delete.assert_not_called()

    get.reset_mock()
    get_response.json.return_value = {'key': 10007}
    get_response.status_code = 200
    assert remove_turbo_role(24) is True
    get.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/24',
        headers=request_headers,
        timeout=(5, 10)
    )
    delete.assert_not_called()

    get.reset_mock()
    get_response.json.return_value = {}
    delete_response.status_code = 204
    assert remove_turbo_role(36) is True
    get.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/36',
        headers=request_headers,
        timeout=(5, 10)
    )
    delete.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/36/roles/2',
        headers=request_headers,
        timeout=(5, 30)
    )

    get.reset_mock()
    delete.reset_mock()
    delete_response.status_code = 500
    delete_response.json.return_value = {'message': 'Service unavailable.'}
    assert remove_turbo_role(48) is False
    get.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/48',
        headers=request_headers,
        timeout=(5, 10)
    )
    delete.assert_called_once_with(
        'https://discord.com/test/guilds/1/members/48/roles/2',
        headers=request_headers,
        timeout=(5, 30)
    )
    assert 'Discord Error: Service unavailable.' in caplog.text
