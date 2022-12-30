import pytest
from unittest.mock import Mock

from turbo_sticks.patreon import (
    build_query, create_session, get_campaigns, get_current_token,
    get_current_user, get_members, init_oauth, sanitize_json, validate_session
)
from turbo_sticks.util import decrypt


@pytest.fixture
def sessions(monkeypatch):
    sessions = {}
    monkeypatch.setattr('turbo_sticks.patreon.sessions', sessions)
    return sessions


def test_create_session(sessions, time_machine):
    time_machine.move_to(0.0, tick=False)
    token = create_session()
    assert len(token) == 128
    assert len(sessions) == 1
    assert sessions[token] == 0.0

    time_machine.move_to(1000.0, tick=False)
    token = create_session()
    assert len(token) == 128
    assert len(sessions) == 2
    assert sessions[token] == 1000.0


def test_validate_session(sessions, time_machine):
    time_machine.move_to(0.0, tick=False)
    env = {}
    assert validate_session(env) is False

    env['HTTP_COOKIE'] = 'TB_PATREON_SESSION=token'
    assert validate_session(env) is False

    sessions['token'] = 0.0
    assert validate_session(env) is True

    time_machine.move_to(3600.0, tick=False)
    assert validate_session(env) is False
    assert 'token' not in sessions


def test_init_oauth(db):
    init_oauth()

    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT access_token, refresh_token, token_expires_on
                FROM oauth WHERE app_name = 'patreon'
            """)

            access_token, refresh_token, token_expires_on = cur.fetchone()

    assert decrypt(access_token) == 'test_access_token'
    assert decrypt(refresh_token) == 'test_refresh_token'
    assert token_expires_on is None


def test_init_oauth_already_inited(db):
    # NOTE: For simplicity we don't encrypt these dummy values
    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO oauth(
                    app_name, access_token, refresh_token, token_expires_on
                )
                VALUES(
                    'patreon',
                    'existing_access_token',
                    'existing_refresh_token',
                    3600
                )
            """)

    init_oauth()

    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT access_token, refresh_token, token_expires_on
                FROM oauth WHERE app_name = 'patreon'
            """)

            access_token, refresh_token, token_expires_on = cur.fetchone()

    assert access_token == 'existing_access_token'
    assert refresh_token == 'existing_refresh_token'
    assert token_expires_on == 3600


def test_get_current_token(db, monkeypatch, time_machine):
    time_machine.move_to(0.0, tick=False)
    client = Mock()
    session = Mock(return_value=client)
    monkeypatch.setattr('turbo_sticks.patreon.OAuth2Session', session)

    client.refresh_token.return_value = {
        'access_token': 'test_access_token',
        'refresh_token': 'test_refresh_token',
        'token_type': 'Bearer',
        'expires_in': '-1',
    }
    token = get_current_token()
    assert token['access_token'] == 'test_access_token'
    assert token['refresh_token'] == 'test_refresh_token'
    assert token['expires_in'] == '-1'
    client.refresh_token.assert_called_once()

    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT access_token, refresh_token, token_expires_on
                FROM oauth WHERE app_name = 'patreon'
            """)

            access_token, refresh_token, token_expires_on = cur.fetchone()

    assert decrypt(access_token) == 'test_access_token'
    assert decrypt(refresh_token) == 'test_refresh_token'
    assert token_expires_on is None

    client.reset_mock()
    client.refresh_token.return_value = {
        'access_token': 'new_access_token',
        'refresh_token': 'new_refresh_token',
        'token_type': 'Bearer',
        'expires_in': '3600'
    }

    token = get_current_token()
    assert token['access_token'] == 'new_access_token'
    assert token['refresh_token'] == 'new_refresh_token'
    assert token['expires_in'] == '3600'
    client.refresh_token.assert_called_once()

    with db.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT access_token, refresh_token, token_expires_on
                FROM oauth WHERE app_name = 'patreon'
            """)

            access_token, refresh_token, token_expires_on = cur.fetchone()

    assert decrypt(access_token) == 'new_access_token'
    assert decrypt(refresh_token) == 'new_refresh_token'
    assert token_expires_on == 3600

    time_machine.move_to(1800.0, tick=False)
    client.reset_mock()
    token = get_current_token()
    assert token['access_token'] == 'new_access_token'
    assert token['refresh_token'] == 'new_refresh_token'
    assert token['expires_in'] == '1800'
    client.refresh_token.assert_not_called()


def test_get_campaigns(json_fixture, monkeypatch):
    response = Mock()
    response.json.return_value = json_fixture('patreon_campaigns.json')
    session = Mock()
    session.return_value = session
    session.get.return_value = response
    monkeypatch.setattr('turbo_sticks.patreon.OAuth2Session', session)
    monkeypatch.setattr('turbo_sticks.patreon.get_current_token', lambda: {})

    assert get_campaigns() == [
        {
            'id': '1',
            'type': 'campaign',
            'creation_name': 'TURBO Sticks',
            'tiers': [
                {
                    'id': '10',
                    'type': 'tier',
                    'title': 'Tip Jar',
                    'amount_cents': 100,
                },
                {
                    'id': '11',
                    'type': 'tier',
                    'title': 'Large Tip Jar',
                    'amount_cents': 500,
                },
            ]
        },
        {
            'id': '2',
            'type': 'campaign',
            'creation_name': 'VGA',
            'tiers': [
                {
                    'id': '20',
                    'type': 'tier',
                    'title': 'AWESOME Piece Theatre',
                    'amount_cents': 500,
                },
            ]
        },
    ]
    session.get.assert_called_once_with(
        'https://patreon.com/test/campaigns'
        '?include=tiers&'
        'fields%5Bcampaign%5D=creation_name&'
        'fields%5Btier%5D=title%2Camount_cents'
    )
    response.json.assert_called_once()


def test_get_members(json_fixture, monkeypatch):
    response = Mock()
    response.json.return_value = json_fixture('patreon_members.json')
    session = Mock()
    session.return_value = session
    session.get.return_value = response
    monkeypatch.setattr('turbo_sticks.patreon.OAuth2Session', session)
    monkeypatch.setattr('turbo_sticks.patreon.get_current_token', lambda: {})

    assert get_members() == [
        {
            'id': '10',
            'type': 'member',
            'last_charge_date': '2020-10-10 10:00:00',
            'last_charge_status': 'Paid',
            'lifetime_support_cents': 1000,
            'currently_entitled_amount_cents': 500,
            'patron_status': 'active_patron',
            'user': {
                'id': '1',
                'type': 'user',
                'full_name': 'John Doe',
                'vanity': 'johndoe',
                'email': 'john.doe@example.com',
                'is_email_verified': True,
                'image_url': 'https://patreon.com/avatars/johndoe.png'
            }
        },
        {
            'id': '20',
            'type': 'member',
            'last_charge_date': None,
            'last_charge_status': None,
            'lifetime_support_cents': 0,
            'currently_entitled_amount_cents': 0,
            'patron_status': None,
            'user': {
                'id': '2',
                'type': 'user',
                'full_name': 'Jane Doe',
                'vanity': None,
                'email': 'jane.doe@example.com',
                'is_email_verified': True,
                'image_url': 'https://patreon.com/avatars/janedoe.png'
            }
        },
    ]
    session.get.assert_called_once_with(
        'https://patreon.com/test/campaigns/test_campaign/members'
        '?include=user&'
        'fields%5Buser%5D=full_name%2C'
        'vanity%2C'
        'email%2C'
        'is_email_verified%2C'
        'image_url&'
        'fields%5Bmember%5D=last_charge_date%2C'
        'last_charge_status%2C'
        'lifetime_support_cents%2C'
        'currently_entitled_amount_cents%2C'
        'patron_status'
    )
    response.json.assert_called_once()


def test_get_current_user(json_fixture):
    response = Mock()
    response.json.return_value = json_fixture('patreon_identity.json')
    session = Mock()
    session.get.return_value = response

    assert get_current_user(session) == {
        'id': '1',
        'type': 'user',
        'full_name': 'John Doe',
        'vanity': 'johndoe',
        'email': 'john.doe@example.com',
        'is_email_verified': True,
        'image_url': 'https://patreon.com/avatars/johndoe.png',
        'memberships': [
            {
                'id': '10',
                'type': 'member',
                'last_charge_date': '2020-10-10 10:00:00',
                'last_charge_status': 'Paid',
                'lifetime_support_cents': 1000,
                'currently_entitled_amount_cents': 500,
                'patron_status': 'active_patron',
                'campaign': {
                    'id': '100',
                    'type': 'campaign'
                }
            },
            {
                'id': '11',
                'type': 'member',
                'last_charge_date': None,
                'last_charge_status': None,
                'lifetime_support_cents': 0,
                'currently_entitled_amount_cents': 0,
                'patron_status': None,
                'campaign': {
                    'id': '110',
                    'type': 'campaign'
                }
            },
        ]
    }
    session.get.assert_called_once_with(
        'https://patreon.com/test/identity'
        '?include=memberships%2Cmemberships.campaign&'
        'fields%5Buser%5D=full_name%2C'
        'vanity%2C'
        'email%2C'
        'is_email_verified%2C'
        'image_url&'
        'fields%5Bmember%5D=last_charge_date%2C'
        'last_charge_status%2C'
        'lifetime_support_cents%2C'
        'currently_entitled_amount_cents%2C'
        'patron_status'
    )
    response.json.assert_called_once()


def test_build_query():
    assert build_query(
        includes=['rel_1', 'rel_2'],
        fields={
            'obj_1': [
                'field_1',
                'field_2',
                'field_3'
            ],
            'obj_2': [
                'field_5',
                'field_7'
            ]
        }
    ) == (
        '?include=rel_1%2Crel_2&'
        'fields%5Bobj_1%5D=field_1%2Cfield_2%2Cfield_3&'
        'fields%5Bobj_2%5D=field_5%2Cfield_7'
    )


def test_sanitize_json():
    assert sanitize_json({
        'data': {'id': '1', 'type': 'obj_1'},
        'links': 'ignored',
        'meta': 'ignored',
    }) == {'id': '1', 'type': 'obj_1'}

    assert sanitize_json({
        'data': [
            {'id': '1', 'type': 'obj_1'},
            {'id': '2', 'type': 'obj_1'},
        ],
        'links': 'ignored',
        'meta': 'ignored',
    }) == [
        {'id': '1', 'type': 'obj_1'},
        {'id': '2', 'type': 'obj_1'},
    ]


def test_sanitize_json_attributes():
    assert sanitize_json({
        'data': {
            'id': '1',
            'type': 'obj_1',
            'attributes': {
                'attr_1': 'val_1',
                'attr_2': 'val_2'
            },
            'links': 'ignored',
        },
        'links': 'ignored',
        'meta': 'ignored',
    }) == {'id': '1', 'type': 'obj_1', 'attr_1': 'val_1', 'attr_2': 'val_2'}

    assert sanitize_json({
        'data': [
            {
                'id': '1',
                'type': 'obj_1',
                'attributes': {
                    'attr_1': 'val_1',
                    'attr_2': 'val_2'
                },
                'links': 'ignored',
            },
            {
                'id': '2',
                'type': 'obj_1',
                'attributes': {
                    'attr_1': 'val_3',
                    'attr_2': 'val_4'
                },
                'links': 'ignored',
            },
        ],
        'links': 'ignored',
        'meta': 'ignored',
    }) == [
        {'id': '1', 'type': 'obj_1', 'attr_1': 'val_1', 'attr_2': 'val_2'},
        {'id': '2', 'type': 'obj_1', 'attr_1': 'val_3', 'attr_2': 'val_4'},
    ]


def test_sanitize_json_relationships():
    assert sanitize_json({
        'data': {
            'id': '1',
            'type': 'obj_1',
            'relationships': {
                'parent': {
                    'data': {'id': '0', 'type': 'obj_1'}
                },
                'children': {
                    'data': [
                        {'id': '10', 'type': 'obj_1'},
                        {'id': '11', 'type': 'obj_1'},
                    ]
                },
            }
        }
    }) == {
        'id': '1',
        'type': 'obj_1',
        'parent': {'id': '0', 'type': 'obj_1'},
        'children': [
            {'id': '10', 'type': 'obj_1'},
            {'id': '11', 'type': 'obj_1'},
        ]
    }


def test_sanitize_json_relationships_included():
    assert sanitize_json({
        'data': {
            'id': '1',
            'type': 'obj_1',
            'relationships': {
                'parent': {
                    'data': {'id': '0', 'type': 'obj_1'}
                },
                'children': {
                    'data': [
                        {'id': '10', 'type': 'obj_1'},
                        {'id': '11', 'type': 'obj_1'},
                    ]
                },
            }
        },
        'included': [
            {
                'id': '0',
                'type': 'obj_1',
                'attributes': {
                    'attr_1': 'val_1'
                },
                'links': 'ignored',
            },
            {
                'id': '10',
                'type': 'obj_1',
                'attributes': {
                    'attr_1': 'val_2'
                },
                'links': 'ignored',
            },
            {
                'id': '11',
                'type': 'obj_2',  # wrong type
                'attributes': {
                    'attr_1': 'val_3'
                },
                'links': 'ignored',
            },
        ]
    }) == {
        'id': '1',
        'type': 'obj_1',
        'parent': {'id': '0', 'type': 'obj_1', 'attr_1': 'val_1'},
        'children': [
            {'id': '10', 'type': 'obj_1', 'attr_1': 'val_2'},
            {'id': '11', 'type': 'obj_1'},
        ]
    }


def test_sanitize_json_with_errors():
    payload = {'errors': ['Error']}
    assert sanitize_json(payload) == payload


def test_sanitize_json_malformed():
    with pytest.raises(ValueError, match=r'Malformed JSON:API content\.'):
        sanitize_json([])

    with pytest.raises(ValueError, match=r'Malformed JSON:API content\.'):
        sanitize_json({})

    with pytest.raises(ValueError, match=r'Malformed JSON:API content\.'):
        sanitize_json('')

    with pytest.raises(ValueError, match=r'Malformed JSON:API content\.'):
        sanitize_json(0.0)

    with pytest.raises(ValueError, match=r'Malformed JSON:API content\.'):
        sanitize_json(False)

    with pytest.raises(ValueError, match=r'Malformed JSON:API content\.'):
        sanitize_json(None)
