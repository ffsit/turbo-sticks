from __future__ import annotations

import json
from requests_oauthlib import OAuth2Session
from time import time
from typing import overload, Any, Literal, TYPE_CHECKING

import turbo_sticks.config as config
import turbo_sticks.util as util
from turbo_sticks.db import DBSession

if TYPE_CHECKING:
    import psycopg

    from .types import JSON
    from .types import JSONArray
    from .types import JSONObject
    from .types import OAuth2Token


sessions: dict[str, float] = {}


# Create session, store session token and return it
def create_session() -> str:
    session_token = util.generate_random_token(128)
    sessions[session_token] = time()
    return session_token


# Check session stored in cookie, returns True if session exists and is active
def validate_session(env: dict[str, Any]) -> bool:
    cookies = util.retrieve_cookies(env)
    session_cookie = cookies.get('TB_PATREON_SESSION')
    if session_cookie is None:
        # No Session Cookie set
        return False
    session_token = session_cookie.value
    creation_time = sessions.get(session_token)
    if creation_time is None:
        # Session doesn't exist
        return False
    if creation_time + config.patreon.session_max_age > time():
        # Session does exist and is still valid
        return True
    # Session expired, so delete it
    del sessions[session_token]
    return False


# Store initial oauth parameters, if not already stored
# this helper accepting a cursor exists so we can call it
# inside get_current_token without a second connection
def _init_oauth(cursor: psycopg.Cursor[Any]) -> None:
    access_token = util.encrypt(
        config.patreon.access_token.get_secret_value()
    )
    refresh_token = util.encrypt(
        config.patreon.refresh_token.get_secret_value()
    )
    sql = """
            INSERT INTO oauth
            (
                app_name,
                access_token,
                refresh_token
            )
            SELECT
                'patreon',
                %s,
                %s
            WHERE NOT EXISTS
            (
                SELECT 1 FROM oauth WHERE app_name = 'patreon'
            )"""

    cursor.execute(sql, (access_token, refresh_token))


def init_oauth() -> None:
    db = DBSession()
    with db.connection() as conn:
        with conn.cursor() as cur:
            _init_oauth(cur)


def get_current_token() -> OAuth2Token:
    db = DBSession()
    with db.connection() as conn:
        with conn.cursor() as cur:
            sql = """
                    SELECT access_token,
                           refresh_token,
                           token_expires_on
                      FROM oauth
                     WHERE app_name = 'patreon'"""

            cur.execute(sql)
            row = cur.fetchone()
            access_token = config.patreon.access_token
            refresh_token = config.patreon.refresh_token
            token: OAuth2Token = {
                'access_token': access_token.get_secret_value(),
                'refresh_token': refresh_token.get_secret_value(),
                'token_type': 'Bearer',
                'expires_in': '-1'
            }
            if row is None:
                _init_oauth(cur)
            else:
                token['access_token'] = util.decrypt(row[0])
                token['refresh_token'] = util.decrypt(row[1])
                if row[2] is not None:
                    token['expires_in'] = str(row[2] - int(time()))
                else:
                    token['expires_in'] = '-1'

            if int(token['expires_in']) < 0:
                client = OAuth2Session(config.patreon.client_id, token=token)
                client_secret = config.patreon.client_secret
                new_token: OAuth2Token = client.refresh_token(  # type:ignore
                    config.patreon.token_url,
                    client_id=config.patreon.client_id,
                    client_secret=client_secret.get_secret_value()
                )

                if new_token != token:
                    token = new_token
                    expires_in = token.get('expires_in',
                                           config.session.max_age)
                    sql = """
                            UPDATE oauth
                               SET access_token = %s,
                                   refresh_token = %s,
                                   token_expires_on = %s
                             WHERE app_name = 'patreon'"""

                    cur.execute(sql, (
                        util.encrypt(token['access_token']),
                        util.encrypt(token['refresh_token']),
                        int(expires_in) + int(time())
                    ))
            return token


# Application wide API calls (require application access token)
def get_campaigns() -> list[JSONObject]:
    token = get_current_token()
    client = OAuth2Session(config.patreon.client_id, token=token)
    campaigns_url = config.patreon.api_endpoint + '/campaigns'
    includes = ['tiers']
    fields = {
        'campaign': ['creation_name'],
        'tier': ['title', 'amount_cents']
    }
    query = build_query(includes, fields)
    campaigns = sanitize_json(client.get(campaigns_url + query).json(), True)
    return campaigns


def get_members() -> list[JSONObject]:
    token = get_current_token()
    client = OAuth2Session(config.patreon.client_id, token=token)
    includes = ['user']
    fields = {
        'user': [
            'full_name',
            'vanity',
            'email',
            'is_email_verified',
            'image_url'
        ],
        'member': [
            'last_charge_date',
            'last_charge_status',
            'lifetime_support_cents',
            'currently_entitled_amount_cents',
            'patron_status'
        ]
    }
    query = build_query(includes, fields)
    api_endpoint = config.patreon.api_endpoint
    campaign_id = config.patreon.campaign_id
    members_url = f'{api_endpoint}/campaigns/{campaign_id}/members'
    members = sanitize_json(client.get(members_url + query).json(), True)
    return members


# User specific API calls (require user access token)
def get_current_user(oauth_session: OAuth2Session) -> JSONObject:
    includes = ['memberships', 'memberships.campaign']
    fields = {
        'user': [
            'full_name',
            'vanity',
            'email',
            'is_email_verified',
            'image_url'
        ],
        'member': [
            'last_charge_date',
            'last_charge_status',
            'lifetime_support_cents',
            'currently_entitled_amount_cents',
            'patron_status'
        ]
    }
    query = build_query(includes, fields)
    identity_url = config.patreon.api_endpoint + '/identity'
    user = sanitize_json(oauth_session.get(identity_url + query).json(), False)
    return user


# Simplified JSON:API helpers for what we need
# Builds a query string for JSON:API
def build_query(includes: list[str], fields: dict[str, list[str]]) -> str:
    query: dict[str, str] = {'include': ','.join(includes)}
    query.update({f'fields[{k}]': ','.join(v) for k, v in fields.items()})
    return '?' + util.urlencode(query)


class JSONAPIError(ValueError):
    def __init__(self, errors: JSON):
        self.errors_json = errors
        super().__init__('JSON:API error:\n' + json.dumps(errors, indent=4))


# Makes JSON:API responses look more sane
# Disregards and strips pagination / links
# Resolves and flattens attributes and relationships
@overload
def sanitize_json(json: JSON, listing: Literal[False] = ...) -> JSONObject: ...
@overload
def sanitize_json(json: JSON, listing: Literal[True]) -> list[JSONObject]: ...


def sanitize_json(
    json: JSON,
    listing: bool = False
) -> JSONObject | list[JSONObject]:
    try:
        assert isinstance(json, dict)

        if 'errors' in json:
            raise JSONAPIError(json['errors'])

        data = json['data']
        included = json.get('included', [])
        assert isinstance(included, list)

        if not isinstance(data, list):
            assert listing is False
            return _flatten_json_entry(data, included)

        assert listing is True
        return [_flatten_json_entry(entry, included) for entry in data]

    except (KeyError, TypeError, AssertionError):
        raise ValueError('Malformed JSON:API content.') from None


def _flatten_json_entry(entry: JSON, included: JSONArray) -> JSONObject:
    assert isinstance(entry, dict)
    result: dict[str, JSON] = {
        'id': entry['id'],
        'type': entry['type'],
    }
    if isinstance((attrs := entry.get('attributes')), dict):
        result.update(attrs)

    if isinstance((rels := entry.get('relationships')), dict):
        for key, item in rels.items():
            assert isinstance(item, dict)
            relationship = item['data']
            if not isinstance(relationship, list):
                result[key] = _fetch_relationship(relationship, included)
                continue

            result[key] = [
                _fetch_relationship(rel, included) for rel in relationship
            ]
    return result


def _fetch_relationship(relationship: JSON, included: JSONArray) -> JSONObject:
    assert isinstance(relationship, dict)
    for item in included:
        assert isinstance(item, dict)
        if item['type'] != relationship['type']:
            continue

        if item['id'] == relationship['id']:
            return _flatten_json_entry(item, included)

    # if it's not included we still want to flatten to the type/id pair
    return {
        'id': relationship['id'],
        'type': relationship['type'],
    }
