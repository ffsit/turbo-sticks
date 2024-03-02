from __future__ import annotations

import json
from psycopg.sql import SQL, Literal
from requests_oauthlib import OAuth2Session
from time import time
from typing import Any, TYPE_CHECKING

import turbo_sticks.config as config
from turbo_sticks.db import DBSession
from turbo_sticks.util import (
    generate_random_token, retrieve_cookies,
    retrieve_get_vars, encrypt, decrypt
)


if TYPE_CHECKING:
    from .csrf import TokenClerk
    from .types import MastodonAccount
    from .types import OAuth2Token


def create_session(oauth_token: OAuth2Token) -> str:
    db = DBSession()
    with db.connection() as conn, conn.cursor() as cur:
        session_token = generate_random_token(128)
        sql = SQL("""
                INSERT INTO sessions
                (
                    session_token,
                    access_token,
                    refresh_token,
                    token_type,
                    token_expires_on,
                    session_expires_on
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    now() + interval '{} seconds'
                )""").format(Literal(config.session.max_age))

        expires_in = oauth_token.get('expires_in', config.session.max_age)
        cur.execute(sql, (
            session_token,
            oauth_token['access_token'],
            oauth_token.get('refresh_token', ''),
            oauth_token['token_type'],
            int(expires_in) + int(time())
        ))
        return session_token


def delete_session(session_token: str | None) -> None:
    if session_token is None:
        return

    db = DBSession()
    with db.connection() as conn, conn.cursor() as cur:
        sql = """
                DELETE
                  FROM sessions
                 WHERE session_token = %s"""
        cur.execute(sql, (session_token,))


def get_session(env: dict[str, Any]) -> str | None:
    cookies = retrieve_cookies(env)
    session_cookie = cookies.get('TB_SESSION')
    if session_cookie:
        return session_cookie.value
    return None


def retrieve_token_from_session(
    session_token: str | None
) -> OAuth2Token | None:

    if session_token is None:
        return None

    db = DBSession()
    with db.connection() as conn, conn.cursor() as cur:
        sql = """
                SELECT access_token,
                       refresh_token,
                       token_type,
                       token_expires_on
                  FROM sessions
                 WHERE session_token = %s
                   AND session_expires_on > now()"""

        cur.execute(sql, (session_token,))
        row = cur.fetchone()
        if row is None:
            return None

        return {
            'access_token': row[0],
            'refresh_token': row[1],
            'token_type': row[2],
            'expires_in': str(row[3] - int(time()))
        }


def retrieve_oauth_account(
    session_token: str | None
) -> MastodonAccount | None:

    if session_token is None:
        return None

    token = retrieve_token_from_session(session_token)
    if token is None:
        return None

    oauth = OAuth2Session(config.mastodon.client_id, token=token)
    if int(token.get('expires_in', 0)) < 0:
        oauth.refresh_token(
            config.mastodon.token_url,
            client_id=config.mastodon.client_id,
            client_secret=config.mastodon.client_secret
        )
    account = oauth.get(config.mastodon.get_account_url).json()

    if int(account.get('id', '0')) <= 0:
        return None

    if account.get('bot', False) is True:
        return None

    if account.get('suspended', False) is True:
        return None

    if account.get('moved') is not None:
        return None

    if account.get('username', '') != account.get('acct', '@'):
        return None

    return account  # type:ignore[no-any-return]


# generates OAuth state, remembering current location
def generate_oauth_state(env: dict[str, Any], csrf_clerk: TokenClerk) -> str:
    # if redirect_to is set, remember that instead of the current location
    get_vars = retrieve_get_vars(env)
    location = get_vars.get('redirect_to', [env['PATH_INFO']])[0]

    csrf_token = csrf_clerk.register('oauth-authorization')

    # oauth state is a list of a csrf token and the location
    oauth_state = [csrf_token, location]

    # return oauth_state jsonified and encrypted
    return encrypt(json.dumps(oauth_state))


def retrieve_oauth_state(encrypted_state: str) -> tuple[
    str | None,  # csrf_token
    str | None   # location
]:
    csrf_token = location = None
    try:
        state = json.loads(decrypt(encrypted_state))
        if isinstance(state, list) and len(state) == 2:
            csrf_token, location = map(str, state)
    except (ValueError, json.JSONDecodeError):
        pass
    return csrf_token, location
