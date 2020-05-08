import json
from time import time
from requests_oauthlib import OAuth2Session

from turbo_config import session_max_age, mastodon
from turbo_util import generate_random_token, retrieve_cookies
from turbo_util import retrieve_get_vars, encrypt, decrypt


# Session Store
def create_session(oauth_token, db):
    if(db is not None):
        with db:
            with db.cursor() as cur:
                session_token = generate_random_token(128)
                sql = """
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
                            (now() + interval '%s seconds')
                        )"""

                expires_in = oauth_token.get('expires_in', session_max_age)
                cur.execute(sql, (
                    session_token,
                    oauth_token['access_token'],
                    oauth_token.get('refresh_token', ''),
                    oauth_token['token_type'],
                    int(expires_in) + int(time()),
                    session_max_age
                ))
                return session_token
    return None


def delete_session(session_token, db):
    if(db is not None and session_token is not None):
        with db:
            with db.cursor() as cur:
                sql = """
                        DELETE
                          FROM sessions
                         WHERE session_token = %s"""
                return cur.execute(sql, (session_token,))
    return False


def retrieve_token_from_session(session_token, db):
    if(db is not None):
        with db:
            with db.cursor() as cur:
                sql = """
                        SELECT access_token,
                               refresh_token,
                               token_type,
                               token_expires_on
                          FROM sessions
                         WHERE session_token = %s
                           AND session_expires_on > current_timestamp"""

                cur.execute(sql, (session_token,))
                row = cur.fetchone()
                if(row is None):
                    return None

                result = {
                    'access_token': row[0],
                    'refresh_token': row[1],
                    'token_type': row[2],
                    'expires_in': str(row[3] - int(time()))
                }

                return result
    return None


# OAuth 2.0 Token Management
def refresh_token_if_necessary(token):
    if(token and int(token.get('expires_in', 0)) < 0):
        # Token needs to refreshed
        client = OAuth2Session(mastodon.client_id, token=token)
        extra = {
            'client_id': mastodon.client_id,
            'client_secret': mastodon.client_secret
        }
        client.refresh_token(mastodon.token_url, **extra)


def get_session(env):
    cookies = retrieve_cookies(env)
    session_cookie = cookies.get('TB_SESSION')
    if(session_cookie):
        return session_cookie.value
    return None


def retrieve_oauth_account(session, db):
    if(session is not None and db is not None):
        token = retrieve_token_from_session(session, db)
        if(token is not None):
            refresh_token_if_necessary(token)
            oauth = OAuth2Session(mastodon.client_id, token=token)
            account = json.loads(oauth.get(mastodon.get_account_url).text)
            # Don't authenticate moved accounts, federated accounts or bots
            if(int(account.get('id', '0')) > 0 and
               account.get('moved') is None and
               account.get('username', '') == account.get('acct', '@')):
                return account
    return None


# generates OAuth state, remembering current location
def generate_state(env, csrf_clerk):
    # if redirect_to is set, remember that instead of the current location
    get_vars = retrieve_get_vars(env)
    location = get_vars.get('redirect_to', [env['PATH_INFO']])[0]

    csrf_token = csrf_clerk.register('oauth-authorization')

    # oauth state is a list of a csrf token and the location
    oauth_state = [csrf_token, location]

    # return oauth_state jsonified and encrypted
    return encrypt(json.dumps(oauth_state))


def retrieve_oauth_state(encrypted_state):
    try:
        return json.loads(decrypt(encrypted_state))
    except ValueError:
        return None
