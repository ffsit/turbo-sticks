import os
import binascii
import json
from time import time
from requests_oauthlib import OAuth2Session

from turbo_config import session_max_age, client_id, client_secret, account_url, token_url
from turbo_util import retrieve_cookies

# Session Store
def create_session(oauth_token, db):
	if(db is not None):
		with db:
			with db.cursor() as cur:
				session_token = binascii.hexlify(os.urandom(128/2))
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

				cur.execute(sql,
					(
						session_token,
						oauth_token['access_token'],
						oauth_token.get('refresh_token',''),
						oauth_token['token_type'],
						int(oauth_token.get('expires_in', session_max_age)) + int(time()),
						session_max_age
					))
				return session_token
	return None

def delete_session(session_token, db):
	if(db is not None and session_token is not None):
		with db:
			with db.cursor() as cur:
				session_token = binascii.hexlify(os.urandom(128/2))
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
		client = OAuth2Session(client_id, token=token)
		extra = {
			'client_id': client_id,
			'client_secret': client_secret
		}
		client.refresh_token(token_url, **extra)

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
			oauth = OAuth2Session(client_id, token=token)
			account = json.loads(oauth.get(account_url).content)
			# Don't authenticate moved accounts, federated accounts or bots
			if(account.get('id', 0) > 0 and
			   account.get('moved', None) is None and
			   account.get('username','') == account.get('acct','@')):
				return account
	return None
