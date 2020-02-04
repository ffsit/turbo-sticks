import sys
import json
from time import time
from requests_oauthlib import OAuth2Session
from collections import OrderedDict

#Local Imports
from turbo_config import patreon, expiration_interval, session_max_age
from turbo_util import encrypt, decrypt, quote_plus, generate_random_token, retrieve_cookies

this = sys.modules[__name__]

# Temp session store (uses expiration_interval instead of session_max_age)
this.sessions = {}

# Create session, store session token and return it
def create_session():
	session_token = generate_random_token(128)
	this.sessions[session_token] = time()
	return session_token

# Check session stored in cookie, returns True if session exists and is active
def validate_session(env):
	cookies = retrieve_cookies(env)
	session_cookie = cookies.get('TB_PATREON_SESSION')
	if(session_cookie is None):
		# No Session Cookie set
		return False
	session_token = session_cookie.value
	creation_time = this.sessions.get(session_token)
	if(creation_time is None):
		# Session doesn't exist
		return False
	if(creation_time + expiration_interval > time()):
		# Session does exist and is still valid
		return True
	# Session expired, so delete it
	del sessions[session_token]
	return False

# Store initial oauth parameters, if not already stored
def init_oauth(db): 
	if(db is not None):
		with db:
			with db.cursor() as cur:
				access_token = encrypt(patreon.access_token)
				refresh_token = encrypt(patreon.refresh_token)
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

				cur.execute(sql,
					(
						access_token,
						refresh_token
					))

def __refresh_access_token(db, token):
	if(db is not None):
		extra = {
			'client_id': patreon.client_id,
			'client_secret': patreon.client_secret
		}

		client = OAuth2Session(patreon.client_id, token=token)
		new_token = client.refresh_token(patreon.token_url, **extra)

		if not(new_token == token):
			token = new_token
			with db:
				with db.cursor() as cur:
					sql = """
							UPDATE oauth
							   SET access_token = %s,
							       refresh_token = %s,
							       token_expires_on = %s
							 WHERE app_name = 'patreon'"""

					cur.execute(sql,
						(
							encrypt(token['access_token']),
							encrypt(token['refresh_token']),
							int(token.get('token_expires_in', session_max_age)) + int(time())
						))
		return token

def __get_current_token(db):
	if(db is not None):
		with db:
			with db.cursor() as cur:
				sql = """
						SELECT access_token,
						       refresh_token,
						       token_expires_on
						  FROM oauth
						 WHERE app_name = 'patreon'"""

				cur.execute(sql)
				row = cur.fetchone()
				token = {
					'access_token': patreon.access_token,
					'refresh_token': patreon.refresh_token,
					'token_type': 'Bearer',
					'token_expires_in': '3000'
				}
				if(row is None):
					init_oauth(db)
				else:
					token['access_token'] = decrypt(row[0])
					token['refresh_token'] = decrypt(row[1])
					if(row[2] is not None):
						token['token_expires_in'] = str(row[2] - int(time()))
					else:
						token['token_expires_in'] = -1

				if(int(token['token_expires_in']) < 0):
					token = __refresh_access_token(db, token)
				return token
	return None

# Application wide API calls (require application access token)
def get_campaigns(db):
	token = __get_current_token(db)
	client = OAuth2Session(patreon.client_id, token=token)
	campaigns_url = patreon.api_endpoint + '/campaigns'
	includes = ['tiers']
	fields = {
		'campaign': ['creation_name'],
		'tier'    : ['title', 'amount_cents']
	}
	query = build_query(includes, fields)
	return sanitize_json(json.loads(client.get(campaigns_url + query).text, object_pairs_hook=OrderedDict))


def get_members(db):
	token = __get_current_token(db)
	client = OAuth2Session(patreon.client_id, token=token)
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
			'patron_status',
			'last_charge_date',
			'last_charge_status',
			'lifetime_support_cents',
			'currently_entitled_amount_cents',
			'patron_status'
		]
	}
	query = build_query(includes, fields)
	members_url = patreon.api_endpoint + '/campaigns/' + patreon.campaign_id + '/members'
	return sanitize_json(json.loads(client.get(members_url + query).text, object_pairs_hook=OrderedDict))

# User specific API calls (require user access token)
def get_current_user(db, oauth_session):
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
			'patron_status',
			'last_charge_date',
			'last_charge_status',
			'lifetime_support_cents',
			'currently_entitled_amount_cents',
			'patron_status'
		]
	}
	query = build_query(includes, fields)
	identity_url = patreon.api_endpoint + '/identity'
	return sanitize_json(json.loads(oauth_session.get(identity_url + query).text, object_pairs_hook=OrderedDict))


# Simplified JSON:API helpers for what we need
# Builds a query string for JSON:API includes=list(), fields=dict(key,list())
def build_query(includes, fields):
	query = '?'
	if(isinstance(includes, list) and len(includes) > 0):
		query += 'include=' + ','.join(includes) + '&'

	if(isinstance(fields, dict)):
		field_queries = []
		for key, item in fields.items():
			if(isinstance(item, list) and len(item) > 0):
				field_queries.append('fields[' + key + ']=' + ','.join(item))
		query += '&'.join(field_queries)
	return quote_plus(query, '?=&')

# Disregards and strips pagination/links
def sanitize_json(json):
	if('errors' in json):
		return json

	if('data' not in json):
		raise AttributeError('Malformed JSON:API content.')

	result = [];
	data = json['data']
	included = json.get('included')
	if(not isinstance(data, list)):
		data = [data]
	for entry in data:
		result.append(__flatten_json_entry(entry, included))

	return result

def __flatten_json_entry(entry, included):
	if(not isinstance(entry, dict)):
		return entry

	result = OrderedDict()
	result['type'] = entry['type']
	result['id'] = entry['id']
	if('attributes' in entry):
		result.update(entry['attributes'])
	if('relationships' in entry):
		for key, item in entry['relationships'].items():
			entries = item['data']
			if(not isinstance(entries, list)):
				entries = [entries]
			result[key] = []
			for item in entries:
				result[key].append(__fetch_relationship(item, included))
	return result


def __fetch_relationship(relationship, included):
	for item in included:
		if(item['type'] == relationship['type'] and item['id'] == relationship['id']):
			return __flatten_json_entry(item, included)
