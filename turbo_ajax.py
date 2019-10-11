import sys
from oauthlib.oauth2 import OAuth2Error

import turbo_user
import turbo_session
from turbo_db import DBWarning, DBError
from turbo_config import *
from turbo_util import *

this = sys.modules[__name__]

# API calls
this.api_calls = {};

# API calls
# func is a function of the form func(post_vars, db, user) -> dict
def create_api_call(func, needs_auth=True):
	def api_call(env, csrf_clerk, db):
		post_vars = retrieve_post_vars(env)
		if(needs_auth):
			try:
				session = turbo_session.get_session(env)
				account = turbo_session.retrieve_oauth_account(session, db)
				if(account is None):
					return generate_json_response({'error': 'Couldn\'t authenticate user.'})
				csrf_token = post_vars.get('csrf_token', [''])[0]
				if(not csrf_clerk.validate(session, csrf_token)):
					return generate_json_response({'error': 'CSRF token verification failed.'})
				user = turbo_user.User.create(account, db)
				return generate_json_response(func(post_vars, db, user))

			except turbo_db.DBWarning as warning:
				# Database Warning, can continue normally
				print_exception('Database Warning occured:', warning)
				pass
			except turbo_db.DBError as error:
				# Database Error
				print_exception('Database Error occured: ', error)
				return generate_json_response({'error': 'A database error has occured.'})
			except OAuth2Error as error:
				# OAuth 2.0 Error
				print_exception('OAuth 2.0 Error occured: ', error)
				return generate_json_response({'error': 'Failed to complete OAuth 2.0 handshake.'})
			except Exception as error:
				# Unknown Exception
				print_exception('Unexpected Error occured: ', error)
				return generate_json_response({'error': 'An unexpected error has occured.'})

		return generate_json_response(func(post_vars, db))

	return api_call;

def reset_app_password(post_vars, db, user):
	user.reset_app_password()
	return {'app_password': user.app_password_plain}

this.api_calls['reset_app_password'] = create_api_call(reset_app_password)
