import sys
from oauthlib.oauth2 import OAuth2Error


import turbo_session
import turbo_util as util
from turbo_db import DBError
from turbo_user import ACL, User

this = sys.modules[__name__]

# API calls
api_calls = {}


# API calls
# func is a function of the form func(env, csrf_clerk, db) -> dict, status
def create_api_call(func):
    def api_call(env, csrf_clerk, db):
        try:
            response, status = func(env, csrf_clerk, db)
            return util.generate_json_response(response, status)
        except DBError as error:
            # Database Error
            util.print_exception('Database Error occured: ', error)
            return util.generate_json_response(
                {'error': 'A database error has occured.'},
                '500 Internal Server Error'
            )
        except OAuth2Error as error:
            # OAuth 2.0 Error
            util.print_exception('OAuth 2.0 Error occured: ', error)
            return util.generate_json_response(
                {'error': 'Failed to complete OAuth 2.0 handshake.'}
            )
        except Exception as error:
            # Unknown Exception
            util.print_exception('Unexpected Error occured: ', error, False)
            return util.generate_json_response(
                {'error': 'An unexpected error has occured.'},
                '500 Internal Server Error'
            )
    return api_call


# Basic API calls with builtin authentication and CSRF check
# func is a function of the form func(post_vars, db, user) -> dict
def create_basic_api_call(func, csrf_check=True, min_access_level=ACL.turbo):
    def basic_api_call(env, csrf_clerk, db):
        post_vars = util.retrieve_post_vars(env)
        session = turbo_session.get_session(env)
        account = turbo_session.retrieve_oauth_account(session, db)
        status = '200 OK'
        if account is None:
            return {'error': 'Couldn\'t authenticate user.'}, status
        csrf_token = post_vars.get('csrf_token', [''])[0]
        if csrf_check and not csrf_clerk.validate(session, csrf_token):
            return {'error': 'CSRF token verification failed.'}, status
        user = User.create(account, db)
        access_level = User.get_access_level(user)
        if access_level < min_access_level:
            return {'error': 'You do not have the required permissions.'}
        return func(post_vars, db, user), status
    return create_api_call(basic_api_call)


def reset_app_password(post_vars, db, user):
    user.reset_app_password()
    return {'app_password': user.app_password_plain}
api_calls['reset_app_password'] = create_basic_api_call(reset_app_password)

this.api_calls = api_calls
