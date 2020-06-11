import sys
import logging
from oauthlib.oauth2 import OAuth2Error

import turbo_session
import turbo_config as config
import turbo_util as util
from turbo_db import DBError, DBSession
from turbo_user import ACL, User

this = sys.modules[__name__]

# Logger
logger = logging.getLogger('sticks.api')

# API calls
this.api_calls = {}


# API call decorator
# func is a function of the form func(env, csrf_clerk, db) -> dict, status
def api_call(path):
    def decorator(func):
        def decorated_function(env, csrf_clerk):
            try:
                response, status = func(env, csrf_clerk)
                return util.generate_json_response(response, status)
            except DBError:
                # Database Error
                logger.exception('Database Error occured.')
                return util.generate_json_response(
                    {'error': 'A database error has occured.'},
                    '500 Internal Server Error'
                )
            except OAuth2Error as error:
                # OAuth 2.0 Error
                logger.info(f'OAuth 2.0 Error occured: {error}',
                            exc_info=config.debug_mode)
                return util.generate_json_response(
                    {'error': 'Failed to complete OAuth 2.0 handshake.'}
                )
            except Exception:
                # Unknown Exception
                logger.exception('Unexpected Error occured')
                return util.generate_json_response(
                    {'error': 'An unexpected error has occured.'},
                    '500 Internal Server Error'
                )
        this.api_calls[path] = decorated_function
        return decorated_function
    return decorator


# Basic API calls with builtin authentication and CSRF check
# func is a function of the form func(post_vars, user) -> dict, status
def auth_api_call(path, csrf_check=True, min_access_level=ACL.turbo):
    def decorator(func):
        def decorated_function(env, csrf_clerk):
            post_vars = util.retrieve_post_vars(env)
            session = turbo_session.get_session(env)
            account = turbo_session.retrieve_oauth_account(session)
            status = '200 OK'
            if account is None:
                return {'error': 'Couldn\'t authenticate user.'}, status
            csrf_token = post_vars.get('csrf_token', [''])[0]
            if csrf_check and not csrf_clerk.validate(session, csrf_token):
                return {'error': 'CSRF token verification failed.'}, status
            user = User.create(account)
            access_level = User.get_access_level(user)
            if access_level < min_access_level:
                return {'error': 'You do not have the required permissions.'}
            response = func(post_vars, user)
            if csrf_check:
                # create new csrf token for next api call
                response['csrf_token'] = csrf_clerk.register(session)
            return response, status
        return api_call(path)(decorated_function)
    return decorator


# API callables
@auth_api_call('reset_app_password')
def reset_app_password(post_vars, user):
    user.reset_app_password()
    return {'app_password': user.app_password_plain}
