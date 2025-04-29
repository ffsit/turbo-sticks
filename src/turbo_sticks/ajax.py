from __future__ import annotations

import functools
import logging
from oauthlib.oauth2 import OAuth2Error

import turbo_sticks.config as config
import turbo_sticks.util as util
from turbo_sticks.db import DBError, PoolTimeout
from turbo_sticks.enums import ACL
from turbo_sticks.session import get_session, retrieve_oauth_account
from turbo_sticks.user import User


from typing import Any, TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Protocol
    from .csrf import TokenClerk
    from .types import JSONObject
    from .types import MultiDict
    from .types import Response

    class RawAPICallable(Protocol):
        def __call__(
            self,
            env:        dict[str, Any],
            csrf_clerk: TokenClerk
        ) -> Response: ...

    class APICallable(Protocol):
        def __call__(
            self,
            env:        dict[str, Any],
            csrf_clerk: TokenClerk
        ) -> tuple[JSONObject, str]: ...

    class AuthAPICallable(Protocol):
        def __call__(
            self,
            post_vars:  MultiDict,
            user:       User | None
        ) -> JSONObject: ...

    class APIDecorator(Protocol):
        def __call__(self, func: APICallable) -> RawAPICallable: ...

    class AuthAPIDecorator(Protocol):
        def __call__(self, func: AuthAPICallable) -> RawAPICallable: ...

logger = logging.getLogger('sticks.api')
api_calls: dict[str, RawAPICallable] = {}


# API call decorator
def api_call(path: str) -> APIDecorator:
    def decorator(func: APICallable) -> RawAPICallable:
        @functools.wraps(func)
        def wrapper(env: dict[str, Any], csrf_clerk: TokenClerk) -> Response:
            try:
                data, status = func(env, csrf_clerk)
                return util.generate_json_response(data, status)
            except (DBError, PoolTimeout):
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
                    {'error': 'Failed to complete OAuth 2.0 handshake.'},
                    '403 Forbidden'
                )
            except Exception:
                # Unknown Exception
                logger.exception('Unexpected Error occured')
                return util.generate_json_response(
                    {'error': 'An unexpected error has occured.'},
                    '500 Internal Server Error'
                )
        api_calls[path] = wrapper
        return wrapper
    return decorator


# Basic API calls with builtin authentication and CSRF check
# func is a function of the form func(post_vars, user) -> dict, status
def auth_api_call(
    path:             str,
    *,
    status:           str = '200 OK',
    csrf_check:       bool = True,
    min_access_level: ACL = ACL.turbo
) -> AuthAPIDecorator:

    def decorator(func: AuthAPICallable) -> RawAPICallable:
        @functools.wraps(func)
        def wrapper(
            env:        dict[str, Any],
            csrf_clerk: TokenClerk
        ) -> tuple[JSONObject, str]:

            post_vars = util.retrieve_post_vars(env)
            session = get_session(env)
            account = retrieve_oauth_account(session)
            if account is None:
                return (
                    {'error': 'Couldn\'t authenticate user.'},
                    '403 Forbidden'
                )

            assert session is not None
            csrf_token = post_vars.get('csrf_token', [''])[0]
            if csrf_check and not csrf_clerk.validate(session, csrf_token):
                return (
                    {'error': 'CSRF token verification failed.'},
                    '403 Forbidden'
                )

            user = User.create(account)
            access_level = User.get_access_level(user)
            if access_level < min_access_level:
                return (
                    {'error': 'You do not have the required permissions.'},
                    '403 Forbidden'
                )

            response = func(post_vars, user)
            if csrf_check:
                # create new csrf token for next api call
                response['csrf_token'] = csrf_clerk.register(session)
            return response, status
        return api_call(path)(wrapper)
    return decorator


# API callables
@auth_api_call('reset_app_password')
def reset_app_password(
    post_vars: MultiDict,
    user: User | None
) -> JSONObject:

    assert user is not None
    user.reset_app_password()
    return {'app_password': user.app_password_plain}
