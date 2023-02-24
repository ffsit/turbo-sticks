from __future__ import annotations

import functools
import logging
import random
from oauthlib.oauth2 import OAuth2Error
from typing import overload, Any, TYPE_CHECKING

import turbo_sticks.config as config
import turbo_sticks.discord as discord
import turbo_sticks.patreon as patreon
import turbo_sticks.session as turbo_session
import turbo_sticks.templates as templates
import turbo_sticks.util as util
from turbo_sticks.db import DBError, PoolTimeout
from turbo_sticks.enums import ACL
from turbo_sticks.navigation import (
    render_navigation, set_nav_item, set_nav_external_item
)
from turbo_sticks.properties import get_property, set_property
from turbo_sticks.user import User


if TYPE_CHECKING:
    from typing import Protocol
    from .csrf import TokenClerk
    from .types import MultiDict
    from .types import Response

    class ViewCallable(Protocol):
        def __call__(
            self,
            env:        dict[str, Any],
            csrf_clerk: TokenClerk
        ) -> Response: ...

    class AuthViewCallable(Protocol):
        def __call__(
            self,
            env:        dict[str, Any],
            get_vars:   MultiDict,
            post_vars:  MultiDict,
            csrf_clerk: TokenClerk,
            session:    str | None,
            user:       User | None
        ) -> Response: ...

    class ViewDecorator(Protocol):
        def __call__(self, func: ViewCallable) -> ViewCallable: ...

    class AuthViewDecorator(Protocol):
        def __call__(self, func: AuthViewCallable) -> ViewCallable: ...


logger = logging.getLogger('sticks.views')
views: dict[str, View] = {}


class View:
    __slots__ = ('display_name', 'path', 'uri', 'view')

    display_name: str
    path:         str | None
    uri:          str
    view:         ViewCallable | None

    @overload
    def __init__(self, display_name: str, *, uri: str): ...
    @overload
    def __init__(self, display_name: str, path: str, view: ViewCallable): ...

    def __init__(
        self,
        display_name: str,
        path:         str | None = None,
        view:         ViewCallable | None = None,
        *,
        uri:          str | None = None
    ):
        self.display_name = display_name
        if path is not None:
            if uri is None:
                uri = util.build_url(path, base='base')
            path = config.base_path + path
        assert uri is not None
        self.path = path
        self.uri = uri
        self.view = view


def basic_page_data(name: str) -> dict[str, Any]:
    item = views.get(name)
    display_name = 'Error'
    if item is not None:
        display_name = item.display_name
    return {
        'title': util.sub_title(display_name),
        'description': config.page_description,
        'nav': '',
        'main_path': views['main'].path,
        'css_version': util.get_css_version(),
        'js_version': util.get_js_version()
    }


# View decorator with standard error handling
@overload
def view(
    func: ViewCallable,
    *,
    nav: str = 'error',
    headless: bool = False
) -> ViewCallable: ...
@overload  # noqa: E302
def view(
    func: None = None,
    *,
    nav: str = 'error',
    headless: bool = False
) -> ViewDecorator: ...
def view(  # noqa: E302
    func:     ViewCallable | None = None,
    *,
    nav:      str = 'error',
    headless: bool = False
) -> ViewDecorator | ViewCallable:
    def decorator(func: ViewCallable) -> ViewCallable:
        @functools.wraps(func)
        def wrapper(env: dict[str, Any], csrf_clerk: TokenClerk) -> Response:
            try:
                return func(env, csrf_clerk)

            except (DBError, PoolTimeout):
                # Database Error
                logger.exception('Database Error occured.')
                return error_view('Database Error',
                                  'A database error has occured.',
                                  nav, '500 Internal Server Error', headless)
            except OAuth2Error as error:
                # OAuth 2.0 Error
                logger.info(f'OAuth 2.0 Error occured: {error}',
                            exc_info=config.debug_mode)
                return error_view('OAuth Error',
                                  'Failed to complete OAuth 2.0 handshake.',
                                  nav, '200 OK', headless)
            except Exception:
                # Unknown Exception
                logger.exception('Unexpected Error occured.')
                return error_view('Unknown Error',
                                  'An unexpected error has occured.',
                                  nav, '500 Internal Server Error', headless)
        return wrapper
    return decorator(func) if callable(func) else decorator


# Auth View decorator that uses default login/logout behaviour
@overload
def auth_view(
    func:             AuthViewCallable,
    *,
    nav:              str = 'error',
    min_access_level: ACL = ACL.turbo,
    headless:         bool = False
) -> ViewCallable: ...
@overload  # noqa: E302
def auth_view(
    func:             None = None,
    *,
    nav:              str = 'error',
    min_access_level: ACL = ACL.turbo,
    headless:         bool = False
) -> AuthViewDecorator: ...
def auth_view(  # noqa: E302
    func:             AuthViewCallable | None = None,
    *,
    nav:              str = 'error',
    min_access_level: ACL = ACL.turbo,
    headless:         bool = False
) -> AuthViewDecorator | ViewCallable:
    def decorator(func: AuthViewCallable) -> ViewCallable:
        @functools.wraps(func)
        def wrapper(env: dict[str, Any], csrf_clerk: TokenClerk) -> Response:
            get_vars = util.retrieve_get_vars(env)
            post_vars = util.retrieve_post_vars(env)
            session = turbo_session.get_session(env)
            account = turbo_session.retrieve_oauth_account(session)

            # Start OAuth
            cookie_set = get_vars.get('cookie_set', ['0'])[0]
            if account is None and min_access_level >= ACL.turbo:
                if cookie_set == '1':
                    # Failed to set cookie, tell user to enable cookies
                    return error_view(
                        'Login Error',
                        'Failed to create session. '
                        'Try to enable cookies for this site.'
                    )

                # Show Auth Error in headless mode
                if headless:
                    return error_view(
                        'Auth Error',
                        'You are not logged in.',
                        status='403 Forbidden',
                        headless=True
                    )

                redirect_uri = views['oauth-callback'].uri
                oauth = turbo_session.OAuth2Session(
                    config.mastodon.client_id,
                    redirect_uri=redirect_uri,
                    scope=config.mastodon.scope)
                authorization_url, state = oauth.authorization_url(
                    config.mastodon.authorize_url,
                    turbo_session.generate_oauth_state(env, csrf_clerk)
                )

                status = '307 Temporary Redirect'
                response_body = b''
                response_headers = [('Location', str(authorization_url))]

            # Redirect to url without cookie_set parameter
            elif cookie_set == '1':
                status = '307 Temporary Redirect'
                response_body = b''
                response_headers = [
                    ('Location', util.build_url(env['PATH_INFO']))
                ]

            # Display View
            else:
                user = User.create(account)
                access_level = User.get_access_level(user)
                if access_level < min_access_level:
                    return error_view(
                        'Missing Privileges',
                        'You do not have the required '
                        'permissions to access this.',
                        status='403 Forbidden',
                        access_level=access_level
                    )
                response_body, response_headers, status = func(
                    env, get_vars, post_vars, csrf_clerk, session, user
                )

            return response_body, response_headers, status
        return view(wrapper, nav=nav, headless=headless)
    return decorator(func) if callable(func) else decorator


def error_view(
    title:        str,
    detail:       str,
    nav:          str = 'error',
    status:       str = '200 OK',
    headless:     bool = False,
    access_level: ACL = ACL.guest
) -> Response:

    try:
        page_data = basic_page_data(nav)
        page_data['error_title'] = title
        page_data['error_detail'] = detail
        page_data['nav'] = render_navigation(nav, access_level=access_level)

        if headless:
            response_body = templates.render('error_headless', page_data)
        else:
            response_body = templates.render('error', page_data)

        response_headers = util.basic_response_header(response_body)
        return response_body, response_headers, status

    # In case we encounter an error in rendering the error view
    # we'd like to report it
    except Exception:
        logger.exception('Unexpected Error occured.')
        return b'', [], '500 Internal Server Error'


# View callables
@view(nav='main')
def main_view(env: dict[str, Any], csrf_clerk: TokenClerk) -> Response:
    page_data = basic_page_data('main')
    status = '200 OK'

    session = turbo_session.get_session(env)
    account = turbo_session.retrieve_oauth_account(session)

    # Couldn't auth based on session. Start fresh OAuth 2.0 handshake
    if account is None:
        if session is not None:
            redirect_uri = views['oauth-callback'].uri
            oauth = turbo_session.OAuth2Session(
                config.mastodon.client_id,
                redirect_uri=redirect_uri,
                scope=config.mastodon.scope
            )
            authorization_url, state = oauth.authorization_url(
                config.mastodon.authorize_url,
                turbo_session.generate_oauth_state(env, csrf_clerk)
            )

            status = '307 Temporary Redirect'
            response_body = b''
            response_headers = [('Location', str(authorization_url))]

        # Not yet authenticated and no old session
        else:
            page_data['nav'] = render_navigation('main')
            page_data['login_uri'] = views['login'].path
            response_body = templates.render('main', page_data)
            response_headers = util.basic_response_header(response_body)

    # Display Account Information
    else:
        status = '307 Temporary Redirect'
        response_body = b''
        response_headers = [
            ('Location', views['account'].uri)
        ]
    return response_body, response_headers, status


@auth_view(nav='login')
def login_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    status = '307 Temporary Redirect'
    response_body = b''
    response_headers = [
        ('Location', views['account'].uri)
    ]
    return response_body, response_headers, status


@view(nav='logout')
def logout_view(env: dict[str, Any], csrf_clerk: TokenClerk) -> Response:
    session = turbo_session.get_session(env)
    turbo_session.delete_session(session)
    status = '307 Temporary Redirect'
    response_body = b''
    response_headers = [
        util.unset_cookie_header('TB_SESSION'),
        ('Location', util.build_url('/', base='base'))
    ]
    return response_body, response_headers, status


@view
def oauth_callback_view(
    env: dict[str, Any],
    csrf_clerk: TokenClerk
) -> Response:

    get_vars = util.retrieve_get_vars(env)
    redirect_uri = views['oauth-callback'].uri
    authorization_response = redirect_uri + '?' + env['QUERY_STRING']
    try:
        oauth = turbo_session.OAuth2Session(
            config.mastodon.client_id,
            redirect_uri=redirect_uri,
            scope=config.mastodon.scope
        )
        csrf_token, redirect_to = turbo_session.retrieve_oauth_state(
            get_vars.get('state', [''])[0]
        )
        if not csrf_clerk.validate('oauth-authorization', csrf_token):
            return error_view('CSRF Verfication failed',
                              'Failed to authorize account due to a CSRF '
                              'verfication error, try again.')

        token = oauth.fetch_token(
            config.mastodon.token_url,
            authorization_response=authorization_response,
            client_secret=config.mastodon.client_secret.get_secret_value()
        )
        session_token = turbo_session.create_session(token)

        if not session_token:
            return error_view('Internal Error',
                              'Failed to create session.')

        if not redirect_to:
            redirect_to = '/'

        if redirect_to.startswith('/'):
            redirect_to = util.build_url(redirect_to,
                                         query={'cookie_set': '1'})

        status = '307 Temporary Redirect'
        response_body = b''
        response_headers = [
            util.set_cookie_header('TB_SESSION', session_token),
            ('Location', redirect_to)
        ]
        return response_body, response_headers, status

    except OAuth2Error as error:
        # Might indicate a "deny" on granting access to the app
        logger.info(f'OAuth 2.0 Error occured: {error}',
                    exc_info=config.debug_mode)
        return error_view('OAuth Error',
                          'Failed to authorize account, try again.')


@auth_view
def discord_callback_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    redirect_uri = views['discord-callback'].uri
    authorization_response = redirect_uri + '?' + env['QUERY_STRING']
    discord_user_url = config.discord.api_endpoint + '/users/@me'
    access_level = User.get_access_level(user)
    try:
        oauth = turbo_session.OAuth2Session(
            config.discord.client_id,
            redirect_uri=redirect_uri,
            scope=config.discord.scope
        )
        csrf_token, redirect_to = turbo_session.retrieve_oauth_state(
            get_vars.get('state', [''])[0]
        )
        if not csrf_clerk.validate('oauth-authorization', csrf_token):
            return error_view('CSRF Verfication failed',
                              'Failed to authorize Discord account due to a '
                              'CSRF verfication error, try again.',
                              access_level=access_level)

        token = oauth.fetch_token(
            config.discord.token_url,
            authorization_response=authorization_response,
            client_secret=config.discord.client_secret.get_secret_value()
        )
        discord_user = oauth.get(discord_user_url).json()
        if discord_user is None or discord_user.get('id') is None:
            return error_view('Unexpected error',
                              'Failed to retrieve Discord user details.',
                              access_level=access_level)
        # If people link their discord to another account,
        # the old one should lose its turbo role
        discord_id = int(discord_user['id'])
        if user.discord_id is not None and user.discord_id != discord_id:
            if not discord.remove_turbo_role(user.discord_id):
                return error_view('Unexpected error',
                                  'Failed to reassign TURBO status to '
                                  'a different Discord account. '
                                  'Please try again.')
        user.set_discord_id(discord_id)
        discord.add_turbo_role(discord_id, token)

        if not redirect_to:
            redirect_to = '/'

        if redirect_to.startswith('/'):
            redirect_to = util.build_url(redirect_to)

        status = '307 Temporary Redirect'
        response_body = b''
        response_headers = [('Location', redirect_to)]
        return response_body, response_headers, status

    except OAuth2Error as error:
        # Might indicate a "deny" on granting access to the app
        logger.info(f'OAuth 2.0 Error occured: {error}',
                    exc_info=config.debug_mode)
        return error_view('OAuth Error',
                          'Failed to authorize Discord account, try again.',
                          access_level=access_level)


@auth_view(nav='account')
def account_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    assert session is not None
    page_data = basic_page_data('account')
    # Reset app_password if requested
    if post_vars.get('reset_app_password', ['0'])[0] == '1':
        csrf_token = post_vars.get('csrf_token', [''])[0]
        if csrf_clerk.validate(session, csrf_token):
            # silently failing on an invalid token is fine here
            user.reset_app_password()
    status = '200 OK'
    page_data['nav'] = render_navigation('account', user, expanded=True)
    page_data['form_action'] = views['account'].path
    page_data['username'] = user.username
    assert user.account is not None
    page_data['avatar_src'] = user.account.get('avatar_static', '')
    page_data['app_password'] = user.app_password_plain
    page_data['csrf_token'] = csrf_clerk.register(session)
    discord_member = discord.get_member(user.discord_id)
    discord_user = discord.get_user(discord_member)
    redirect_uri = views['discord-callback'].uri
    oauth = turbo_session.OAuth2Session(
        config.discord.client_id,
        redirect_uri=redirect_uri,
        scope=config.discord.scope
    )
    authorization_url, state = oauth.authorization_url(
        config.discord.authorize_url,
        turbo_session.generate_oauth_state(env, csrf_clerk)
    )
    page_data['discord_username'] = discord.render_username(discord_user)
    page_data['discord_roles'] = discord.render_roles(discord_member)
    page_data['discord_avatar_src'] = discord.get_avatar_url(discord_user)
    page_data['authorization_url'] = authorization_url
    response_body = templates.render('account', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='chat')
def chat_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    page_data = basic_page_data('chat')
    page_data['nav'] = render_navigation('chat', user)
    page_data['chat_uri'] = views['chat-headless'].path
    status = '200 OK'
    response_body = templates.render('chat', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(headless=True)
def headless_chat_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    page_data = basic_page_data('chat-headless')
    page_data['frash_mode'] = ''
    page_data['rules_uri'] = views['rules'].path
    page_data['rand_spinner'] = str(random.randint(1, 5))  # nosec
    page_data['webchat_uri'] = util.build_url('/webchat', 'websockets')
    page_data['live_channel'] = config.discord.live_channel
    status = '200 OK'
    response_body = templates.render('chat_headless', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(min_access_level=ACL.crew)
def frash_chat_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    page_data = basic_page_data('frash-chat')
    page_data['frash_mode'] = 'frash-show-mode'
    page_data['rules_uri'] = views['rules'].path
    page_data['rand_spinner'] = str(random.randint(1, 5))  # nosec
    page_data['webchat_uri'] = util.build_url('/webchat', 'websockets')
    page_data['live_channel'] = config.discord.live_channel
    status = '200 OK'
    response_body = templates.render('chat_headless', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='stream')
def stream_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    page_data = basic_page_data('stream')
    page_data['nav'] = render_navigation('stream', user)
    page_data['stream_uri'] = views['stream-headless'].path
    status = '200 OK'
    response_body = templates.render('stream', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(headless=True)
def headless_stream_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    page_data = basic_page_data('stream-headless')
    page_data['chat_uri'] = views['chat-headless'].path
    page_data['default_embed'] = util.get_default_embed(config.stream_sources)
    page_data['video_sources'] = util.generate_video_sources(
        config.stream_sources
    )
    status = '200 OK'
    response_body = templates.render('stream_embed', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='theatre', min_access_level=ACL.guest)
def theatre_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    page_data = basic_page_data('theatre')
    page_data['nav'] = render_navigation('theatre', user)
    page_data['theatre_uri'] = views['theatre-headless'].path
    status = '200 OK'
    response_body = templates.render('theatre', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(min_access_level=ACL.guest, headless=True)
def headless_theatre_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    page_data = basic_page_data('theatre-headless')
    status = '200 OK'
    given_password = post_vars.get('theatre_password', [''])[0]
    theatre_password = get_property('theatre_password', None)
    if (
        user is not None or given_password == theatre_password or
        patreon.validate_session(env)
    ):
        page_data['chat_uri'] = views['chat-headless'].path
        page_data['youtube_stream_id'] = get_property('theatre_stream_id')
        response_body = templates.render('youtube_embed', page_data)
    else:
        callback_view = views['patreon-theatre-callback']
        redirect_uri = callback_view.uri
        oauth = turbo_session.OAuth2Session(
            config.patreon.client_id,
            redirect_uri=redirect_uri,
            scope=config.patreon.scope
        )
        authorization_url, state = oauth.authorization_url(
            config.patreon.authorize_url,
            turbo_session.generate_oauth_state(env, csrf_clerk)
        )
        page_data['patreon_authorization_uri'] = authorization_url
        page_data['form_action'] = views['theatre-headless'].path
        page_data['login_uri'] = util.build_url(
            views['login'].path or '/login',
            query={'redirect_to': views['theatre'].path or '/theatre'}
        )
        response_body = templates.render('theatre_auth', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='theatre-admin', min_access_level=ACL.crew)
def theatre_admin_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    assert user is not None
    assert session is not None
    page_data = basic_page_data('theatre-admin')
    page_data['nav'] = render_navigation('theatre-admin', user)
    theatre_password = post_vars.get(
        'theatre_password', [get_property('theatre_password')])[0]
    youtube_stream_id = post_vars.get(
        'youtube_stream_id', [get_property('theatre_stream_id')])[0]
    set_property('theatre_password', theatre_password)
    set_property('theatre_stream_id', youtube_stream_id)
    page_data['form_action'] = views['theatre-admin'].path
    page_data['theatre_password'] = theatre_password
    page_data['youtube_stream_id'] = youtube_stream_id
    page_data['csrf_token'] = csrf_clerk.register(session)
    status = '200 OK'
    response_body = templates.render('theatre_admin', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@view(nav='theatre')
def patreon_theatre_callback_view(
    env:        dict[str, Any],
    csrf_clerk: TokenClerk
) -> Response:

    redirect_uri = views['patreon-theatre-callback'].uri
    authorization_response = redirect_uri + '?' + env['QUERY_STRING']
    get_vars = util.retrieve_get_vars(env)
    try:
        oauth = turbo_session.OAuth2Session(
            config.patreon.client_id,
            redirect_uri=redirect_uri,
            scope=config.patreon.scope
        )
        csrf_token, redirect_to = turbo_session.retrieve_oauth_state(
            get_vars.get('state', [''])[0]
        )
        if not csrf_clerk.validate('oauth-authorization', csrf_token):
            return error_view('CSRF Verfication failed',
                              'Failed to authorize Patreon account due to a '
                              'CSRF verfication error, try again.')
        oauth.fetch_token(
            config.patreon.token_url,
            authorization_response=authorization_response,
            client_secret=config.patreon.client_secret.get_secret_value()
        )
        patreon_user = patreon.get_current_user(oauth)
        if 'errors' in patreon_user:
            return error_view('Unexpected error',
                              'Failed to retrieve Patreon user details.')

        memberships = patreon_user.get('memberships', [])
        assert isinstance(memberships, list)
        session_token = None
        for item in memberships:
            assert isinstance(item, dict)
            campaign = item.get('campaign', {})
            assert isinstance(campaign, dict)
            campaign_id = campaign.get('id', '')
            if campaign_id != config.patreon.campaign_id:
                continue

            cents = item.get('currently_entitled_amount_cents', 0)
            if cents >= config.patreon.theatre_cents:
                session_token = patreon.create_session()
            break

        if session_token is None:
            dollars = config.patreon.theatre_cents // 100
            return error_view(
                'Insufficient pledge',
                f'We could not verify that you are pledging ${dollars} '
                'to the Video Games AWESOME Patreon.'
            )

        redirect_to = views['theatre'].uri

        status = '307 Temporary Redirect'
        response_body = b''
        response_headers = [
            util.set_cookie_header(
                'TB_PATREON_SESSION',
                session_token,
                max_age=config.patreon.session_max_age
            ),
            ('Location', redirect_to)
        ]
        return response_body, response_headers, status

    except OAuth2Error as error:
        # Might indicate a "deny" on granting access to the app
        logger.info(f'OAuth 2.0 Error occured: {error}',
                    exc_info=config.debug_mode)
        return error_view('OAuth Error',
                          'Failed to authorize Patreon account, try again.')


@auth_view(nav='rules', min_access_level=ACL.guest)
def rules_view(
    env:        dict[str, Any],
    get_vars:   MultiDict,
    post_vars:  MultiDict,
    csrf_clerk: TokenClerk,
    session:    str | None,
    user:       User | None
) -> Response:

    page_data = basic_page_data('rules')
    page_data['nav'] = render_navigation('rules', user)
    status = '200 OK'
    response_body = templates.render('rules', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


# List of views
views['main'] = View(
    'Home', '/', main_view
)
views['account'] = View(
    'Account Overview', '/account', account_view
)
views['login'] = View(
    'Login', '/login', login_view
)
views['logout'] = View(
    'Logout', '/logout', logout_view
)
views['oauth-callback'] = View(
    'OAuth Callback', '/callback', oauth_callback_view
)
views['discord-callback'] = View(
    'Discord Callback', '/discord-callback', discord_callback_view
)
views['chat-headless'] = View(
    'TURBO Chat', '/chat-headless', headless_chat_view
)
views['chat'] = View(
    'TURBO Chat', '/chat', chat_view
)
views['frash-chat'] = View(
    'Frash Chat', '/frash-chat', frash_chat_view
)
views['stream'] = View(
    'TURBO Stream', '/stream', stream_view
)
views['stream-headless'] = View(
    'TURBO Stream', '/stream-headless', headless_stream_view
)
views['theatre-admin'] = View(
    'Movie Night Admin', '/theatre-admin', theatre_admin_view
)
views['theatre'] = View(
    'Movie Night', '/theatre', theatre_view
)
views['theatre-headless'] = View(
    'Movie Night', '/theatre-headless', headless_theatre_view
)
views['patreon-theatre-callback'] = View(
    'Patreon Theatre Callback',
    '/patreon-theatre-callback',
    patreon_theatre_callback_view
)
views['rules'] = View(
    'Rules', '/rules', rules_view
)


set_nav_item('login', max_access_level=ACL.patron)
set_nav_item('account', min_access_level=ACL.turbo)
set_nav_item('chat', min_access_level=ACL.turbo)
set_nav_item('frash-chat', min_access_level=ACL.crew)
set_nav_item('stream', min_access_level=ACL.turbo)
set_nav_item('theatre-admin', min_access_level=ACL.crew)
set_nav_item('theatre')
set_nav_external_item('toot', 'TURBO Toot',
                      'https://toot.turbo.chat')
set_nav_external_item('discourse', 'TURBO Discourse',
                      'https://discourse.turbo.chat')
set_nav_external_item('discord', 'VGA Discord',
                      'https://discord.gg/zFx3knd')
set_nav_item('rules')
set_nav_item('logout', min_access_level=ACL.turbo)
