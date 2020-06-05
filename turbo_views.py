import sys
import json
import random
from oauthlib.oauth2 import OAuth2Error

import turbo_nav
import turbo_session
import turbo_config as config
import turbo_templates as templates
import turbo_discord as discord
import turbo_patreon as patreon
import turbo_util as util
from turbo_db import DBError
from turbo_properties import get_property, set_property
from turbo_user import ACL, User

this = sys.modules[__name__]

# Views
turbo_views = {}


class turbo_view:
    def __init__(self, display_name, path=None, view=None, uri=None):
        self.display_name = display_name
        if(uri is None and path is not None):
            uri = util.build_url(path, base='base')
        if path is not None:
            path = config.base_path + path
        self.path = path
        self.uri = uri
        self.view = view


def basic_page_data(name):
    item = this.turbo_views.get(name)
    display_name = 'Error'
    if item is not None:
        display_name = item.display_name
    return {
        'title': util.sub_title(display_name),
        'description': config.page_description,
        'main_path': this.turbo_views['main'].path,
        'css_version': util.get_css_version(),
        'js_version': util.get_js_version()
    }


# View decorator with standard error handling
# func is a function of the form func(env, csrf_clerk)
#      -> response_body, response_headers, status
def view(func=None, *, nav='error', headless=False):
    def decorator(func):
        def decorated_function(env, csrf_clerk):
            response_body = 'Template Render Error.'
            response_headers = util.basic_response_header(response_body)
            status = '200 OK'
            try:
                response_body, response_headers, status = func(env, csrf_clerk)

            except DBError as error:
                # Database Error
                util.print_exception('Database Error occured:', error)
                return error_view('Database Error',
                                  'A database error has occured.',
                                  nav, '500 Internal Server Error', headless)
            except OAuth2Error as error:
                # OAuth 2.0 Error
                util.print_exception('OAuth 2.0 Error occured:', error)
                return error_view('OAuth Error',
                                  'Failed to complete OAuth 2.0 handshake.',
                                  nav, status, headless)
            except Exception as error:
                # Unknown Exception
                util.print_exception('Unexpected Error occured:', error, False)
                return error_view('Unknown Error',
                                  'An unexpected error has occured.',
                                  nav, '500 Internal Server Error', headless)
            else:
                # Normal function return without errors
                return response_body, response_headers, status
        return decorated_function
    return decorator(func) if callable(func) else decorator


# Auth View decorator that uses default login/logout behaviour
# func is a function of the form:
# func(env, get_vars, post_vars, csrf_clerk, session, user)
#      -> response_body, response_headers, status
def auth_view(func=None, *, nav='error', min_access_level=ACL.turbo,
              headless=False):
    def decorator(func):
        def decorated_function(env, csrf_clerk):
            get_vars = util.retrieve_get_vars(env)
            post_vars = util.retrieve_post_vars(env)
            session = turbo_session.get_session(env)
            account = turbo_session.retrieve_oauth_account(session)

            # Start OAuth
            cookie_set = int(get_vars.get('cookie_set', [0])[0])
            # Failed to set cookie, tell user to enable cookies
            if(account is None and min_access_level >= ACL.turbo and
               cookie_set == 1):
                return error_view('Login Error',
                                  'Failed to create session. Try to enable '
                                  ' cookies for this site.')

            elif(account is None and min_access_level >= ACL.turbo):
                # Show Auth Error in headless mode
                if(headless):
                    return error_view('Auth Error', 'You are not logged in.',
                                      nav, headless=True)

                redirect_uri = turbo_views['oauth-callback'].uri
                oauth = turbo_session.OAuth2Session(
                    config.mastodon.client_id,
                    redirect_uri=redirect_uri,
                    scope=config.mastodon.scope)
                authorization_url, state = oauth.authorization_url(
                    config.mastodon.authorize_url,
                    turbo_session.generate_state(env, csrf_clerk)
                )

                status = '307 Temporary Redirect'
                response_body = ''
                response_headers = [('Location', str(authorization_url))]

            # Redirect to url without cookie_set parameter
            elif(cookie_set == 1):
                status = '307 Temporary Redirect'
                response_body = ''
                response_headers = [
                    ('Location', util.build_url(env['PATH_INFO']))
                ]

            # Display View
            else:
                user = User.create(account)
                access_level = User.get_access_level(user)
                if access_level < min_access_level:
                    return error_view('Missing Privileges',
                                      'You do not have the required '
                                      'permissions to access this.',
                                      access_level=access_level)
                response_body, response_headers, status = func(
                    env, get_vars, post_vars, csrf_clerk, session, user
                )

            return response_body, response_headers, status
        return view(decorated_function, nav=nav, headless=headless)
    return decorator(func) if callable(func) else decorator


def error_view(title, detail, nav='error', status='200 OK', headless=False,
               access_level=ACL.guest):
    try:
        page_data = basic_page_data(nav)
        page_data['error_title'] = title
        page_data['error_detail'] = detail
        page_data['nav'] = turbo_nav.generate_html(nav,
                                                   access_level=access_level)

        if(headless):
            response_body = templates.render('error_headless', page_data)
        else:
            response_body = templates.render('error', page_data)

        response_headers = util.basic_response_header(response_body)
        return response_body, response_headers, status

    # In case we encounter an error in rendering the error view
    # we'd like to report it
    except Exception as error:
        util.print_exception('Unexpected Error occured: ', error, False)
        return '', '', '500 Internal Server Error'


# View callables
@view(nav='main')
def main_view(env, csrf_clerk):
    page_data = basic_page_data('main')
    response_body = 'Template Render Error.'
    response_headers = util.basic_response_header(response_body)
    status = '200 OK'

    session = turbo_session.get_session(env)
    account = turbo_session.retrieve_oauth_account(session)

    # Couldn't auth based on session. Start fresh OAuth 2.0 handshake
    if(account is None):
        if(session is not None):
            redirect_uri = turbo_views['oauth-callback'].uri
            oauth = turbo_session.OAuth2Session(
                config.mastodon.client_id,
                redirect_uri=redirect_uri,
                scope=config.mastodon.scope
            )
            authorization_url, state = oauth.authorization_url(
                config.mastodon.authorize_url,
                turbo_session.generate_state(env, csrf_clerk)
            )

            status = '307 Temporary Redirect'
            response_body = ''
            response_headers = [('Location', str(authorization_url))]

        # Not yet authenticated and no old session
        else:
            page_data['nav'] = turbo_nav.generate_html('main')
            page_data['login_uri'] = turbo_views['login'].path
            response_body = templates.render('main', page_data)
            response_headers = util.basic_response_header(response_body)

    # Display Account Information
    else:
        status = '307 Temporary Redirect'
        response_body = ''
        response_headers = [
            ('Location', turbo_views['account'].uri)
        ]
    return response_body, response_headers, status


@auth_view(nav='login')
def login_view(env, get_vars, post_vars, csrf_clerk, session, user):
    status = '307 Temporary Redirect'
    response_body = ''
    response_headers = [
        ('Location', turbo_views['account'].uri)
    ]
    return response_body, response_headers, status


@view(nav='logout')
def logout_view(env, csrf_clerk):
    response_body = 'Template Render Error.'
    response_headers = util.basic_response_header(response_body)
    status = '200 OK'

    session = turbo_session.get_session(env)
    turbo_session.delete_session(session)
    status = '307 Temporary Redirect'
    response_body = ''
    response_headers = [
        util.unset_cookie_header('TB_SESSION'),
        ('Location', util.build_url('/', base='base'))
    ]
    return response_body, response_headers, status


@view
def oauth_callback_view(env, csrf_clerk):
    get_vars = util.retrieve_get_vars(env)
    redirect_uri = turbo_views['oauth-callback'].uri
    authorization_response = redirect_uri + '?' + env['QUERY_STRING']
    try:
        oauth = turbo_session.OAuth2Session(
            config.mastodon.client_id,
            redirect_uri=redirect_uri,
            scope=config.mastodon.scope
        )
        oauth_state = turbo_session.retrieve_oauth_state(
            get_vars.get('state', [''])[0]
        )
        if(oauth_state and
           csrf_clerk.validate('oauth-authorization', oauth_state[0])):
            token = oauth.fetch_token(
                config.mastodon.token_url,
                authorization_response=authorization_response,
                client_secret=config.mastodon.client_secret
            )
            session_token = turbo_session.create_session(token)

            if(session_token is not None):
                redirect_to = str(oauth_state[1])
                if redirect_to.startswith('/'):
                    redirect_to = util.build_url(redirect_to,
                                                 query={'cookie_set': 1})

                status = '307 Temporary Redirect'
                response_body = ''
                response_headers = [
                    util.set_cookie_header('TB_SESSION', session_token),
                    ('Location', redirect_to)
                ]
            else:
                return error_view('Internal Error',
                                  'Failed to create session.')
        else:
            return error_view('CSRF Verfication failed',
                              'Failed to authorize account due to a CSRF '
                              'verfication error, try again.')

    except OAuth2Error as error:
        # Might indicate a "deny" on granting access to the app
        util.print_exception('OAuth 2.0 Error occured: ', error)
        return error_view('OAuth Error',
                          'Failed to authorize account, try again.')
    else:
        # Normal function return without errors
        return response_body, response_headers, status


@auth_view
def discord_callback_view(env, get_vars, post_vars, csrf_clerk, session, user):
    redirect_uri = turbo_views['discord-callback'].uri
    authorization_response = redirect_uri + '?' + env['QUERY_STRING']
    discord_user_url = config.discord.api_endpoint + '/users/@me'
    access_level = User.get_access_level(user)
    try:
        oauth = turbo_session.OAuth2Session(
            config.discord.client_id,
            redirect_uri=redirect_uri,
            scope=config.discord.scope
        )
        oauth_state = turbo_session.retrieve_oauth_state(
            get_vars.get('state', [''])[0]
        )
        if(oauth_state and
           csrf_clerk.validate('oauth-authorization', oauth_state[0])):
            token = oauth.fetch_token(
                config.discord.token_url,
                authorization_response=authorization_response,
                client_secret=config.discord.client_secret
            )
            discord_user = json.loads(oauth.get(discord_user_url).text)
            if discord_user is not None and discord_user.get('id') is not None:
                # If people link their discord to another account,
                # the old one should lose its turbo role
                if(user.discord_id is not None and
                   user.discord_id != int(discord_user['id'])):
                    if(not discord.remove_turbo_role(user.discord_id)):
                        return error_view('Unexpected error',
                                          'Failed to reassign TURBO status to '
                                          'a different Discord account. '
                                          'Please try again.')
                user.set_discord_id(discord_user['id'])
                discord.add_turbo_role(user.discord_id, token)

                redirect_to = str(oauth_state[1])
                if redirect_to.startswith('/'):
                    redirect_to = util.build_url(redirect_to)

                status = '307 Temporary Redirect'
                response_body = ''
                response_headers = [('Location', redirect_to)]
            else:
                return error_view('Unexpected error',
                                  'Failed to retrieve Discord user details.',
                                  access_level=access_level)
        else:
            return error_view('CSRF Verfication failed',
                              'Failed to authorize Discord account due to a '
                              'CSRF verfication error, try again.',
                              access_level=access_level)

    except OAuth2Error as error:
        # Might indicate a "deny" on granting access to the app
        util.print_exception('OAuth 2.0 Error occured: ', error)
        return error_view('OAuth Error',
                          'Failed to authorize Discord account, try again.',
                          access_level=access_level)
    else:
        # Normal function return without errors
        return response_body, response_headers, status


@auth_view(nav='account')
def account_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('account')
    # Reset app_password if requested
    if(int(post_vars.get('reset_app_password', [0])[0]) == 1):
        csrf_token = post_vars.get('csrf_token', [''])[0]
        if(csrf_clerk.validate(session, csrf_token)):
            # silently failing on an invalid token is fine here
            user.reset_app_password()
    status = '200 OK'
    page_data['nav'] = turbo_nav.generate_html('account', user, expanded=True)
    page_data['form_action'] = turbo_views['account'].path
    page_data['username'] = user.username
    page_data['avatar_src'] = user.account.get('avatar', '')
    page_data['app_password'] = user.app_password_plain
    page_data['csrf_token'] = csrf_clerk.register(session)
    discord_member = discord.get_member(user.discord_id)
    discord_user = discord.get_user(discord_member)
    redirect_uri = turbo_views['discord-callback'].uri
    oauth = turbo_session.OAuth2Session(
        config.discord.client_id,
        redirect_uri=redirect_uri,
        scope=config.discord.scope
    )
    authorization_url, state = oauth.authorization_url(
        config.discord.authorize_url,
        turbo_session.generate_state(env, csrf_clerk)
    )
    page_data['discord_username'] = discord.render_username(discord_user)
    page_data['discord_roles'] = discord.render_roles(discord_member)
    page_data['discord_avatar_src'] = discord.get_avatar_url(discord_user)
    page_data['authorization_url'] = authorization_url
    response_body = templates.render('account', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='chat')
def chat_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('chat')
    page_data['nav'] = turbo_nav.generate_html('chat', user)
    page_data['chat_uri'] = turbo_views['chat-headless'].path
    status = '200 OK'
    response_body = templates.render('chat', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(headless=True)
def headless_chat_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('chat-headless')
    page_data['frash_mode'] = ''
    page_data['rules_uri'] = turbo_views['rules'].path
    page_data['legacy_uri'] = turbo_views['legacy-chat-headless'].path
    page_data['rand_spinner'] = str(random.randint(1, 5))
    page_data['webchat_uri'] = util.build_url('/webchat', 'websockets')
    page_data['live_channel'] = config.discord.live_channel
    status = '200 OK'
    response_body = templates.render('chat_headless', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(min_access_level=ACL.crew)
def frash_chat_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('frash-chat')
    page_data['frash_mode'] = 'frash-show-mode'
    page_data['rules_uri'] = turbo_views['rules'].path
    page_data['legacy_uri'] = turbo_views['legacy-chat-headless'].path
    page_data['rand_spinner'] = str(random.randint(1, 5))
    page_data['webchat_uri'] = util.build_url('/webchat', 'websockets')
    page_data['live_channel'] = config.discord.live_channel
    status = '200 OK'
    response_body = templates.render('chat_headless', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(headless=True)
def headless_legacy_chat_view(env, get_vars, post_vars, csrf_clerk, session,
                              user):
    page_data = basic_page_data('legacy-chat-headless')
    page_data['rules_uri'] = turbo_views['rules'].path
    page_data['rand_spinner'] = str(random.randint(1, 5))
    page_data['username'] = user.username if user is not None else ''
    page_data['password'] = user.app_password_plain if user is not None else ''
    status = '200 OK'
    response_body = templates.render('legacy_chat_headless', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='stream')
def stream_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('stream')
    page_data['nav'] = turbo_nav.generate_html('stream', user)
    page_data['stream_uri'] = turbo_views['stream-headless'].path
    status = '200 OK'
    response_body = templates.render('stream', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(headless=True)
def headless_stream_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('stream-headless')
    page_data['chat_uri'] = turbo_views['chat-headless'].path
    page_data['default_embed'] = util.get_default_embed(config.stream_sources)
    page_data['video_sources'] = util.generate_video_sources(
        config.stream_sources
    )
    status = '200 OK'
    response_body = templates.render('stream_embed', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='theatre', min_access_level=ACL.guest)
def theatre_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('theatre')
    page_data['nav'] = turbo_nav.generate_html('theatre', user)
    page_data['theatre_uri'] = turbo_views['theatre-headless'].path
    status = '200 OK'
    response_body = templates.render('theatre', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(min_access_level=ACL.guest, headless=True)
def headless_theatre_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('theatre-headless')
    status = '200 OK'
    given_password = post_vars.get('theatre_password', [''])[0]
    theatre_password = get_property('theatre_password', None)
    if(user is not None or given_password == theatre_password or
       patreon.validate_session(env)):
        page_data['chat_uri'] = turbo_views['chat-headless'].path
        page_data['youtube_stream_id'] = get_property('theatre_stream_id')
        response_body = templates.render('youtube_embed', page_data)
    else:
        callback_view = turbo_views['patreon-theatre-callback']
        redirect_uri = callback_view.uri
        oauth = turbo_session.OAuth2Session(
            config.patreon.client_id,
            redirect_uri=redirect_uri,
            scope=config.patreon.scope
        )
        authorization_url, state = oauth.authorization_url(
            config.patreon.authorize_url,
            turbo_session.generate_state(env, csrf_clerk)
        )
        page_data['patreon_authorization_uri'] = authorization_url
        page_data['form_action'] = turbo_views['theatre-headless'].path
        page_data['login_uri'] = util.build_url(
            turbo_views['login'].path,
            query={'redirect_to': turbo_views['theatre'].path}
        )
        response_body = templates.render('theatre_auth', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@auth_view(nav='theatre-admin', min_access_level=ACL.crew)
def theatre_admin_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('theatre-admin')
    page_data['nav'] = turbo_nav.generate_html('theatre-admin', user)
    theatre_password = post_vars.get(
        'theatre_password', [get_property('theatre_password')])[0]
    youtube_stream_id = post_vars.get(
        'youtube_stream_id', [get_property('theatre_stream_id')])[0]
    set_property('theatre_password', theatre_password)
    set_property('theatre_stream_id', youtube_stream_id)
    page_data['form_action'] = turbo_views['theatre-admin'].path
    page_data['theatre_password'] = theatre_password
    page_data['youtube_stream_id'] = youtube_stream_id
    page_data['csrf_token'] = csrf_clerk.register(session)
    status = '200 OK'
    response_body = templates.render('theatre_admin', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


@view(nav='theatre')
def patreon_theatre_callback_view(env, csrf_clerk):
    redirect_uri = turbo_views['patreon-theatre-callback'].uri
    authorization_response = redirect_uri + '?' + env['QUERY_STRING']
    get_vars = util.retrieve_get_vars(env)
    try:
        oauth = turbo_session.OAuth2Session(
            config.patreon.client_id,
            redirect_uri=redirect_uri,
            scope=config.patreon.scope)
        oauth_state = turbo_session.retrieve_oauth_state(
            get_vars.get('state', [''])[0]
        )
        if(oauth_state and
           csrf_clerk.validate('oauth-authorization', oauth_state[0])):
            oauth.fetch_token(
                config.patreon.token_url,
                authorization_response=authorization_response,
                client_secret=config.patreon.client_secret
            )
            patreon_user = patreon.get_current_user(oauth)
            if(patreon_user is not None and len(patreon_user) > 0):
                memberships = patreon_user[0].get('memberships', [])
                session_token = None
                for item in memberships:
                    cents = item.get('currently_entitled_amount_cents', 0)
                    campaign_id = item.get('campaign', [{}])[0].get('id', '')
                    if(cents >= config.patreon.theatre_cents and
                       campaign_id == config.patreon.campaign_id):
                        session_token = patreon.create_session()

                if(session_token is None):
                    dollars = str(config.patreon.theatre_cents // 100)
                    return error_view('Insufficient pledge',
                                      'We could not verify that you are '
                                      'pledging $' + dollars + ' to the '
                                      'Video Games AWESOME Patreon.')

                redirect_to = turbo_views['theatre'].uri

                status = '307 Temporary Redirect'
                response_body = ''
                response_headers = [
                    util.set_cookie_header('TB_PATREON_SESSION',
                                           session_token),
                    ('Location', redirect_to)
                ]
            else:
                return error_view('Unexpected error',
                                  'Failed to retrieve Patreon user details.')
        else:
            return error_view('CSRF Verfication failed',
                              'Failed to authorize Patreon account due to a '
                              'CSRF verfication error, try again.')

    except OAuth2Error as error:
        # Might indicate a "deny" on granting access to the app
        util.print_exception('OAuth 2.0 Error occured: ', error)
        return error_view('OAuth Error',
                          'Failed to authorize Patreon account, try again.')
    else:
        # Normal function return without errors
        return response_body, response_headers, status


@auth_view(nav='rules', min_access_level=ACL.guest)
def rules_view(env, get_vars, post_vars, csrf_clerk, session, user):
    page_data = basic_page_data('rules')
    page_data['nav'] = turbo_nav.generate_html('rules', user)
    status = '200 OK'
    response_body = templates.render('rules', page_data)
    response_headers = util.basic_response_header(response_body)
    return response_body, response_headers, status


# List of views
turbo_views['main'] = turbo_view(
    'Home', '/', main_view
)
turbo_views['account'] = turbo_view(
    'Account Overview', '/account', account_view
)
turbo_views['login'] = turbo_view(
    'Login', '/login', login_view
)
turbo_views['logout'] = turbo_view(
    'Logout', '/logout', logout_view
)
turbo_views['oauth-callback'] = turbo_view(
    'OAuth Callback', '/callback', oauth_callback_view
)
turbo_views['discord-callback'] = turbo_view(
    'Discord Callback', '/discord-callback', discord_callback_view
)
turbo_views['chat-headless'] = turbo_view(
    'TURBO Chat', '/chat-headless', headless_chat_view
)
turbo_views['legacy-chat-headless'] = turbo_view(
    'TURBO Chat', '/legacy-chat-headless', headless_legacy_chat_view
)
turbo_views['chat'] = turbo_view(
    'TURBO Chat', '/chat', chat_view
)
turbo_views['frash-chat'] = turbo_view(
    'Frash Chat', '/frash-chat', frash_chat_view
)
turbo_views['stream'] = turbo_view(
    'TURBO Stream', '/stream', stream_view
)
turbo_views['stream-headless'] = turbo_view(
    'TURBO Stream', '/stream-headless', headless_stream_view
)
turbo_views['theatre-admin'] = turbo_view(
    'Movie Night Admin', '/theatre-admin', theatre_admin_view
)
turbo_views['theatre'] = turbo_view(
    'Movie Night', '/theatre', theatre_view
)
turbo_views['theatre-headless'] = turbo_view(
    'Movie Night', '/theatre-headless', headless_theatre_view
)
turbo_views['patreon-theatre-callback'] = turbo_view(
    'Patreon Theatre Callback',
    '/patreon-theatre-callback',
    patreon_theatre_callback_view
)
turbo_views['rules'] = turbo_view(
    'Rules', '/rules', rules_view
)


# List of nav items
def set_nav_item(name, max_access_level=ACL.admin,
                 min_access_level=ACL.guest):
    turbo_nav.items[name] = turbo_nav.nav_item(turbo_views[name],
                                               max_access_level,
                                               min_access_level)


def set_nav_external_item(name, display_name, uri,
                          max_access_level=ACL.admin,
                          min_access_level=ACL.guest):
    dummy_view = turbo_view(display_name, uri=uri)
    turbo_nav.items[name] = turbo_nav.nav_item(dummy_view,
                                               max_access_level,
                                               min_access_level)


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
set_nav_item('rules')
set_nav_item('logout', min_access_level=ACL.turbo)

this.turbo_views = turbo_views
