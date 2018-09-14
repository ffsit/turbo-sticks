import sys
import random
from oauthlib.oauth2 import OAuth2Error

import turbo_session
import turbo_user
import turbo_templates as templates
import turbo_nav
from turbo_db import DBWarning, DBError
from turbo_config import *
from turbo_util import *

this = sys.modules[__name__]

# Views
this.turbo_views = {}

class turbo_view:
	def __init__(self, display_name, uri=None, view=None):
		self.display_name = display_name
		if(uri is not None and uri.startswith('/')):
			uri = base_path + uri
		self.uri = uri
		self.view = view

def basic_page_data(name):
	item = this.turbo_views.get(name)
	display_name = 'Error'
	if item is not None:
		display_name = item.display_name
	return {
		'title': sub_title(display_name),
		'description': page_description,
		'main_path': this.turbo_views['main'].uri
	}

# Create View with standard error handling
# func is a function of the form func(env, csrf_clerk, db)
def create_view(func, nav='error', headless=False):
	def view(env, csrf_clerk, db):
		response_body = 'Template Render Error.'
		response_headers = basic_response_header(response_body)
		status = '200 OK'
		try:
			response_body, response_headers, status = func(env, csrf_clerk, db)

		except DBWarning as warning:
			# Database Warning, can continue normally
			print_exception('Database Warning occured:', warning)
			pass
		except DBError as error:
			# Database Error
			print_exception('Database Error occured: ', error)
			return error_view('Database Error',
			                  'A database error has occured.',
			                  nav, status, headless)
		except OAuth2Error as error:
			# OAuth 2.0 Error
			print_exception('OAuth 2.0 Error occured: ', error)
			return error_view('OAuth Error',
			                  'Failed to complete OAuth 2.0 handshake.',
			                  nav, status, headless)
		except Exception as error:
			# Unknown Exception
			print_exception('Unexpected Error occured: ', error)
			return error_view('Unknown Error',
			                  'An unexpected error has occured.',
			                  nav, status, headless)
		else:
			# Normal function return without errors
			return response_body, response_headers, status
	return view

# Basic Views that use default login/logout behaviour and only require post_vars
# func is a function of the form func(post_vars, csrf_clerk, db, session, user) -> dict
def create_basic_view(func, nav='error', needs_auth=True, headless=False):
	def basic_view(env, csrf_clerk, db):
 		post_vars = retrieve_post_vars(env)
		session = turbo_session.get_session(env)
		account = turbo_session.retrieve_oauth_account(session, db)

 		# Start OAuth
 		if(account is None and needs_auth):
 			# Show Auth Error in headless mode
 			if(headless):
 				return error_view('Auth Error', 'You are not logged in.', nav, headless=True)

			redirect_uri = web_uri + base_path + '/callback'
			oauth = turbo_session.OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
			authorization_url, state = oauth.authorization_url(authorize_url)

			status = '307 Temporary Redirect'
			response_body = ''
			response_headers = [('Location', str(authorization_url))]

		# Display View
		else:
			user = turbo_user.User.create(account, db)
			response_body, response_headers, status = func(post_vars, csrf_clerk, db, session, user)

		return response_body, response_headers, status
	return create_view(basic_view, nav, headless);

# Sub Site Views
def error_view(title, detail, nav='error', logged_in=False, status='200 OK', headless=False):
	page_data = basic_page_data(nav)
	page_data['error_title'] = title
	page_data['error_detail'] = detail
	page_data['nav'] = turbo_nav.generate_html(nav, logged_in)
	
	if(headless):
		response_body = templates.render('error_headless', page_data)
	else:
		response_body = templates.render('error', page_data)

	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status

def __main_view(env, csrf_clerk, db):
	page_data = basic_page_data('main')
	response_body = 'Template Render Error.'
	response_headers = basic_response_header(response_body)
	status = '200 OK'

	session = turbo_session.get_session(env)
	account = turbo_session.retrieve_oauth_account(session, db)
	post_vars = retrieve_post_vars(env)

	# Couldn't auth based on session. Start fresh OAuth 2.0 handshake
	if(account is None):
		if(session is not None):
			redirect_uri = web_uri + base_path + '/callback'
			oauth = turbo_session.OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
			authorization_url, state = oauth.authorization_url(authorize_url)

			status = '307 Temporary Redirect'
			response_body = ''
			response_headers = [('Location', str(authorization_url))]

		# Not yet authenticated and no old session
		else:
			page_data['nav'] = turbo_nav.generate_html('main')
			page_data['login_uri'] = turbo_views['login'].uri
			response_body = templates.render('main', page_data)
			response_headers = basic_response_header(response_body)

	# Display Account Information
	else:
		status = '307 Temporary Redirect'
		response_body = ''
		response_headers = [('Location', web_uri + turbo_views['account'].uri)]
	return response_body, response_headers, status
main_view = create_view(__main_view, 'main')

def __login_view(env, csrf_clerk, db):
	page_data = basic_page_data('login')
	response_body = 'Template Render Error.'
	response_headers = basic_response_header(response_body)
	status = '200 OK'

	session = turbo_session.get_session(env)
	account = turbo_session.retrieve_oauth_account(session, db)
	get_vars = retrieve_get_vars(env)
	post_vars = retrieve_post_vars(env)

	# Failed to set cookie, tell user to enable cookies to use this site
	cookie_set = int(get_vars.get('cookie_set', [0])[0])
	if(account is None and cookie_set == 1):
		return error_view('Login Error',
		                  'Failed to create session. Try to enable cookies for this site.')

	# Couldn't auth based on session. Start fresh OAuth 2.0 handshake
	elif(account is None):
		redirect_uri = web_uri + base_path + '/callback'
		oauth = turbo_session.OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
		authorization_url, state = oauth.authorization_url(authorize_url)

		status = '307 Temporary Redirect'
		response_body = ''
		response_headers = [('Location', str(authorization_url))]

	# Display Account Information
	else:
		status = '307 Temporary Redirect'
		response_body = ''
		response_headers = [('Location', web_uri + turbo_views['account'].uri)]

	return response_body, response_headers, status
login_view = create_view(__login_view)

def __logout_view(env, csrf_clerk, db):
	page_data = basic_page_data('login')
	response_body = 'Template Render Error.'
	response_headers = basic_response_header(response_body)
	status = '200 OK'

	session = turbo_session.get_session(env)
	turbo_session.delete_session(session, db)
	status = '307 Temporary Redirect'
	response_body = ''
	response_headers = [
		('Set-Cookie', "TB_SESSION=guest; Domain=%s; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; Secure; HttpOnly" % (cookie_scope,)),
		('Location', web_uri + base_path + '/')
	]

	return response_body, response_headers, status
logout_view = create_view(__logout_view, 'logout')

def __oauth_callback_view(env, csrf_clerk, db):
	redirect_uri = web_uri + base_path + '/callback'
	authorization_response = redirect_uri + '?' + env['QUERY_STRING']
	oauth = turbo_session.OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
	try:
		token = oauth.fetch_token(token_url, authorization_response=authorization_response, client_secret=client_secret)
		session_token = turbo_session.create_session(token, db)

		if(session_token is not None):
			status = '307 Temporary Redirect'
			response_body = ''
			response_headers = [
				('Set-Cookie', "TB_SESSION=%s; Domain=%s; Max-Age=%s; Path=/; Secure; HttpOnly" % (session_token, cookie_scope, session_max_age)),
				('Location', web_uri + turbo_views['login'].uri + '?cookie_set=1')
			]
		else:
			return error_view('Internal Error',
			                  'Failed to create session.')

	except OAuth2Error as error:
		# Might indicate a "deny" on granting access to the app
		print_exception('OAuth 2.0 Error occured: ', error)
		return error_view('OAuth Error',
		                  'Failed to authorize account, try again.')
	else:
		# Normal function return without errors
		return response_body, response_headers, status
oauth_callback_view = create_view(__oauth_callback_view)

def __account_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('account')
	# Reset app_password if requested
	if(int(post_vars.get('reset_app_password', [0])[0]) == 1):
		csrf_token = post_vars.get('csrf_token', [''])[0]
		if(csrf_clerk.validate(session, csrf_token)):
			# silently failing on an invalid token is fine here
			user.reset_app_password()
	status = '200 OK'
	page_data['nav'] = turbo_nav.generate_html('account', user is not None)
	page_data['form_action'] = turbo_views['account'].uri
	page_data['username'] = user.username
	page_data['avatar_src'] = user.account.get('avatar', '')
	page_data['app_password'] = user.app_password_plain
	page_data['csrf_token'] = csrf_clerk.register(session)
	response_body = templates.render('account', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
account_view = create_basic_view(__account_view, 'account')

def __headless_chat_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('chat-headless')
	page_data['rules_uri'] = turbo_views['rules'].uri
	page_data['rand_spinner'] = str(random.randint(1,5))
	page_data['username'] = user.username if user is not None else ''
	page_data['password'] = user.app_password_plain if user is not None else ''
	status = '200 OK'
	response_body = templates.render('chat_headless', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
headless_chat_view = create_basic_view(__headless_chat_view, 'chat-headless', headless=True)

def __chat_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('chat')
	page_data['nav'] = turbo_nav.generate_html('chat', user is not None)
	page_data['chat_uri'] = turbo_views['chat-headless'].uri
	status = '200 OK'
	response_body = templates.render('chat', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
chat_view = create_basic_view(__chat_view, 'chat')

def __headless_stream_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('stream-headless')
	page_data['chat_uri'] = turbo_views['chat-headless'].uri
	status = '200 OK'
	response_body = templates.render('stream_headless', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
headless_stream_view = create_basic_view(__headless_stream_view, 'stream-headless', headless=True)

def __stream_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('stream')
	page_data['nav'] = turbo_nav.generate_html('stream', user is not None)
	page_data['stream_uri'] = turbo_views['stream-headless'].uri
	status = '200 OK'
	response_body = templates.render('stream', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
stream_view = create_basic_view(__stream_view, 'stream')

def __headless_theatre_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('stream-headless')
	page_data['chat_uri'] = turbo_views['chat-headless'].uri
	status = '200 OK'
	response_body = templates.render('theatre_headless', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
headless_theatre_view = create_basic_view(__headless_theatre_view, 'theatre-headless', headless=True)

def __theatre_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('theatre')
	page_data['nav'] = turbo_nav.generate_html('theatre', user is not None)
	page_data['theatre_uri'] = turbo_views['theatre-headless'].uri
	status = '200 OK'
	given_password = post_vars.get('theatre_password', [''])[0]
	if(user is not None or given_password == theatre_password):
		response_body = templates.render('theatre', page_data)
	else:
		page_data['form_action'] = turbo_views['theatre'].uri
		response_body = templates.render('theatre_auth', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
theatre_view = create_basic_view(__theatre_view, 'theatre', False)

def __rules_view(post_vars, csrf_clerk, db, session, user):
	page_data = basic_page_data('rules')
	page_data['nav'] = turbo_nav.generate_html('rules', user is not None)
	status = '200 OK'
	response_body = templates.render('rules', page_data)
	response_headers = basic_response_header(response_body)
	return response_body, response_headers, status
rules_view = create_basic_view(__rules_view, 'rules', False)

# List of views
turbo_views['main'] = turbo_view('Home', '/', main_view)
turbo_views['account'] = turbo_view('Account Overview', '/account', account_view)
turbo_views['login'] = turbo_view('Login', '/login', login_view)
turbo_views['logout'] = turbo_view('Logout', '/logout', logout_view)
turbo_views['oauth_callback'] = turbo_view('OAuth Callback', '/callback', oauth_callback_view)
turbo_views['chat-headless'] = turbo_view('Turbo Chat', '/chat-headless', headless_chat_view)
turbo_views['chat'] = turbo_view('Turbo Chat', '/chat', chat_view)
turbo_views['stream'] = turbo_view('Turbo Stream', '/stream', stream_view)
turbo_views['stream-headless'] = turbo_view('Turbo Stream', '/stream-headless', headless_stream_view)
turbo_views['theatre'] = turbo_view('Movie Night', '/theatre', theatre_view)
turbo_views['theatre-headless'] = turbo_view('Movie Night', '/theatre-headless', headless_theatre_view)
turbo_views['rules'] = turbo_view('Rules', '/rules', rules_view)

# List of nav items
def set_nav_item(name, hidden_when_logged_out=False, hidden_when_logged_in=False):
	turbo_nav.items[name] = turbo_nav.nav_item(turbo_views[name], hidden_when_logged_out, hidden_when_logged_in)

set_nav_item('login', False, True)
set_nav_item('account', True)
set_nav_item('chat', True)
set_nav_item('stream', True)
set_nav_item('theatre')
set_nav_item('rules')
set_nav_item('logout', True)
