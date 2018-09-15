import sys
import traceback
import json
from cgi import parse_qs, escape
from Cookie import SimpleCookie
from turbo_config import page_title, base_path, debug_mode

# General Helpers
def print_exception(title, exception):
	if(debug_mode):
		exc_type, exc_value, exc_traceback = sys.exc_info()
		print '========================================'
		print title
		print exception
		traceback.print_tb(exc_traceback)
		print '========================================'

def sub_title(sub_title, title=page_title):
	return sub_title + ' - ' + title

# Web Server Helpers
def retrieve_get_vars(env):
	return parse_qs(env['QUERY_STRING'])

def retrieve_post_vars(env):
	try:
		request_body_size = int(env.get('CONTENT_LENGTH',0))
	except (ValueError):
		request_body_size = 0;
	request_body = env['wsgi.input'].read(request_body_size)
	return parse_qs(request_body)

def retrieve_cookies(env):
	cookies = SimpleCookie()
	cookies.load(env.get('HTTP_COOKIE',''))
	return cookies

def basic_response_header(response_body, send_length=True):
	if(send_length):
		return [
			('Content-Type', 'text/html'),
			('Content-Length', str(len(response_body)))
		]
	else:
		return [('Content-Type', 'text/html')]

def generate_json_response(data):
	response_body = json.dumps(data)
	response_headers = [
		('Content-Type', 'application/json'),
		('Content-Length', str(len(response_body)))
	];
	return response_body, response_headers, '200 OK';

def get_default_embed(sources):
	if(len(sources) > 0 and sources[0]['embed_type'] == 'html'):
		return sources[0]['embed']
	return '' 

def generate_video_sources(sources):
	if(len(sources) > 0):
		sources[0]['selected'] = True
		return json.dumps(sources)
	return '[]'
