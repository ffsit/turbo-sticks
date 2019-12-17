import sys
import traceback
import json
import http
from Crypto.Cipher import AES
from html import escape
from urllib.parse import parse_qs, quote_plus, urlencode
from os import urandom, listdir, path
from fnmatch import fnmatch

from turbo_config import page_title, base_path, debug_mode, app_secret

# General Helpers
def print_info(info, debug_message=True):
	if(not debug_message or debug_mode):
		print('========================================')
		print(info)
		print('========================================')

def print_exception(title, exception, debug_message=True):
	if(not debug_message or debug_mode):
		exc_type, exc_value, exc_traceback = sys.exc_info()
		print('========================================')
		print(title)
		print(exception)
		traceback.print_tb(exc_traceback)
		print('========================================')

def sub_title(sub_title, title=page_title):
	return sub_title + ' - ' + title

# Crypto Helpers
def generate_random_token(length):
	return urandom(length//2).hex()

def encrypt(plaintext):
	iv = urandom(16)
	key = app_secret.encode('utf-8')[:16]
	cipher = AES.new(key, AES.MODE_CFB, iv)
	return cipher.encrypt(plaintext.encode('utf-8')).hex() + iv.hex()

def decrypt(ciphertext):
	iv = bytes.fromhex(ciphertext[-32:])
	key = app_secret.encode('utf-8')[:16]
	cipher = AES.new(key, AES.MODE_CFB, iv)
	return cipher.decrypt(bytes.fromhex(ciphertext[:-32])).decode('utf-8')

# Web Server Helpers
def retrieve_get_vars(env):
	return parse_qs(env['QUERY_STRING'], encoding='utf-8')

def retrieve_request_body(env):
	try:
		request_body_size = int(env.get('CONTENT_LENGTH',0))
	except (ValueError):
		request_body_size = 0;
	return env['wsgi.input'].read(request_body_size)

def retrieve_post_vars(env):
	request_body = retrieve_request_body(env)
	return parse_qs(request_body.decode('utf-8'))

def retrieve_cookies(env):
	cookies = http.cookies.SimpleCookie()
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

def generate_json_response(data, status='200 OK'):
	response_body = json.dumps(data).encode('utf-8')
	response_headers = [
		('Content-Type', 'application/json'),
		('Content-Length', str(len(response_body)))
	];
	return response_body, response_headers, status;

def get_default_embed(sources):
	if(len(sources) > 0 and sources[0]['embed_type'] == 'html'):
		return sources[0]['embed']
	return '' 

def generate_video_sources(sources):
	if(len(sources) > 0):
		return json.dumps(sources)
	return '[]'

# File Helpers

def files(source_path, pattern='*'):
	for entry in listdir(source_path):
		if fnmatch(entry, pattern):
			file_path = path.join(source_path, entry)
			if path.isfile(file_path):
				yield file_path

css_version = 0
def get_css_version():
	global css_version
	pattern = '*.css'
	if css_version == 0:
		for file_path in files('./static', pattern):
			css_version = max(css_version, int(path.getmtime(file_path)))
	return css_version

js_version = 0
def get_js_version():
	global js_version
	pattern = '*.js'
	if js_version == 0:
		for file_path in files('./static', pattern):
			js_version = max(js_version, int(path.getmtime(file_path)))
	return js_version

