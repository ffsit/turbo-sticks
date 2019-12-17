import atexit

# Local Imports
import turbo_db
import turbo_csrf
from turbo_config import base_path, api_path
from turbo_util import generate_json_response
from turbo_views import turbo_views, error_view
from turbo_ajax import api_calls

# CSRF Protection
csrf_clerk = turbo_csrf.TokenClerk()

# Web Server Main
def application(env, start_response):
	path = env['PATH_INFO']
	response_body, response_headers, status = error_view(
		'404 Not Found',
		'The requested page or resource doesn\'t exist',
		status='404 Not Found')

	turbo_db.init_db()

	if(turbo_db.db is None):
		response_body, response_headers, status = error_view(
			'Database Error',
			'Database connection failed.',
			status='500 Internal Server Error')

	elif(path.startswith(api_path)):
		response_body, response_headers, status = generate_json_response({'error': 'Unknown API call.'})
		for name, api_call in api_calls.items():
			if(path == api_path + '/' + name):
				response_body, response_headers, status = api_call(env, csrf_clerk, turbo_db.db)
				break

	elif(path.startswith(base_path)):
		for name, item in turbo_views.items():
			if(path == item.uri):
				if(item.view is not None):
					response_body, response_headers, status = item.view(env, csrf_clerk, turbo_db.db)
				break

	start_response(status, response_headers)
	return [response_body]

# Cleanup on shutdown
def shutdown():
	if(turbo_db.db is not None):
		turbo_db.db.close()
atexit.register(shutdown)
