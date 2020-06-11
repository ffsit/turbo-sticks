# Monkey Patching
from gevent import monkey
monkey.patch_all()  # NOQA

import logging
import uwsgi

# Local Imports
import turbo_csrf
from turbo_db import DBSession
from turbo_config import base_path, api_path, websockets_path, debug_mode
from turbo_util import generate_json_response
from turbo_ajax import api_calls
from turbo_views import turbo_views, error_view
from turbo_websockets import channels, init_redis_state

# Setup logging
logging.basicConfig(
    format='[%(asctime)s] %(levelname)-8s - %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    style='%',
    level=logging.DEBUG if debug_mode else logging.INFO,
)
logger = logging.getLogger('sticks')
logger.info('Initialized logger.')

# CSRF Protection
logger.info('Initializing CSRF Clerk.')
csrf_clerk = turbo_csrf.TokenClerk()

# Initialize state stored in Redis
logger.info('Initializing Redis state.')
init_redis_state()


# Web Server Main
def application(env, start_response):
    path = env['PATH_INFO']
    response_body, response_headers, status = error_view(
        '404 Not Found',
        'The requested page or resource doesn\'t exist',
        status='404 Not Found')

    db = DBSession()

    if(db.connection is None):
        response_body, response_headers, status = error_view(
            'Database Error',
            'Database connection failed.',
            status='500 Internal Server Error')

    elif(path.startswith(api_path)):
        response_body, response_headers, status = generate_json_response(
            {'error': 'Unknown API call.'})
        for name, api_call in api_calls.items():
            if(path == api_path + '/' + name):
                response_body, response_headers, status = api_call(
                    env, csrf_clerk)
                break

    elif(path.startswith(websockets_path)):
        for channel in channels:
            if(path == channel.path):
                channel.open_websocket(env)
                return []

    elif(path.startswith(base_path)):
        for name, item in turbo_views.items():
            if(path == item.path):
                if(item.view is not None):
                    response_body, response_headers, status = item.view(
                        env, csrf_clerk)
                break

    start_response(status, response_headers)
    return [response_body]


# Cleanup on shutdown
def shutdown():
    logger.info('Closing active websockets for shutdown.')
    for channel in channels:
        channel.close()

    logger.info('Closing active DB connection.')
    db = DBSession()
    if db and db.is_alive():
        db.close()

    logger.info('Finished shutdown.')


uwsgi.atexit = shutdown
