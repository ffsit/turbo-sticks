# Monkey Patching
from gevent import monkey; monkey.patch_all()  # noqa: E702

import logging
import uwsgi

from turbo_sticks.csrf import TokenClerk
from turbo_sticks.db import DBSession
from turbo_sticks.websockets import init_redis_state
from turbo_sticks.wsgi import WSGIApplication


logger = logging.getLogger('sticks')
logger.info('Initialized logger.')

# DB Pool
logger.info('Initializing DB pool.')
db = DBSession()
db.start_checks()

# CSRF Protection
logger.info('Initializing CSRF Clerk.')
csrf_clerk = TokenClerk()

# Initialize state stored in Redis
logger.info('Initializing Redis state.')
init_redis_state()

# uWSGI entry point
application = WSGIApplication(csrf_clerk)

# uWSGI exit hook
uwsgi.atexit = application.shutdown
