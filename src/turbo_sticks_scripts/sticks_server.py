from __future__ import annotations

# Monkey Patching
# In order for this to work we put the scripts into a separate package so
# turbo_sticks does not get loaded before monkey patching can occur
from gevent import monkey; monkey.patch_all()  # noqa: E702

import argparse
import logging
import os
from gevent.pywsgi import WSGIServer
from typing import TYPE_CHECKING

import turbo_sticks.config as config
from turbo_sticks.csrf import TokenClerk
from turbo_sticks.db import DBSession
from turbo_sticks.websockets import init_redis_state
from turbo_sticks.wsgi import WSGIApplication

if TYPE_CHECKING:
    from _typeshed.wsgi import StartResponse, WSGIEnvironment
    from collections.abc import Iterable
    from turbo_sticks.types import HTTPHeader

# the kinds of static files we will serve
mime_types = {
    'css': 'text/css',
    'gif': 'image/gif',
    'ico': 'image/x-icon',
    'jpg': 'image/jpeg',
    'js': 'text/javascript',
    'png': 'image/png',
    'woff': 'font/woff',
    'woff2': 'font/woff2',
    'xml': 'text/xml',
}
cached_files: dict[str, tuple[list[HTTPHeader], bytes]] = {}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='sticks-server',
        description='Run TURBO sticks server [development]',
    )
    parser.add_argument(
        'listener',
        default='0.0.0.0:8080',
        nargs='?',
    )
    args = parser.parse_args()

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

    wsgi_logger = logging.getLogger('gevent.pywsgi')
    # NOTE: We don't support websockets yet without uwsgi
    application = WSGIApplication(csrf_clerk, websockets=False)

    # NOTE: We'll serve files ourselves, which is inefficient, but since
    #       this is mostly used for testing without uwsgi we don't care
    def application_which_serves_static_files(
        env: WSGIEnvironment,
        start_response: StartResponse
    ) -> Iterable[bytes]:

        path = env['PATH_INFO']
        if (cached := cached_files.get(path)) is not None:
            headers, content = cached
            start_response('200 OK', headers)
            return [content]

        _, _, ext = path.rpartition('.')
        prefix = config.base_path + '/static'
        if path.startswith(prefix) and (mime_type := mime_types.get(ext)):
            rel_path_parts = path[len(prefix):].split('/')
            static_path = os.path.join(config.static_dir, *rel_path_parts)
            if os.path.isfile(static_path):
                with open(static_path, 'rb') as fp:
                    content = fp.read()

                headers = [
                    ('Content-Type', mime_type),
                    ('Content-Length', str(len(content)))
                ]
                cached_files[path] = (headers, content)
                start_response('200 OK', headers)
                return [content]

        return application(env, start_response)

    server = WSGIServer(
        args.listener,
        application=application_which_serves_static_files,
        log=wsgi_logger,
        error_log=wsgi_logger,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    # cleanup
    application.shutdown()


if __name__ == '__main__':
    main()
