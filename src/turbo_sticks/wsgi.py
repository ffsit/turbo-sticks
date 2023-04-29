from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, TYPE_CHECKING

import turbo_sticks.config as config
from turbo_sticks.db import DBSession
from turbo_sticks.util import generate_json_response
from turbo_sticks.ajax import api_calls
from turbo_sticks.views import views, error_view
from turbo_sticks.websockets import channels

if TYPE_CHECKING:
    from turbo_sticks.csrf import TokenClerk
    from turbo_sticks.types import HTTPHeader


logger = logging.getLogger('sticks')


class WSGIApplication:
    def __init__(self, csrf_clerk: TokenClerk, websockets: bool = True):
        self.csrf_clerk = csrf_clerk
        self.websockets = websockets

    def __call__(
        self,
        env: dict[str, Any],
        start_response: Callable[[str, list[HTTPHeader]], None]
    ) -> list[bytes]:

        path = env['PATH_INFO']
        response_body, response_headers, status = error_view(
            '404 Not Found',
            'The requested page or resource doesn\'t exist',
            status='404 Not Found')

        # TODO: If the number of individual paths ever increases we probably
        #       want to switch to dictionary lookups from O(n) lookup loops
        api_path = config.api_path
        if path.startswith(api_path):
            response_body, response_headers, status = generate_json_response(
                {'error': 'Unknown API call.'},
                '404 Not Found'
            )
            for name, api_call in api_calls.items():
                if path == f'{api_path}/{name}':
                    response_body, response_headers, status = api_call(
                        env, self.csrf_clerk
                    )
                    break

        elif self.websockets and path.startswith(config.websockets.path):
            for channel in channels:
                if path == channel.path:
                    channel.open_websocket(env)
                    return []

        elif path.startswith(config.base_path):
            for item in views.values():
                if path == item.path:
                    if item.view is not None:
                        response_body, response_headers, status = item.view(
                            env, self.csrf_clerk
                        )
                    break

        start_response(status, response_headers)
        return [response_body]

    # Cleanup on shutdown
    def shutdown(self) -> None:
        logger.info('Closing active websockets for shutdown.')
        for channel in channels:
            channel.close()

        logger.info('Closing active DB connection pool.')
        db = DBSession()
        db.close()

        logger.info('Finished shutdown.')
