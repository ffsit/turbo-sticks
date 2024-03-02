from __future__ import annotations

import functools
import gevent
import gevent.event
import gevent.lock
import gevent.queue
import gevent.select
import json
import logging
import time
import uuid
from collections.abc import Callable
from enum import Enum
from oauthlib.oauth2 import OAuth2Error
from redis import Redis
from typing import cast, overload, Any, ClassVar, TypeVar, TYPE_CHECKING

import turbo_sticks.config as config
import turbo_sticks.util as util
from turbo_sticks.db import DBError, PoolTimeout
from turbo_sticks.enums import ACL
from turbo_sticks.session import get_session, retrieve_oauth_account
from turbo_sticks.user import User

try:
    import uwsgi
except ModuleNotFoundError:
    # NOTE: For pure gevent without uwsgi we could use gevent-websockets
    #       but it's probably not worth the effort. Maybe for testing?
    #       we'll see. For now we'll just avoid import errors
    uwsgi = NotImplemented


if TYPE_CHECKING:
    from collections.abc import Sequence
    from greenlet import greenlet as greenlet_t
    from redis.client import PubSub
    from typing import Literal
    from .types import (
        Decorator, FormattedMember, FormattedMessage, OnlineMembers, Rank
    )

    _T = TypeVar('_T')
    _F = TypeVar('_F', bound=Callable[..., Any])
    CallbackOrMethodName = str | Callable[[], None]
    EventDestination = Literal['bot', 'channel', 'client']


_C = TypeVar('_C', bound='Client')
logger = logging.getLogger('sticks.wss')
channels = []


def init_redis_state(redis: Redis[bytes] | None = None) -> None:
    if redis is None:  # pragma: no cover
        redis = Redis.from_url(config.redis_uri)
    redis.set('websocket-clients', 0)
    redis.delete('webchat-clients')
    redis.delete('webchat-online-members')
    redis.close()


# Exceptions
class ClientError(Exception):
    pass


class ClientDisconnect(ClientError):
    pass


class ClientTimeout(ClientError):
    pass


def _resolve_callable(obj: _T, func: CallbackOrMethodName | None) -> None:
    if callable(func):
        func()
    elif isinstance(func, str) and hasattr(obj, func):
        getattr(obj, func)()


# Client job decorator
@overload
def client_job(
    func:      None = None,
    *,
    on_error:  CallbackOrMethodName | None = None,
    on_finish: CallbackOrMethodName | None = None
) -> Decorator: ...
@overload  # noqa: E302
def client_job(
    func:      _F,
    *,
    on_error:  CallbackOrMethodName | None = None,
    on_finish: CallbackOrMethodName | None = None
) -> _F: ...
def client_job(  # noqa: E302
    func:      _F | None = None,
    *,
    on_error:  CallbackOrMethodName | None = None,
    on_finish: CallbackOrMethodName | None = None
) -> Decorator | _F:

    def decorator(func: _F) -> _F:
        @functools.wraps(func)
        def wrapper(self: Client, *args: Any, **kwargs: Any) -> Any:
            logger.debug(
                f'<Client {self.id}> Started greenlet {func.__name__}.'
            )
            graceful_exit = False
            try:
                func(self, *args, **kwargs)
                graceful_exit = True
            except ClientTimeout:
                self.state = ClientState.suspended
                logger.info(f'<Client {self.id}> Client timeout.')
            except ClientDisconnect:
                self.state = ClientState.exited
                logger.info(f'<Client {self.id}> Client disconnected.')
                graceful_exit = True
            except ClientError as error:
                self.state = ClientState.exited
                logger.warning(f'<Client {self.id}> Client error: {error}')
            except (DBError, PoolTimeout):
                # Database Error
                self.state = ClientState.exited
                logger.exception('Database error occured.')
            except OAuth2Error as error:
                # OAuth 2.0 Error
                self.state = ClientState.exited
                logger.info(f'OAuth 2.0 error occured: {error}',
                            exc_info=config.debug_mode)
            except Exception as error:
                # Unknown Exception
                self.state = ClientState.exited
                logger.exception(
                    f'<Client {self.id}> Unexpected error occured: {error}')
            finally:
                if not graceful_exit:
                    _resolve_callable(self, on_error)
                _resolve_callable(self, on_finish)
                logger.debug(
                    f'<Client {self.id}> Finished greenlet {func.__name__}.'
                )
        return cast('_F', wrapper)
    return decorator(func) if func is not None else decorator


# Channel job decorator
@overload
def channel_job(
    func:      None = None,
    *,
    on_error:  CallbackOrMethodName | None = None,
    on_finish: CallbackOrMethodName | None = None
) -> Decorator: ...
@overload  # noqa: E302
def channel_job(
    func:      _F,
    *,
    on_error:  CallbackOrMethodName | None = None,
    on_finish: CallbackOrMethodName | None = None
) -> _F: ...
def channel_job(  # noqa: E302
    func:      _F | None = None,
    *,
    on_error:  CallbackOrMethodName | None = None,
    on_finish: CallbackOrMethodName | None = None
) -> Decorator | _F:

    def decorator(func: _F) -> _F:
        @functools.wraps(func)
        def wrapper(self: Channel, *args: Any, **kwargs: Any) -> Any:
            logger.debug(
                f'<Channel {self.name}> Started greenlet {func.__name__}.'
            )
            graceful_exit = False
            try:
                func(self, *args, **kwargs)
                graceful_exit = True
            except (DBError, PoolTimeout):
                # Database Error
                logger.exception('Database error occured.')
            except OAuth2Error as error:
                # OAuth 2.0 Error
                logger.info(f'OAuth 2.0 error occured: {error}',
                            exc_info=config.debug_mode)
            except Exception as error:
                # Unknown Exception
                logger.exception(
                    f'<Channel {self.name}> Unexpected error occured: {error}')
            finally:
                if not graceful_exit:
                    _resolve_callable(self, on_error)
                _resolve_callable(self, on_finish)
                logger.debug(
                    f'<Channel {self.name}> Finished greenlet {func.__name__}.'
                )
        return cast('_F', wrapper)
    return decorator(func) if func is not None else decorator


class JobState(Enum):
    new = 0
    started = 1
    suspended = 2
    exited = 3


class ClientState(Enum):
    new = 0
    started = 1
    suspended = 2
    resumed = 3
    exited = 4
    merged = 5


ACL_rank_map: dict[ACL, Rank] = {
    ACL.guest: 'shadow',
    ACL.patron: 'patron',
    ACL.turbo: 'turbo',
    ACL.helper: 'helper',
    ACL.moderator: 'mod',
    ACL.crew: 'crew',
    ACL.admin: 'mod',
}


# Generic passthrough websocket client
class Client:

    id:                str
    greenlet:          greenlet_t | None
    channel:           Channel
    env:               dict[str, Any]
    fd_select_job:     gevent.greenlet.Greenlet[[], None] | None
    jobs:              list[gevent.greenlet.Greenlet[..., Any]]
    job_state:         JobState
    event:             gevent.event.Event
    merge_event:       gevent.event.Event
    client_send_queue: gevent.queue.Queue[bytes]
    client_recv_queue: gevent.queue.Queue[bytes]
    context:           dict[str, Any]
    state:             ClientState

    def __init__(self, channel: Channel, env: dict[str, Any]):
        self.id = str(uuid.uuid4())
        self.greenlet = None
        self.channel = channel
        self.env = env
        self.fd_select_job = None
        self.jobs = []
        self.job_state = JobState.new
        self.event = gevent.event.Event()
        self.merge_event = gevent.event.Event()
        self.client_send_queue = gevent.queue.Queue()
        self.client_recv_queue = gevent.queue.Queue()
        self.state = ClientState.new
        self.context = {}

    @property
    def redis(self) -> Redis[bytes]:
        return self.channel.redis

    def authenticate(self, env: dict[str, Any]) -> User | None:
        session = get_session(env)
        account = retrieve_oauth_account(session)
        if account:
            return User.create(account)
        return None

    def init_context(self) -> None:
        user = self.authenticate(self.env)
        access_level = User.get_access_level(user)

        self.context = {
            'user': user,
            'access_level': access_level,
        }

    def client_publish(self, message: bytes) -> None:
        self.client_send_queue.put_nowait(message)
        self.event.set()

    def channel_publish(self, message: bytes) -> None:
        self.redis.publish(self.channel.name, message)

    def handle_client_message(self, message: bytes) -> None:
        self.channel_publish(message)

    @client_job
    def _handle_client_messages(self) -> None:
        while self.job_state != JobState.exited:
            if self.job_state == JobState.suspended:
                gevent.sleep(0.2)
                continue
            try:
                message = self.client_recv_queue.get(timeout=0.2)
                self.handle_client_message(message)
            except gevent.queue.Empty:
                pass
            # NOTE: Sleeping 0 is a special case in gevent that may starve
            #       other greenlets. So we instead want to wait a very short
            #       period of time so other jobs still get a chance to execute
            #       when we get flooded with messages. @ZeroSleep
            gevent.sleep(0.001)

    def _fd_select(self) -> None:
        while self.state == ClientState.started:
            self.event.set()
            # for some reason any other method of checking fails
            try:
                gevent.select.select([self.websocket_fd], [], [])[0]
            except (ValueError, OSError):
                break

    def spawn_jobs(self) -> None:
        self.job_state = JobState.started
        self.jobs.extend([
            gevent.spawn(self._handle_client_messages),
        ])

    def kill_jobs(self, timeout: float | None = None) -> None:
        self.job_state = JobState.exited
        if self.jobs:
            gevent.joinall(self.jobs, timeout=timeout)
        self.jobs = []

    @client_job(on_finish='cleanup')
    def start(self) -> None:
        self.greenlet = gevent.getcurrent()

        uwsgi.websocket_handshake()
        self.websocket_fd = uwsgi.connection_fd()
        logger.info(f'<Client {self.id}> Opening websocket connection')

        client_count = int((
            self.redis.get('websocket-clients') or b'0'
        ).decode('utf-8'))
        if client_count >= config.websockets.max_clients:
            raise ClientError('No available slots.')

        self.init_context()
        if self.context['access_level'] < self.channel.min_access_level:
            raise ClientError('Insufficient privileges.')

        self.redis.incr('websocket-clients')
        self.state = ClientState.started

        self.fd_select_job = gevent.spawn(self._fd_select)
        self.spawn_jobs()
        self.main_loop()

    def resume(self: _C, client: _C) -> None:
        self.job_state = JobState.suspended
        gevent.sleep(0.2)
        self.channel.remove_client(self)
        self.id = client.id
        self.client_send_queue = client.client_send_queue
        self.client_recv_queue = client.client_recv_queue
        self.context = client.context
        client.state = ClientState.merged
        client.merge_event.set()
        client.join(timeout=0.2)
        self.job_state = JobState.started
        logger.info(f'<Client {self.id}> Websocket session resumed.')
        self.channel.clients[self.id] = self

    def main_loop(self) -> None:
        while self.state == ClientState.started:
            self.event.wait(3.0)
            try:
                message = uwsgi.websocket_recv_nb()
            except IOError:
                if self.state == ClientState.started:
                    self.state = ClientState.suspended
                break
            if message:
                self.client_recv_queue.put_nowait(message)

            # push client messages to client
            try:
                message = self.client_send_queue.get(block=False)
                uwsgi.websocket_send(message)
            except gevent.queue.Empty:
                # no more messages, so we can clear the event
                self.event.clear()

    def exit(
        self,
        block: bool = True,
        timeout: float | None = None
    ) -> None:

        self.state = ClientState.exited
        self.job_state = JobState.exited
        if block:
            greenlets: 'Sequence[greenlet_t]'
            if self.greenlet is None:
                greenlets = self.jobs
            else:
                greenlets = [self.greenlet]
                greenlets.extend(self.jobs)
            gevent.joinall(greenlets, timeout=timeout)

    def join(self, timeout: float | None = None) -> None:
        if self.greenlet is not None:
            # this could be a basic greenlet, which doesn't have a join method
            gevent.joinall((self.greenlet, ), timeout=timeout)

    def on_kill(self) -> None:
        self.kill_jobs(timeout=0.2)
        if self.context:
            self.redis.decr('websocket-clients')
        self.channel.remove_client(self)

    def cleanup(self) -> None:
        if self.fd_select_job:
            self.fd_select_job.kill()

        logger.info(f'<Client {self.id}> Websocket connection lost.')
        uwsgi.disconnect()
        if self.state == ClientState.suspended:
            # wait an amount of time to be picked up for resume
            self.merge_event.wait(60.0)

        if self.state == ClientState.merged:
            logger.info(
                f'<Client {self.id}> Merging websocket session to resume.')
        else:
            logger.info(f'<Client {self.id}> Websocket session killed.')

        self.on_kill()


# Generic Redis websocket channel
class Channel:
    client_cls:  ClassVar[type[Client]] = Client
    clients:     dict[str, Client]
    client_lock: gevent.lock.RLock

    _redis:           Redis[bytes] | None = None
    _redis_channel:   PubSub | None
    redis_lock:       gevent.lock.RLock
    name:             str
    path:             str
    uri:              str
    min_access_level: ACL
    # we annotate greenlet_t for simplicity, since list isn't covariant
    jobs:             list[greenlet_t]
    job_state:        JobState

    def __init__(
        self,
        name: str,
        path: str,
        min_access_level: ACL = ACL.turbo
    ):
        self.clients = {}
        self.client_lock = gevent.lock.RLock()
        self.name = name
        self.path = config.websockets.path + path
        self.uri = util.build_url(path, base='websockets')
        self.min_access_level = min_access_level
        self.jobs = []
        self.job_state = JobState.new
        self._redis_channel = None
        self.redis_lock = gevent.lock.RLock()
        channels.append(self)

    def add_client(self, env: dict[str, Any]) -> Client:
        with self.client_lock:
            client = self.client_cls(self, env)
            self.clients[client.id] = client
            return client

    def get_client(self, client_id: str) -> Client | None:
        return self.clients.get(client_id)

    def remove_client(self, client: Client) -> None:
        with self.client_lock:
            if client.id in self.clients.keys():
                del self.clients[client.id]

    @property
    def redis(self) -> Redis[bytes]:
        with self.redis_lock:
            if self._redis is not None:
                try:
                    self._redis.ping()
                except ConnectionError:
                    logger.warning('Lost connection to Redis.')
                    del self._redis
            if self._redis is None:
                self._redis = Redis.from_url(config.redis_uri)
                logger.info('Connecting to Redis...')
        return self._redis

    def redis_channel(self) -> PubSub:
        # NOTE: This should only ever be accessed by _handle_channel_messages
        #       so we don't need a lock, until that changes
        if self._redis_channel:
            try:
                self._redis_channel.check_health()
            except RuntimeError:
                logger.warning('Redis subscription died.')
                self._redis_channel = None
        if not self._redis_channel:
            self._redis_channel = self.redis.pubsub()
            self._redis_channel.subscribe(self.name)
            logger.info('Subscribing to Redis channel.')
        return self._redis_channel

    @channel_job(on_error='recover_jobs')
    def _handle_channel_messages(self) -> None:
        while self.job_state != JobState.exited:
            # NOTE: Currently there's no case where this ever happens or is
            #       required
            if self.job_state == JobState.suspended:
                gevent.sleep(0.2)
                continue

            message = self.redis_channel().parse_response(
                block=False,
                timeout=0.2
            )
            if message and message[0] == b'message':
                self.handle_channel_message(message[2])
            # NOTE: @ZeroSleep
            gevent.sleep(0.001)

    def handle_channel_message(self, message: bytes) -> None:
        for client in self.clients.values():
            self.dispatch_client_message(client, message)

    def dispatch_client_message(self, client: Client, message: bytes) -> None:
        if client.state in [ClientState.started, ClientState.suspended]:
            if client.job_state == JobState.suspended:
                # if the client job is suspended dispatch the message delayed
                gevent.spawn_later(0.5, client.client_publish, message)
            else:
                client.client_publish(message)

    def spawn_jobs(self) -> None:
        if self.job_state not in [JobState.started, JobState.suspended]:
            self.job_state = JobState.started
            self.jobs.extend([
                gevent.spawn(self._handle_channel_messages),
            ])

    def kill_jobs(self, timeout: float | None = None) -> None:
        self.job_state = JobState.exited
        if (jobs := self.jobs):
            self.jobs = []
            gevent.joinall(jobs, timeout=timeout)

    def recover_jobs(self) -> None:
        self.kill_jobs(timeout=0.2)
        self.spawn_jobs()

    def open_websocket(self, env: dict[str, Any]) -> None:
        self.spawn_jobs()
        client = self.add_client(env)
        client.start()

    def close(self, timeout: float | None = None) -> None:
        self.job_state = JobState.exited
        with self.client_lock:
            greenlets = []
            for client in self.clients.values():
                client.exit(block=False)
                if client.greenlet is not None:
                    greenlets.append(client.greenlet)

            self.clients = {}

        # this needs to happen outside the lock otherwise we get a deadlock
        gevent.joinall(greenlets + self.jobs, timeout=timeout)
        self.jobs = []


def webchat_user_key(member: dict[str, Any]) -> str:
    if member['discord_id']:
        return member['discord_id']  # type:ignore[no-any-return]
    return member['username']  # type:ignore[no-any-return]


class DiscordClient(Client):

    heartbeat_interval: ClassVar[float] = 4.0
    channel:            DiscordChannel

    def resume(self, client: DiscordClient) -> None:
        super().resume(client)
        self.hello()

    def init_context(self) -> None:
        super().init_context()
        self.context['connected'] = False
        self.context['discord_id'] = None
        self.context['discriminator'] = None
        self.context['local'] = True
        self.context['rank'] = ACL_rank_map.get(
            self.context['access_level'], 'shadow')
        user = self.context.get('user')
        if user:
            if user.banned:
                raise ClientError('You have been banned.')
            self.context['username'] = user.username
            self.context['avatar_url'] = user.account.get('avatar_static', '')
            if user.discord_id:
                self.context['discord_id'] = str(user.discord_id)
        else:
            # authenticate with discord directly
            raise NotImplementedError()
            # discord_member = discord.member_from_guest_session(self.env)
            # discord_user = discord.get_user(discord_member)
            # if not discord_user:
            #     raise ClientError('Guests require Discord account.')
            # username = discord_member.get('nick', '')
            # if not username:
            #     username = discord_user.get('username', '')
            # discriminator = discord_user.get('discriminator', '')
            # avatar_url = discord.get_avatar_url(discord_user)
            # if not username or not discriminator:
            #     raise ClientError('Failed to retrieve username')
            # self.context['username'] = username
            # self.context['discriminator'] = discriminator
            # self.context['discord_id'] = str(discord_member.get('id'))
            # self.context['avatar_url'] = avatar_url

    def bot_publish(self, message: bytes) -> None:
        self.redis.publish('sticks-bot', message)

    def publish_event(
        self,
        event:       str,
        data:        Any = None,  # FIXME: this is a bit lax
        destination: EventDestination = 'client'
    ) -> None:

        assert destination in ['bot', 'channel', 'client']
        payload = {'ev': event, 'd': data or {}}
        message = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        getattr(self, destination + '_publish')(message)

    def hello(self) -> None:
        self.publish_event('hello', {'client_id': self.id})

    def ack(self, info: str | None = None) -> None:
        self.publish_event('ack', {'info': info} if info else {})

    def error(self, message: str, detail: str | None = None) -> None:
        payload = {'message': message}
        if detail:
            payload['detail'] = detail
        self.publish_event('error', payload)

    def handle_client_message(self, message: bytes) -> None:
        try:
            payload = json.loads(message.decode('utf-8'))
            event = payload['ev']
            if not isinstance(event, str):
                raise TypeError
            data = payload.get('d', {})
            if not isinstance(data, dict):
                raise TypeError
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError):
            logger.debug(
                f'<Client {self.id}> Received invalid websockets payload.')
            return

        if not self.context['connected'] and event not in (
            'connect',
            'resume',
        ):
            self.error('You are not connected.')
            return

        self.dispatch_event(event, data)

    def format_user(self, context: dict[str, Any]) -> FormattedMember:
        return {
            'discord_id': context['discord_id'],
            'username': context['username'],
            'discriminator': context['discriminator'],
            'rank': context['rank'],
            'local': context['local'],
        }

    def is_alive(self) -> bool:
        heartbeat: float | None = self.context.get('heartbeat')
        if heartbeat is None:
            return False
        return time.monotonic() - heartbeat <= self.heartbeat_interval*2

    def dispatch_event(self, event: str, data: dict[str, Any]) -> None:
        event_handler = getattr(self, 'on_' + event, None)
        if event_handler is not None:
            event_handler(data)
        else:
            logger.debug(f'<Client {self.id}> Received invalid event {event}.')

    def get_online_members(self) -> OnlineMembers:
        webchat_members = {
            k.decode('utf-8'): json.loads(v.decode('utf-8'))
            for k, v in self.redis.hgetall('webchat-online-members').items()
        }
        discord_members = {
            k.decode('utf-8'): json.loads(v.decode('utf-8'))
            for k, v in self.redis.hgetall('discord-online-members').items()
        }
        return {
            'webchat': webchat_members,
            'discord': discord_members,
        }

    def get_message_history(self) -> list[FormattedMessage]:
        raw_messages = util.zhgetall(self.redis, 'webchat-message-history')
        return [json.loads(m.decode('utf-8')) for m in raw_messages]

    def on_resume(self, data: dict[str, Any]) -> None:
        client = self.channel.clients.get(data['client_id'])
        if not isinstance(client, DiscordClient):
            raise ClientError('Could not resume session.')
        # resume disconnected client
        logger.debug(
            f'<Client {self.id}> {self.context["username"]} resuming '
            'connection to webchat.'
        )
        # resuming will replace our context with the original client's
        # so we set its heartbeat rather than our own
        client.context['heartbeat'] = time.monotonic()
        self.redis.hincrby(
            'webchat-clients',
            webchat_user_key(self.context),
            1
        )
        self.resume(client)

    def on_connect(self, data: dict[str, Any] | None = None) -> None:
        if self.context.get('connected', False) is True:
            # we are already connected, nothing to do
            return

        self.context['connected'] = True
        self.context['heartbeat'] = time.monotonic()
        self.hello()

        logger.debug(
            f'<Client {self.id}> {self.context["username"]} '
            'connected to webchat.'
        )
        client_count = self.redis.hincrby(
            'webchat-clients',
            webchat_user_key(self.context),
            1
        )
        member = self.format_user(self.context)
        # first client publishes connect
        if client_count == 1:
            self.publish_event(
                'connect',
                member,
                'channel'
            )
        self.redis.hset('webchat-online-members',
                        webchat_user_key(self.context),
                        json.dumps(member, separators=(',', ':')))
        self.publish_event(
            'connection_success',
            {
                'you': member,
                'online_members': self.get_online_members(),
                'message_history': self.get_message_history(),
            },
        )

    def on_disconnect(
        self,
        data: dict[str, Any] | None = None,
        timeout: bool = False
    ) -> None:

        logger.debug(
            f'<Client {self.id}> {self.context["username"]} '
            'disconnected from webchat.'
        )
        raise ClientDisconnect()

    def on_heartbeat(self, data: dict[str, Any] | None = None) -> None:
        self.context['heartbeat'] = time.monotonic()
        logger.debug(
            f'<Client {self.id}> Received heartbeat from '
            f'{self.context["username"]}.'
        )

    def on_message(self, data: dict[str, Any]) -> None:
        user = self.context['user']
        username = self.context['username']
        avatar_url = self.context['avatar_url']
        # check if user has been banned
        if user.is_banned():
            self.error('You have been banned.')
            raise ClientError('You have been banned.')

        # check if user has been timed out
        raw_timeout = util.shget(
            self.redis,
            'timed-out-members',
            webchat_user_key(self.context)
        )
        if raw_timeout:
            timeout = json.loads(raw_timeout.decode('utf-8'))
            ttl = util.shttl(
                self.redis,
                'timed-out-members',
                webchat_user_key(self.context)
            )
            detail = f'You have to wait another {ttl} seconds.'
            if timeout.get('reason'):
                detail += f'\nReason: {timeout["reason"]}'
            self.error('You have been timed out.', detail)
            return

        # push to channel
        content = data['content']
        channel_name = data['channel_name']
        logger.debug(f'<Client {self.id}> {username} says: {content}')
        message: FormattedMessage = {
            'id': str(uuid.uuid4()),
            'content': content,
            'channel_name': channel_name,
            'author': self.format_user(self.context),
            'created_at': time.time(),
        }
        self.publish_event(
            'message',
            message,
            'channel'
        )
        # add message to history
        util.zhaddex(
            self.redis,
            'webchat-message-history',
            message['id'],
            config.webchat.history_ttl,
            json.dumps(message, separators=(',', ':')),
            message['created_at'],
            config.webchat.history_length
        )

        # push to bot for discord users
        self.publish_event(
            'webchat_message',
            {
                'channel_name': channel_name,
                'username': username,
                'avatar_url': avatar_url,
                'content': content,
            },
            'bot'
        )

        self.ack()

    def on_whisper(self, data: dict[str, Any]) -> None:
        content = data['content']
        target = data['member']
        message: dict[str, Any] = {
            'id': str(uuid.uuid4()),
            'content': content,
            'target': target,
            'author': self.format_user(self.context),
            'created_at': time.time(),
        }
        self.publish_event(
            'whisper',
            message,
            'channel'
        )
        if (discord_id := target['discord_id']):
            self.publish_event(
                'webchat_whisper',
                {
                    'target_id': discord_id,
                    'username': self.context['username'],
                    'avatar_url': self.context['avatar_url'],
                    'rank': self.context['rank'],
                    'content': content,
                },
                'bot'
            )

        self.ack()

    def on_broadcast(self, data: dict[str, Any]) -> None:
        user = self.context['user']
        if user and self.context['access_level'] >= ACL.moderator:
            content = data['content']
            message: FormattedMessage = {
                'id': str(uuid.uuid4()),
                'channel_name': 'broadcast',
                'content': content,
                'author': self.format_user(self.context),
                'created_at': time.time(),
            }
            self.publish_event(
                'broadcast',
                message,
                'channel'
            )
            # add message to history
            util.zhaddex(
                self.redis,
                'webchat-message-history',
                message['id'],
                config.webchat.history_ttl,
                json.dumps(message, separators=(',', ':')),
                message['created_at'],
                config.webchat.history_length
            )
            self.publish_event(
                'webchat_broadcast',
                {
                    'username': self.context['username'],
                    'avatar_url': self.context['avatar_url'],
                    'content': content,
                },
                'bot'
            )

            self.ack()
        else:
            self.error('Insufficient privileges.')

    def on_timeout_member(self, data: dict[str, Any]) -> None:
        user = self.context['user']
        if user and self.context['access_level'] >= ACL.moderator:
            member = data['member']
            if member['local']:
                local_user = user.get_user(username=member['username'])
                if not local_user:
                    self.error('Could not find user to timeout.')
                    return
                if local_user.access_level >= self.context['access_level']:
                    self.error(
                        'Cannot timeout user with same or higher rank.'
                    )
                    return
            util.shaddex(
                self.redis,
                'timed-out-members',
                webchat_user_key(member),
                config.webchat.timeout_duration,
                json.dumps(data, separators=(',', ':'))
            )
            self.publish_event('timeout_member', data, 'channel')
            if member['discord_id']:
                self.publish_event('webchat_timeout_member', data, 'bot')
            self.ack(f'{member["username"]} has been timed out successfully.')
        else:
            self.error('Insufficient privileges.')
        return

    def on_ban_member(self, data: dict[str, Any]) -> None:
        user = self.context['user']
        member: FormattedMember = data['member']
        if user and self.context['access_level'] >= ACL.moderator:
            if member['local']:
                local_user = user.get_user(username=member['username'],
                                           fuzzy=True)
                if not local_user:
                    self.error('Could not find user to ban.')
                    return
                if local_user.access_level >= self.context['access_level']:
                    self.error(
                        'Cannot ban user with same or higher rank.'
                    )
                    return
                local_user.ban()
                # in case we only got a name we fill in the blanks here
                member['username'] = local_user.username
                member['discord_id'] = (
                    str(local_user.discord_id)
                    if local_user.discord_id else None
                )
                member['discriminator'] = None
                # banned user's ranks will always be shadow
                member['rank'] = 'shadow'
                data['member'] = member
            self.publish_event('ban_member', data, 'channel')
            if member['discord_id']:
                self.publish_event('webchat_ban_member', data, 'bot')
            self.ack(f'{member["username"]} has been banned successfully.')
        else:
            self.error('Insufficient privileges.')

    def on_unban_member(self, data: dict[str, Any]) -> None:
        user = self.context['user']
        member = data['member']
        if user and self.context['access_level'] >= ACL.moderator:
            if member['local']:
                local_user = user.get_user(username=member['username'],
                                           fuzzy=True)
                if not local_user:
                    self.error('Could not find user to unban.')
                    return

                # we want to know the access level after unban
                access_level = config.special_users.get(
                    local_user.username,
                    ACL.turbo
                )
                if access_level >= self.context['access_level']:
                    self.error(
                        'Cannot unban user with same or higher rank.'
                    )
                    return

                local_user.unban()
                # in case we only got a name we fill in the blanks here
                member['username'] = local_user.username
                member['discord_id'] = (
                    str(local_user.discord_id)
                    if local_user.discord_id else None
                )
                member['discriminator'] = None
                member['rank'] = ACL_rank_map.get(access_level, 'shadow')
                data['member'] = member

            # Remove member from timed out members list
            util.shdel(
                self.redis,
                'timed-out-members',
                webchat_user_key(member),
            )
            self.publish_event('unban_member', data, 'channel')
            if member['discord_id']:
                self.publish_event('webchat_unban_member', data, 'bot')
            self.ack(
                f'{member["username"]} has been unbanned successfully. '
                'They will need to be unbanned from Discord manually.'
            )
        else:
            self.error('Insufficient privileges.')

    def on_ban_username(self, data: dict[str, Any]) -> None:
        username = data['username']
        # if we only get a name we treat it as a local user
        data['member'] = {'username': username, 'local': True}
        del data['username']
        return self.on_ban_member(data)

    def on_unban_username(self, data: dict[str, Any]) -> None:
        username = data['username']
        # if we only get a name we treat it as a local user
        data['member'] = {'username': username, 'local': True}
        del data['username']
        return self.on_unban_member(data)

    def on_kill(self) -> None:
        if self.context and 'username' in self.context:
            user_key = webchat_user_key(self.context)
            client_count = self.redis.hincrby(
                'webchat-clients',
                user_key,
                -1
            )
            # last client publishes disconnect
            if client_count <= 0:
                self.publish_event(
                    'disconnect',
                    self.format_user(self.context),
                    'channel'
                )
                self.redis.hdel('webchat-clients', user_key)
                self.redis.hdel('webchat-online-members', user_key)
        super().on_kill()


class DiscordChannel(Channel):

    client_cls: ClassVar[type[DiscordClient]] = DiscordClient

    def handle_channel_message(self, message: bytes) -> None:
        try:
            payload = json.loads(message.decode('utf-8'))
            event = payload['ev']
            if not isinstance(event, str):
                raise TypeError
            data = payload.get('d', {})
            if not isinstance(data, dict):
                raise TypeError
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, KeyError):
            logger.debug(
                f'<Channel {self.name}> Received invalid channel payload.')
            return

        user_key_filter = None
        if event == 'whisper':
            # whispers should only go to the clients that are involved
            user_key_filter = (
                webchat_user_key(data['author']),
                webchat_user_key(data['target'])
            )

        for client in self.clients.values():
            assert isinstance(client, DiscordClient)
            if client.context and client.context.get('connected', False):
                if not client.is_alive():
                    # set client to suspended, so it can resume its session
                    client.context['connected'] = False
                    client.state = ClientState.suspended
                    logger.info(f'<Client {client.id}> Client timeout.')
                    continue

                if (
                    user_key_filter is not None and
                    webchat_user_key(client.context) not in user_key_filter
                ):
                    # doesn't concern us
                    continue

                # this gets republished to each client's websocket, so we pass
                # the raw message, rather than the decoded payload
                self.dispatch_client_message(client, message)


DiscordChannel(config.discord.live_channel, '/webchat')
