import sys
import logging
import json
import time
import uwsgi
import uuid
import gevent
from enum import Enum
from oauthlib.oauth2 import OAuth2Error
from redis import StrictRedis as Redis

import turbo_session
import turbo_config as config
import turbo_util as util
import turbo_discord as discord
from turbo_db import DBError
from turbo_user import ACL, User

this = sys.modules[__name__]

# Logger
logger = logging.getLogger('sticks.wss')

# Channels
this.channels = []


def init_redis_state():
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


# Websocket job decorator
def websocket_job(func=None, *,  on_finish=None):
    def decorator(func):
        def decorated_function(self, *args, **kwargs):
            logger.debug(
                f'<Client {self.id}> Started greenlet {func.__name__}.'
            )
            try:
                func(self, *args, **kwargs)
            except ClientTimeout:
                self.state = ClientState.exited
                logger.info(f'<Client {self.id}> Client timeout.')
            except ClientDisconnect:
                self.state = ClientState.exited
                logger.info(f'<Client {self.id}> Client disconnected.')
            except ClientError as error:
                self.state = ClientState.exited
                logger.warning(f'<Client {self.id}> Client error: {error}')
            except DBError:
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
                if callable(on_finish):
                    on_finish()
                elif isinstance(on_finish, str) and hasattr(self, on_finish):
                    getattr(self, on_finish)()
                logger.debug(
                    f'<Client {self.id}> Finished greenlet {func.__name__}.'
                )
        return decorated_function
    return decorator(func) if callable(func) else decorator


class Channel(object):
    _redis = None

    def __init__(self, client_cls, name, path, min_access_level=ACL.turbo):
        self.client_cls = client_cls
        self.name = name
        self.path = config.websockets_path + path
        self.uri = util.build_url(path, base='websockets')
        self.min_access_level = min_access_level
        self.clients = {}
        this.channels.append(self)

    def add_client(self, env):
        client = self.client_cls(self, env)
        self.clients[client.id] = client
        return client

    def remove_client(self, client):
        if client.id in self.clients.keys():
            del self.clients[client.id]

    @property
    def redis(self):
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

    def open_websocket(self, env):
        try:
            client = self.add_client(env)
            client.start()
        except ClientError as error:
            logger.warning(f'Failed to init websocket client: {error}')
            self.remove_client(client)

    def close(self):
        for client in self.clients.values():
            client.exit()
        gevent.sleep(1.0)


class ClientState(Enum):
    new = 0
    started = 1
    suspended = 2
    resumed = 3
    exited = 4
    merged = 5


# Generic passthrough websocket client
class Client(object):
    def __init__(self, channel, env):
        self.id = str(uuid.uuid4())
        self.channel = channel
        self.env = env
        self.fd_select_job = None
        self.jobs = []
        self.event = gevent.event.Event()
        self.merge_event = gevent.event.Event()
        self.client_send_queue = gevent.queue.Queue()
        self.client_recv_queue = gevent.queue.Queue()
        self.context = None
        self._redis_channel = None
        self.state = ClientState.new

    @property
    def redis(self):
        return self.channel.redis

    def redis_channel(self):
        if self._redis_channel:
            try:
                self._redis_channel.check_health()
            except RuntimeError:
                self._redis_channel = None
        if not self._redis_channel:
            self._redis_channel = self.redis.pubsub()
            self._redis_channel.subscribe(self.channel.name)
        return self._redis_channel

    def authenticate(self, env):
        session = turbo_session.get_session(env)
        account = turbo_session.retrieve_oauth_account(session)
        if account:
            return User.create(account)
        return None

    def init_context(self):
        user = self.authenticate(self.env)
        access_level = User.get_access_level(user)

        self.context = {
            'user': user,
            'access_level': access_level,
        }

    def client_publish(self, message):
        self.client_send_queue.put_nowait(message)
        self.event.set()

    def channel_publish(self, message):
        self.redis.publish(self.channel.name, message)

    def handle_client_message(self, message):
        self.channel_publish(message)

    def handle_channel_message(self, message):
        self.client_publish(message)

    @websocket_job
    def _handle_channel_messages(self):
        while self.job_state != ClientState.exited:
            if self.job_state == ClientState.suspended:
                gevent.sleep(0.2)
                continue
            message = self.redis_channel().parse_response(block=False,
                                                          timeout=0.2)
            if message and message[0] == b'message':
                self.handle_channel_message(message[2])
            gevent.sleep(0)

    @websocket_job
    def _handle_client_messages(self):
        while self.job_state != ClientState.exited:
            try:
                message = self.client_recv_queue.get(timeout=0.2)
                self.handle_client_message(message)
            except gevent.queue.Empty:
                pass
            gevent.sleep(0)

    def _fd_select(self):
        while self.state == ClientState.started:
            self.event.set()
            # for some reason any other method of checking fails
            try:
                gevent.select.select([self.websocket_fd], [], [])[0]
            except (ValueError, OSError):
                break

    def spawn_jobs(self):
        self.job_state = ClientState.started
        self.jobs.extend([
            gevent.spawn(self._handle_client_messages),
            gevent.spawn(self._handle_channel_messages),
        ])

    @websocket_job(on_finish='cleanup')
    def start(self):
        self.init_context()
        if self.context['access_level'] < self.channel.min_access_level:
            raise ClientError('Insufficient privileges.')

        uwsgi.websocket_handshake()
        self.websocket_fd = uwsgi.connection_fd()
        logger.info(f'<Client {self.id}> Opening websocket connection')

        client_count = self.redis.get('websocket-clients')
        if client_count:
            client_count = int(client_count.decode('utf-8'))
            if client_count >= config.websockets_max_clients:
                raise ClientError('No available slots.')
        self.redis.incr('websocket-clients')
        self.state = ClientState.started

        self.fd_select_job = gevent.spawn(self._fd_select)
        self.spawn_jobs()
        self.main_loop()

    def resume(self, client):
        self.job_state = ClientState.suspended
        gevent.sleep(0.2)
        self.channel.remove_client(self)
        self.id = client.id
        self.client_send_queue = client.client_send_queue
        self.client_recv_queue = client.client_recv_queue
        self.context = client.context
        client.state = ClientState.merged
        client.merge_event.set()
        gevent.sleep(0.2)
        self.job_state = ClientState.started
        logger.info(f'<Client {self.id}> Websocket session resumed.')
        self.channel.clients[self.id] = self

    def main_loop(self):
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

    def kill_jobs(self):
        self.job_state = ClientState.exited
        gevent.sleep(0.2)
        self.jobs = []

    def exit(self):
        self.state = ClientState.exited
        self.kill_jobs()

    def on_kill(self):
        self.kill_jobs()
        if self.context:
            self.redis.decr('websocket-clients')
        self.channel.remove_client(self)

    def cleanup(self):
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


ACL_rank_map = {
    ACL.guest: 'shadow',
    ACL.patron: 'patron',
    ACL.turbo: 'turbo',
    ACL.helper: 'helper',
    ACL.moderator: 'mod',
    ACL.crew: 'crew',
    ACL.admin: 'mod',
}


class DiscordClient(Client):
    heartbeat_interval = 4.0

    def resume(self, client):
        super().resume(client)
        self.hello()

    def init_context(self):
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
            self.context['avatar_url'] = user.account.get('avatar', '')
            if user.discord_id:
                self.context['discord_id'] = str(user.discord_id)
        else:
            # authenticate with discord directly
            discord_member = discord.member_from_guest_session(self.env)
            discord_user = discord.get_user(discord_member)
            if not discord_user:
                raise ClientError('Guests require Discord account.')
            username = discord_member.get('nick', '')
            if not username:
                username = discord_user.get('username', '')
            discriminator = discord_user.get('discriminator', '')
            avatar_url = discord.get_avatar_url(discord_user)
            if not username or not discriminator:
                raise ClientError('Failed to retrieve username')
            self.context['username'] = username
            self.context['discriminator'] = discriminator
            self.context['discord_id'] = str(discord_member.get('id'))
            self.context['avatar_url'] = avatar_url

    def bot_publish(self, message):
        self.redis.publish('sticks-bot', message)

    def publish_event(self, event, data={}, destination='client'):
        assert destination in ['bot', 'channel', 'client']
        payload = {'ev': event, 'd': data}
        message = json.dumps(payload, separators=(',', ':'))
        getattr(self, destination + '_publish')(message)

    def hello(self):
        self.publish_event('hello', {'client_id': self.id})

    def ack(self, info=None):
        self.publish_event('ack', {'info': info} if info else {})

    def error(self, message, detail=None):
        payload = {'message': message}
        if detail:
            payload['detail'] = detail
        self.publish_event('error', payload)

    def handle_client_message(self, message):
        try:
            payload = json.loads(message.decode('utf-8'))
            if isinstance(payload, dict) and payload.get('ev'):
                event = payload['ev']
                data = payload.get('d', {})
                if not self.context['connected'] and event not in [
                    'connect',
                    'resume',
                ]:
                    self.error('You are not connected.')
                    return
                self.dispatch_event(event, data)
        except (json.JSONDecodeError, KeyError):
            logger.debug(
                f'<Client {self.id}> Received invalid websockets payload.')

    def handle_channel_message(self, message):
        if self.context.get('connected', False):
            self.check_client_alive()
            try:
                payload = json.loads(message.decode('utf-8'))
                if isinstance(payload, dict) and payload.get('ev'):
                    event = payload['ev']
                    data = payload.get('d', {})
                    if event == 'whisper':
                        self_key = self.webchat_user_key(self.context)
                        author_key = self.webchat_user_key(data['author'])
                        target_key = self.webchat_user_key(data['target'])
                        if self_key not in [author_key, target_key]:
                            # doesn't concern us
                            return
            except (json.JSONDecodeError, KeyError):
                logger.debug(
                    f'<Client {self.id}> Received invalid channel payload.')
            self.client_publish(message)

    def format_user(self, context):
        return {k: context[k] for k in (
            'discord_id',
            'username',
            'discriminator',
            'rank',
            'local',
        )}

    def check_client_alive(self):
        heartbeat = self.context.get('heartbeat', 0)
        if time.time() - heartbeat > self.heartbeat_interval*2:
            raise ClientTimeout()

    def dispatch_event(self, event, data):
        handler = 'on_' + event
        if hasattr(self, handler):
            getattr(self, handler)(data)
        else:
            logger.debug(f'<Client {self.id}> Received invalid event.')

    def get_online_members(self):
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

    def get_message_history(self):
        raw_messages = util.zhgetall(self.redis, 'webchat-message-history')
        return [json.loads(m.decode('utf-8')) for m in raw_messages]

    def webchat_user_key(self, member):
        if member['discord_id']:
            return member['discord_id']
        return member['username']

    def on_resume(self, data):
        client = self.channel.clients.get(data['client_id'])
        if not client:
            raise ClientError('Could not resume session.')
        # resume disconnected client
        logger.debug(
            f'<Client {self.id}> {self.context["username"]} resuming '
            'connection to webchat.'
        )
        self.context['heartbeat'] = time.time()
        self.redis.hincrby(
            'webchat-clients',
            self.webchat_user_key(self.context),
            1
        )
        self.resume(client)

    def on_connect(self, data=None):
        if self.context.get('connected', False) is False:
            self.hello()
        logger.debug(
            f'<Client {self.id}> {self.context["username"]} '
            'connected to webchat.'
        )
        self.context['heartbeat'] = time.time()
        client_count = self.redis.hincrby(
            'webchat-clients',
            self.webchat_user_key(self.context),
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
                        self.webchat_user_key(self.context),
                        json.dumps(member, separators=(',', ':')))
        self.publish_event(
            'connection_success',
            {
                'you': member,
                'online_members': self.get_online_members(),
                'message_history': self.get_message_history(),
            },
        )
        self.context['connected'] = True

    def on_disconnect(self, data=None, timeout=False):
        logger.debug(
            f'<Client {self.id}> {self.context["username"]} '
            'disconnected from webchat.'
        )
        raise ClientDisconnect()

    def on_heartbeat(self, data=None):
        self.context['heartbeat'] = time.time()
        logger.debug(
            f'<Client {self.id}> Received heartbeat from '
            f'{self.context["username"]}.'
        )

    def on_message(self, data):
        user = self.context['user']
        username = self.context['username']
        avatar_url = self.context['avatar_url']
        # check if user has been banned
        if user.is_banned():
            self.error('You have been banned.')
            raise ClientError('You have been banned.')

        # check if user has been timed out
        timeout = util.shget(
            self.redis,
            'timed-out-members',
            self.webchat_user_key(self.context)
        )
        if timeout:
            timeout = json.loads(timeout.decode('utf-8'))
            ttl = util.shttl(
                self.redis,
                'timed-out-members',
                self.webchat_user_key(self.context)
            )
            detail = f'You have to wait another {ttl} seconds.'
            if timeout.get('reason'):
                detail += f'\nReason: {timeout["reason"]}'
            self.error('You have been timed out.', detail)
            return

        # push to channel
        logger.debug(f'<Client {self.id}> {username} says: {data["content"]}')
        message = {
            'id': str(uuid.uuid4()),
            'content': data['content'],
            'channel_name': data['channel_name'],
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
            config.message_history_ttl,
            json.dumps(message, separators=(',', ':')),
            message['created_at'],
            config.message_history_length
        )

        # push to bot for discord users
        self.publish_event(
            'webchat_message',
            {
                'channel_name': data['channel_name'],
                'username': username,
                'avatar_url': avatar_url,
                'content': data['content'],
            },
            'bot'
        )

        self.ack()

    def on_whisper(self, data):
        target = data['member']
        message = {
            'id': str(uuid.uuid4()),
            'content': data['content'],
            'target': target,
            'author': self.format_user(self.context),
            'created_at': time.time(),
        }
        self.publish_event(
            'whisper',
            message,
            'channel'
        )
        if target['discord_id']:
            self.publish_event(
                'webchat_whisper',
                {
                    'target_id': target['discord_id'],
                    'username': self.context['username'],
                    'avatar_url': self.context['avatar_url'],
                    'rank': self.context['rank'],
                    'content': data['content'],
                },
                'bot'
            )

        self.ack()

    def on_broadcast(self, data):
        user = self.context['user']
        if user and self.context['access_level'] >= ACL.moderator:
            message = {
                'id': str(uuid.uuid4()),
                'channel': 'broadcast',
                'content': data['content'],
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
                config.message_history_ttl,
                json.dumps(message, separators=(',', ':')),
                message['created_at'],
                config.message_history_length
            )
            self.publish_event(
                'webchat_broadcast',
                {
                    'username': self.context['username'],
                    'avatar_url': self.context['avatar_url'],
                    'content': data['content'],
                },
                'bot'
            )

            self.ack()
        else:
            self.error('Insufficient privileges.')

    def on_timeout_member(self, data):
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
                self.webchat_user_key(member),
                config.timeout_duration,
                json.dumps(data, separators=(',', ':'))
            )
            self.publish_event('timeout_member', data, 'channel')
            if member['discord_id']:
                self.publish_event('webchat_timeout_member', data, 'bot')
            self.ack(f'{member["username"]} has been timed out successfully.')
        else:
            self.error('Insufficient privileges.')
        return

    def on_ban_member(self, data):
        user = self.context['user']
        member = data['member']
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
                member['discord_id'] = local_user.discord_id
                member['rank'] = ACL_rank_map.get(local_user.access_level,
                                                  'shadow')
                data['member'] = member
            self.publish_event('ban_member', data, 'channel')
            if member['discord_id']:
                self.publish_event('webchat_ban_member', data, 'bot')
            self.ack(f'{member["username"]} has been banned successfully.')
        else:
            self.error('Insufficient privileges.')

    def on_unban_member(self, data):
        user = self.context['user']
        member = data['member']
        if user and self.context['access_level'] >= ACL.moderator:
            if member['local']:
                local_user = user.get_user(username=member['username'],
                                           fuzzy=True)
                if not local_user:
                    self.error('Could not find user to unban.')
                    return
                if local_user.access_level >= self.context['access_level']:
                    self.error(
                        'Cannot unban user with same or higher rank.'
                    )
                    return
                local_user.unban()
                # in case we only got a name we fill in the blanks here
                member['username'] = local_user.username
                member['discord_id'] = local_user.discord_id
                member['rank'] = ACL_rank_map.get(local_user.access_level,
                                                  'shadow')
                data['member'] = member

            # Remove member from timed out members list
            util.shdel(
                self.redis,
                'timed-out-members',
                self.webchat_user_key(member),
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

    def on_ban_username(self, data):
        username = data['username']
        # if we only get a name we treat it as a local user
        data['member'] = {'username': username, 'local': True}
        del data['username']
        return self.on_ban_member(data)

    def on_unban_username(self, data):
        username = data['username']
        # if we only get a name we treat it as a local user
        data['member'] = {'username': username, 'local': True}
        del data['username']
        return self.on_unban_member(data)

    def on_kill(self):
        if self.context and 'username' in self.context:
            client_count = self.redis.hincrby(
                'webchat-clients',
                self.webchat_user_key(self.context),
                -1
            )
            # last client publishes disconnect
            if client_count <= 0:
                self.publish_event(
                    'disconnect',
                    self.format_user(self.context),
                    'channel'
                )
                self.redis.hdel(
                    'webchat-clients',
                    self.webchat_user_key(self.context)
                )
                self.redis.hdel(
                    'webchat-online-members',
                    self.webchat_user_key(self.context)
                )
        super().on_kill()

Channel(DiscordClient, config.discord.live_channel, '/webchat')
