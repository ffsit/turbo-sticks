import sys
import json
import time
import uwsgi
import gevent.select
import uuid
from oauthlib.oauth2 import OAuth2Error
from redis import StrictRedis as Redis

import turbo_session
import turbo_config as config
import turbo_util as util
import turbo_discord as discord
from turbo_db import DBError
from turbo_user import ACL, User

this = sys.modules[__name__]

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


# Generic passthrough websocket
class Channel(object):
    _redis = None

    def __init__(self, name, path, min_access_level=ACL.turbo):
        self.name = name
        self.path = config.websockets_path + path
        self.uri = util.build_url(path, base='websockets')
        self.min_access_level = min_access_level
        this.channels.append(self)

    @property
    def redis(self):
        if self._redis is not None:
            try:
                self._redis.ping()
            except ConnectionError:
                util.print_info('Lost connection to Redis.', False)
                del self._redis
        if self._redis is None:
            self._redis = Redis.from_url(config.redis_uri)
            util.print_info('Connecting to Redis...', False)
        return self._redis

    def authenticate(self, env):
        session = turbo_session.get_session(env)
        account = turbo_session.retrieve_oauth_account(session)
        if account:
            return User.create(account)
        return None

    def init_context(self, env, user, connection_id):
        return {
            'env': env,
            'user': user,
            'access_level': User.get_access_level(user),
            'connection_id': connection_id,
        }

    def open_websocket(self, env):
        context = None
        try:
            user = self.authenticate(env)
            access_level = User.get_access_level(user)
            if access_level < self.min_access_level:
                return

            uwsgi.websocket_handshake()
            util.print_info('Opening websocket connection', False)

            client_count = self.redis.get('websocket-clients')
            if client_count:
                client_count = int(client_count.decode('utf-8'))
                if client_count >= config.websockets_max_clients:
                    raise ClientError('No available slots.')
            self.redis.incr('websocket-clients')
            context = True
            channel = self.redis.pubsub()
            channel.subscribe(self.name)

            websocket_fd = uwsgi.connection_fd()
            redis_fd = channel.connection._sock.fileno()
            context = self.init_context(env, user, redis_fd)

            while True:
                ready = gevent.select.select(
                    [websocket_fd, redis_fd], [], [], 4.0
                )
                if not ready[0]:
                    # send ping on timeout
                    uwsgi.websocket_recv_nb()

                for fd in ready[0]:
                    if fd == websocket_fd:
                        # client message
                        context = self.fetch_and_handle_client_message(context)
                    elif fd == redis_fd:
                        # channel message
                        message = channel.parse_response()
                        if message[0] == b'message':
                            context = self.handle_channel_message(context,
                                                                  message[2])
        except ClientTimeout:
            util.print_info('Websocket connection client timeout.')
        except ClientDisconnect:
            util.print_info('Websocket connection client disconnected.')
        except ClientError as error:
            util.print_exception('Websocket client error', error, False,
                                 print_traceback=False)
        except IOError as error:
            # Socket Error
            util.print_exception('Websocket connection closed', error, False,
                                 print_traceback=False)
        except DBError as error:
            # Database Error
            util.print_exception('Database Error occured: ', error)
        except OAuth2Error as error:
            # OAuth 2.0 Error
            util.print_exception('OAuth 2.0 Error occured: ', error)
        except Exception as error:
            # Unknown Exception
            util.print_exception('Unexpected Error occured: ', error, False)
        finally:
            self.cleanup(context)

    def client_publish(self, message):
        uwsgi.websocket_send(message)

    def channel_publish(self, message):
        self.redis.publish(self.name, message)

    def fetch_and_handle_client_message(self, context):
        message = uwsgi.websocket_recv_nb()
        if message:
            return self.handle_client_message(context, message)
        return context

    def handle_client_message(self, context, message):
        self.channel_publish(message)
        return context

    def handle_channel_message(self, context, message):
        self.client_publish(message)
        return context

    def cleanup(self, context):
        if context:
            self.redis.decr('websocket-clients')


ACL_rank_map = {
    ACL.guest: 'shadow',
    ACL.patron: 'patron',
    ACL.turbo: 'turbo',
    ACL.helper: 'helper',
    ACL.moderator: 'mod',
    ACL.crew: 'crew',
    ACL.admin: 'mod',
}


class DiscordChannel(Channel):
    heartbeat_interval = 4.0

    def __init__(self, name, path, min_access_level=ACL.turbo):
        super().__init__(name, path, min_access_level)

    def init_context(self, env, user, connection_id):
        context = super().init_context(env, user, connection_id)
        context['connected'] = False
        context['discord_id'] = None
        context['discriminator'] = None
        context['local'] = True
        context['rank'] = ACL_rank_map.get(context['access_level'], 'shadow')
        if user:
            if user.banned:
                raise ClientError('You have been banned.')
            context['username'] = user.username
            context['avatar_url'] = user.account.get('avatar', '')
            if user.discord_id:
                context['discord_id'] = str(user.discord_id)
        else:
            # authenticate with discord directly
            discord_member = discord.member_from_guest_session(env)
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
            context['username'] = username
            context['discriminator'] = discriminator
            context['discord_id'] = str(discord_member.get('id'))
            context['avatar_url'] = avatar_url
        return context

    def bot_publish(self, message):
        self.redis.publish('sticks-bot', message)

    def publish_event(self, event, data={}, destination='client'):
        assert destination in ['bot', 'channel', 'client']
        payload = {'ev': event, 'd': data}
        message = json.dumps(payload, separators=(',', ':'))
        getattr(self, destination + '_publish')(message)

    def ack(self, info=None):
        self.publish_event('ack', {'info': info} if info else {})

    def error(self, message, detail=None):
        payload = {'message': message}
        if detail:
            payload['detail'] = detail
        self.publish_event('error', payload)

    def handle_client_message(self, context, message):
        try:
            payload = json.loads(message.decode('utf-8'))
            if isinstance(payload, dict) and payload.get('ev'):
                event = payload['ev']
                data = payload.get('d', {})
                if not context['connected'] and event != 'connect':
                    self.error('You are not connected.')
                    return context
                context = self.dispatch_event(context, event, data)
        except (json.JSONDecodeError, KeyError):
            util.print_info('Received invalid websockets payload.')
        return context

    def handle_channel_message(self, context, message):
        if context.get('connected', False):
            self.check_client_alive(context)
            try:
                payload = json.loads(message.decode('utf-8'))
                if isinstance(payload, dict) and payload.get('ev'):
                    event = payload['ev']
                    data = payload.get('d', {})
                    if event == 'whisper':
                        self_key = self.webchat_user_key(context)
                        author_key = self.webchat_user_key(data['author'])
                        target_key = self.webchat_user_key(data['target'])
                        if self_key not in [author_key, target_key]:
                            # doesn't concern us
                            return context
            except (json.JSONDecodeError, KeyError):
                util.print_info('Received invalid channel payload.')
            self.client_publish(message)
        return context

    def format_user(self, context):
        return {k: context[k] for k in (
            'discord_id',
            'username',
            'discriminator',
            'rank',
            'local',
        )}

    def check_client_alive(self, context):
        heartbeat = context.get('heartbeat', 0)
        if time.time() - heartbeat > self.heartbeat_interval*2:
            raise ClientTimeout()

    def dispatch_event(self, context, event, data):
        handler = 'on_' + event
        if hasattr(self, handler):
            context = getattr(self, handler)(context, data)
        else:
            util.print_info('Received invalid event.')
        return context

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

    def webchat_user_key(self, context):
        if context['discord_id']:
            return context['discord_id']
        return context['username']

    def on_connect(self, context, data=None):
        util.print_info(f'{context["username"]} connected to webchat.')
        context['heartbeat'] = time.time()
        client_count = self.redis.hincrby(
            'webchat-clients',
            self.webchat_user_key(context),
            1
        )
        member = self.format_user(context)
        # first client publishes connect
        if client_count == 1:
            self.publish_event(
                'connect',
                member,
                'channel'
            )
        self.redis.hset('webchat-online-members',
                        self.webchat_user_key(context),
                        json.dumps(member, separators=(',', ':')))
        self.publish_event(
            'connection_success',
            {
                'you': member,
                'online_members': self.get_online_members(),
                'message_history': self.get_message_history(),
            },
        )
        context['connected'] = True
        return context

    def on_disconnect(self, context, data=None, timeout=False):
        raise ClientDisconnect()

    def on_heartbeat(self, context, data=None):
        context['heartbeat'] = time.time()
        util.print_info(f'Received heartbeat from {context["username"]}.')
        return context

    def on_message(self, context, data):
        user = context['user']
        username = context['username']
        avatar_url = context['avatar_url']
        # check if user has been banned
        if user.is_banned():
            raise ClientError('You have been banned.')

        # check if user has been timed out
        timeout = util.shget(
            self.redis,
            'timed-out-members',
            self.webchat_user_key(context)
        )
        if timeout:
            timeout = json.loads(timeout.decode('utf-8'))
            ttl = util.shttl(
                self.redis,
                'timed-out-members',
                self.webchat_user_key(context)
            )
            detail = f'You have to wait another {ttl} seconds.'
            if timeout.get('reason'):
                detail += f'\nReason: {timeout["reason"]}'
            self.error('You have been timed out.', detail)
            return context

        # push to channel
        util.print_info(f'{username} says: {data["content"]}')
        message = {
            'id': str(uuid.uuid4()),
            'content': data['content'],
            'channel_name': data['channel_name'],
            'author': self.format_user(context),
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
        return context

    def on_whisper(self, context, data):
        target = data['member']
        message = {
            'id': str(uuid.uuid4()),
            'content': data['content'],
            'target': target,
            'author': self.format_user(context),
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
                    'username': context['username'],
                    'avatar_url': context['avatar_url'],
                    'rank': context['rank'],
                    'content': data['content'],
                },
                'bot'
            )

        self.ack()
        return context

    def on_broadcast(self, context, data):
        user = context['user']
        if user and context['access_level'] >= ACL.moderator:
            message = {
                'id': str(uuid.uuid4()),
                'channel': 'broadcast',
                'content': data['content'],
                'author': self.format_user(context),
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
                    'username': context['username'],
                    'avatar_url': context['avatar_url'],
                    'content': data['content'],
                },
                'bot'
            )

            self.ack()
        else:
            self.error('Insufficient privileges.')
        return context

    def on_timeout_member(self, context, data):
        user = context['user']
        if user and context['access_level'] >= ACL.moderator:
            member = data['member']
            if member['local']:
                local_user = user.get_user(username=member['username'])
                if not local_user:
                    self.error('Could not find user to timeout.')
                    return context
                if local_user.access_level >= context['access_level']:
                    self.error(
                        'Cannot timeout user with same or higher rank.'
                    )
                    return context
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
        return context

    def on_ban_member(self, context, data):
        user = context['user']
        member = data['member']
        if user and context['access_level'] >= ACL.moderator:
            if member['local']:
                local_user = user.get_user(username=member['username'],
                                           fuzzy=True)
                if not local_user:
                    self.error('Could not find user to unban.')
                    return context
                if local_user.access_level >= context['access_level']:
                    self.error(
                        'Cannot unban user with same or higher rank.'
                    )
                    return context
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
        return context

    def on_unban_member(self, context, data):
        user = context['user']
        member = data['member']
        if user and context['access_level'] >= ACL.moderator:
            if member['local']:
                local_user = user.get_user(username=member['username'],
                                           fuzzy=True)
                if not local_user:
                    self.error('Could not find user to unban.')
                    return context
                if local_user.access_level >= context['access_level']:
                    self.error(
                        'Cannot unban user with same or higher rank.'
                    )
                    return context
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
        return context

    def on_ban_username(self, context, data):
        username = data['username']
        # if we only get a name we treat it as a local user
        data['member'] = {'username': username, 'local': True}
        del data['username']
        return self.on_ban_member(context, data)

    def on_unban_username(self, context, data):
        username = data['username']
        # if we only get a name we treat it as a local user
        data['member'] = {'username': username, 'local': True}
        del data['username']
        return self.on_unban_member(context, data)

    def cleanup(self, context):
        super().cleanup(context)
        if context and 'username' in context:
            client_count = self.redis.hincrby(
                'webchat-clients',
                self.webchat_user_key(context),
                -1
            )
            # last client publishes disconnect
            if client_count < 1:
                self.publish_event(
                    'disconnect',
                    self.format_user(context),
                    'channel'
                )
            self.redis.hdel('webchat-online-members', context['username'])

DiscordChannel(config.discord.live_channel, '/webchat')
