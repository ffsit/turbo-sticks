import asyncio
import discord
import json
import logging
import time
import uuid
from redis import StrictRedis as Redis
from discord.ext import tasks
from datetime import datetime, timedelta

import turbo_config as config
import turbo_util as util

# Setup discord.py logging
logging_level = logging.DEBUG if config.debug_mode else logging.WARNING
logging.basicConfig(level=logging_level)
logger = logging.getLogger('discord')
webchat_roles = ['crew', 'mod', 'vip', 'turbo']


def format_user(user):
    if user is None:
        return {}
    rank = None
    if user.bot:
        rank = 'bot'
    elif hasattr(user, 'top_role'):
        rank = format_role(user.top_role)
    return {
        'username': user.display_name,
        'discord_id': str(user.id),
        'discriminator': user.discriminator,
        'rank': rank,
        'local': False,
    }


def get_epoch_from_datetime(dt):
    return (dt - datetime(1970, 1, 1)) / timedelta(seconds=1)


def format_message(message):
    author = message.author if hasattr(message, 'author') else None
    return {
        'id': str(message.id),
        'channel_name': message.channel.name,
        'content': message.clean_content,
        'author': format_user(author),
        'created_at': get_epoch_from_datetime(message.created_at)
    }


def format_role(role):
    for webchat_role in webchat_roles:
        if role.name.lower().startswith(webchat_role):
            return webchat_role
    return 'shadow'


# NOTE: For simplicity's sake the connection to Redis is not fully asynchronous
#       this could potentially lead to timeouts, but for how little traffic is
#       to be expected with a couple of channels with a few dozen users, this
#       should be fine.
class SticksBot(discord.Client):
    webchat_webhook = None
    pubsub = None
    live_channel_id = None
    last_whisper_sender = {}

    def __init__(self):
        super().__init__()
        self.redis = Redis.from_url(config.redis_uri)
        self.redis_loop_lock = asyncio.Lock()
        self.redis_loop.start()
        self.webchat_webhook_lock = asyncio.Lock()
        self.refresh_webhook_loop.start()

    def redis_next_message(self):
        return self.pubsub.parse_response(False)

    @tasks.loop(seconds=0.1)
    async def redis_loop(self):
        if self.redis_loop_lock.locked():
            return
        async with self.redis_loop_lock:
            for message in iter(self.redis_next_message, None):
                try:
                    if message[0] != b'message':
                        continue
                    payload = json.loads(message[2].decode('utf-8'))
                    event = payload['ev']
                    args = []
                    kwargs = payload.get('d', {})
                    logger.debug(f'Received event {event} from webchat.')
                    self.dispatch(event, *args, **kwargs)
                except (json.JSONDecodeError, KeyError):
                    logger.error('Received invalid message from webchat.')

    @redis_loop.before_loop
    async def before_redis_loop(self):
        await self.wait_until_ready()
        self.pubsub = self.redis.pubsub()
        self.pubsub.subscribe('sticks-bot')

    @tasks.loop(seconds=4.0)
    async def webchat_heartbeat(self):
        self.redis.set('sticks-bot-heartbeat', time.time())

    @webchat_heartbeat.before_loop
    async def before_webchat_heartbeat(self):
        await self.wait_until_ready()

    async def refresh_webhook(self):
        async with self.webchat_webhook_lock:
            guild = self.get_guild(int(config.discord.server_id))
            for channel in guild.channels:
                if channel.name == config.discord.live_channel:
                    # clean up old webhooks
                    webhooks = await channel.webhooks()
                    for webhook in webhooks:
                        if(
                            webhook.user == client.user and
                            webhook.name.startswith('WEBCHAT-')
                        ):
                            await webhook.delete()

                    # create new webhook
                    webhook_name = f'WEBCHAT-{channel.name}'
                    webhook = await channel.create_webhook(name=webhook_name)
                    self.webchat_webhook = webhook
                    break

    @tasks.loop(seconds=config.discord.webhook_refresh_interval)
    async def refresh_webhook_loop(self):
        self.refresh_webhook()

    @refresh_webhook_loop.before_loop
    async def before_refresh_webhook(self):
        await self.wait_until_ready()

    async def publish_event(self, event, data={}):
        payload = {
            'ev': event,
            'd': data,
        }
        self.redis.publish(config.discord.live_channel,
                           json.dumps(payload, separators=(',', ':')))

    async def on_guild_available(self, guild):
        if str(guild.id) == config.discord.server_id:
            await self.refresh_webhook()
            self.redis.delete('discord-online-members')
            members = {}
            for channel in guild.channels:
                if channel.name == config.discord.live_channel:
                    self.live_channel_id = channel.id
                    for member in channel.members:
                        if member.status != discord.Status.offline:
                            await self.set_member_online(member, publish=False)
                            members[member.id] = format_user(member)
            self.webchat_heartbeat.start()
            await self.publish_event('discord_connect', {'members': members})

    async def on_guild_unavailable(self, guild):
        if str(guild.id) == config.discord.server_id:
            await self.publish_event('discord_disconnect')
            self.redis.delete('discord-online-members')
            self.webchat_heartbeat.cancel()

    async def on_disconnect(self):
        await self.publish_event('discord_disconnect')
        self.redis.delete('discord-online-members')
        self.webchat_heartbeat.cancel()

    def is_relevant_message(self, message):
        return (
            message.type == discord.MessageType.default and
            message.content and
            hasattr(message.channel, 'guild') and
            str(message.channel.guild.id) == config.discord.server_id and
            message.channel.name == config.discord.live_channel and
            hasattr(message, 'author') and
            hasattr(message.author, 'top_role')
        )

    def filter_messages(self, messages):
        filtered = []
        for message in messages:
            if self.is_relevant_message(message):
                filtered.append(message)
        return filtered

    async def close(self):
        await self.publish_event('discord_disconnect')
        self.redis.delete('discord-online-members')
        await super().close()

    def get_rank_colour(self, guild, rank):
        for role in guild.roles:
            if rank in role.name.lower():
                return role.colour

    async def on_webchat_message(self, channel_name, username, avatar_url,
                                 content):
        if username[-5:-4] != '#':
            username += config.discord.webchat_user_suffix
        async with self.webchat_webhook_lock:
            await self.webchat_webhook.send(content, username=username,
                                            avatar_url=avatar_url)

    async def on_webchat_broadcast(self, username, avatar_url, content):
        if username[-5:-4] != '#':
            username += config.discord.webchat_user_suffix

        if self.live_channel_id:
            channel = self.get_channel(self.live_channel_id)
            embed = discord.Embed(description=content, colour=0xe74c3c)
            embed.set_author(name=username,
                             icon_url=avatar_url)
            await channel.send('Webchat Broadcast:', embed=embed)

    async def on_webchat_whisper(self, target_id, username, avatar_url, rank,
                                 content):
        guild = self.get_guild(int(config.discord.server_id))
        member = guild.get_member(int(target_id))
        if member:
            self.last_whisper_sender[member.id] = username
            embed = discord.Embed(
                description=content,
                colour=self.get_rank_colour(guild, rank),
            )
            if username[-5:-4] != '#':
                username += config.discord.webchat_user_suffix
            embed.set_author(name=f'{username} whispers:', icon_url=avatar_url)
            await member.send('', embed=embed)

    async def on_webchat_timeout_member(self, member, reason=''):
        guild = self.get_guild(int(config.discord.server_id))
        member = guild.get_member(int(member['discord_id']))
        if member:
            if reason:
                reason = f' Reason: {reason}'
            await member.send(
                f'You have been timed out.{reason}\n'
                'Your messages won\'t appear in the webchat or on show. '
                f'Please wait {config.timeout_duration} seconds.\n'
            )

    async def on_webchat_ban_member(self, member, reason=None):
        guild = self.get_guild(int(config.discord.server_id))
        member = guild.get_member(int(member['discord_id']))
        if member:
            await member.ban(reason=reason)
            if reason:
                reason = f' Reason: {reason}'
            await member.send(f'You have been banned.{reason}')

    async def on_webchat_unban_member(self, member, reason=None):
        guild = self.get_guild(int(config.discord.server_id))
        member = guild.get_member(int(member['discord_id']))
        if member:
            await member.send(f'Your timeout has been lifted.')
            await member.unban(reason=reason)

    async def command_help(self, member, argstr):
        await member.send(
            'Available commands: ```\n'
            '%![command] [arg1], [arg2]  -- [Command description]\n'
            '%!reply message             -- Reply to the last private message '
            'you received\n'
            '%!whisper username, message -- Whisper to a webchat user\n'
            '%!online                    -- List online Webchat users\n'
            '```'
        )

    async def command_whisper(self, member, argstr):
        args = argstr.split(',', 1)
        if len(args) != 2:
            await member.send('Usage: `%!whisper username, message`')
            return
        username = args[0]
        content = args[1]
        webchat_members = [
            json.loads(v.decode('utf-8'))
            for v in self.redis.hgetall('webchat-online-members').values()
        ]
        for webchat_member in webchat_members:
            if webchat_member['username'].lower() == username.lower():
                await self.publish_event('whisper', {
                    'id': str(uuid.uuid4()),
                    'content': content,
                    'target': webchat_member,
                    'author': format_user(member),
                    'created_at': time.time(),
                })
                return

        await member.send(
            f'{username} is not online, use `%!online` to see who is online.'
        )

    async def command_reply(self, member, argstr):
        username = self.last_whisper_sender.get(member.id)
        if username is None:
            await member.send(
                'I don\'t remember who sent you the last whisper, please use '
                '`!whisper username, message` instead.'
            )
            return
        webchat_members = [
            json.loads(v.decode('utf-8'))
            for v in self.redis.hgetall('webchat-online-members').values()
        ]
        for webchat_member in webchat_members:
            if webchat_member['username'].lower() == username.lower():
                await self.publish_event('whisper', {
                    'id': str(uuid.uuid4()),
                    'content': argstr,
                    'target': webchat_member,
                    'author': format_user(member),
                    'created_at': time.time(),
                })
                return

        await member.send(
            'Cannot reply because the user is no longer online, '
            'use `%!online` to see who is online.'
        )

    async def command_online(self, member, argstr):
        webchat_members = [
            json.loads(v.decode('utf-8'))['username'].capitalize()
            for v in self.redis.hgetall('webchat-online-members').values()
        ]
        member_list = '\n'.join(webchat_members)
        await member.send(f'Online Webchat users:```\n{member_list}```')

    async def command_broadcast(self, member, argstr):
        rank = format_role(member.top_role)
        if rank not in ['mod', 'crew']:
            await member.send('You do not have permission to send broadcasts.')
            return

        if self.live_channel_id:
            channel = self.get_channel(self.live_channel_id)
            embed = discord.Embed(description=argstr, colour=0xe74c3c)
            embed.set_author(name=member.display_name,
                             icon_url=member.avatar_url)
            await channel.send('Webchat Broadcast:', embed=embed)
            formatted = {
                    'id': str(uuid.uuid4()),
                    'channel': 'broadcast',
                    'content': argstr,
                    'author': format_user(member),
                    'created_at': time.time(),
            }
            await self.publish_event('broadcast', formatted)
            util.zhaddex(
                self.redis,
                'webchat-message-history',
                formatted['id'],
                config.message_history_ttl,
                json.dumps(formatted, separators=(',', ':')),
                formatted['created_at'],
                config.message_history_length
            )

    async def dispatch_command(self, member, content):
        split = content.split(' ', 1)
        command = split[0][2:]
        if not command:
            command = 'broadcast'
        command = f'command_{command}'
        argstr = ''.join(split[1:])
        if hasattr(self, command):
            coro = getattr(self, command)
        else:
            coro = self.command_help
        self._schedule_event(coro, command, member, argstr)

    async def on_private_message(self, message):
        guild = self.get_guild(int(config.discord.server_id))
        for member in guild.members:
            if member == message.author:
                if not message.content.startswith('%!'):
                    await member.send(
                        'To reply to the previous whisper use '
                        '`%!reply response`. For a list of available '
                        'commands use `%!help`'
                    )
                    return
                await self.dispatch_command(member, message.content)

    async def on_message(self, message):
        if hasattr(message, 'author') and message.author == self.user:
            return

        if message.channel.type == discord.ChannelType.private:
            await self.on_private_message(message)
            return

        if self.is_relevant_message(message):
            if message.content.startswith('%!'):
                await self.dispatch_command(message.author, message.content)
                await message.delete(delay=0)
                return

            timeout = util.shget(
                self.redis,
                'timed-out-members',
                str(message.author.id)
            )
            if timeout:
                ttl = util.shttl(
                    self.redis,
                    'timed-out-members',
                    str(message.author.id)
                )
                await message.author.send(
                    'You are still timed out. '
                    f'Please wait another {ttl} seconds.\n'
                )
                await message.delete(delay=0)
                return

            formatted = format_message(message)
            await self.publish_event('message', formatted)
            # add message to history
            util.zhaddex(
                self.redis,
                'webchat-message-history',
                formatted['id'],
                config.message_history_ttl,
                json.dumps(formatted, separators=(',', ':')),
                formatted['created_at'],
                config.message_history_length
            )

    async def on_message_edit(self, before, after):
        if self.is_relevant_message(after):
            if before.content != after.content:
                formatted = format_message(after)
                await self.publish_event('message_edit', formatted)
                # edit message in history
                util.zhmod(
                    self.redis,
                    'webchat-message-history',
                    formatted['id'],
                    formatted
                )

    async def on_message_delete(self, message):
        if self.is_relevant_message(message):
            if message.content.startswith('%!'):
                return
            message_id = str(message.id)
            await self.publish_event('message_delete', message_id)
            # remove message from history
            util.zhdel(self.redis, 'webchat-message-history', message_id)

    async def on_bulk_message_delete(self, messages):
        filtered = self.filter_messages(messages)
        if filtered:
            filtered_ids = [str(m.id) for m in filtered]
            await self.publish_event('bulk_message_delete', filtered_ids)
            # remove messages from history
            util.zhdel(self.redis, 'webchat-message-history', *filtered_ids)

    def is_live_channel_member(self, member):
        return (
            self.live_channel_id is not None and
            member in self.get_channel(self.live_channel_id).members
        )

    async def set_member_online(self, member, publish=True):
        formatted = format_user(member)
        self.redis.hset('discord-online-members',
                        member.id,
                        json.dumps(formatted,
                                   separators=(',', ':')))
        if publish:
            await self.publish_event('connect', formatted)

    async def set_member_offline(self, member, publish=True):
        self.redis.hdel('discord-online-members', member.id)
        if publish:
            await self.publish_event('disconnect', format_user(member))

    async def on_member_update(self, before, after):
        if before.status == after.status:
            return
        if self.is_live_channel_member(after):
            if after.status == discord.Status.offline:
                await self.set_member_offline(after)
            elif before.status == discord.Status.offline:
                await self.set_member_online(after)

    async def on_member_join(self, member):
        if member.status != discord.Status.offline:
            if self.is_live_channel_member(member):
                await self.set_member_online(member)

    async def on_member_remove(self, member):
        if self.redis.hexists('discord-online-members', member.id):
            await self.set_member_offline(member)


client = SticksBot()
client.run(config.discord.bot_token)
