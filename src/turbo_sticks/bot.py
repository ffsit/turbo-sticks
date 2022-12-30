from __future__ import annotations

import asyncio
import discord
import json
import logging
import re
import time
import uuid
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from discord import app_commands
from discord.ext import tasks
from itertools import islice
from redis import Redis
from typing import Any, TYPE_CHECKING

import turbo_sticks.config as config
import turbo_sticks.util as util

if TYPE_CHECKING:
    from redis.client import PubSub
    from .types import FormattedMember, FormattedMessage, Rank


logger = logging.getLogger('discord')
webchat_roles: list[Rank] = ['crew', 'mod', 'helper', 'vip', 'turbo']
_emoji_regex = re.compile(r'<:\w+:\d+>')


def get_epoch_from_datetime(dt: datetime) -> float:
    epoch = datetime.utcfromtimestamp(0)
    assert epoch.tzinfo is None
    if dt.tzinfo is not None:
        # if we get a tz-aware dt we need to specify that our epoch is in UTC
        epoch = epoch.replace(tzinfo=timezone.utc)
    return (dt - epoch) / timedelta(seconds=1)


def filter_emojis(content: str) -> str:
    return _emoji_regex.sub('', content)


def format_role(role: discord.Role) -> Rank:
    for webchat_role in webchat_roles:
        if role.name.lower().startswith(webchat_role):
            return webchat_role
    return 'shadow'


def format_user(
    user: discord.Member | discord.User | None
) -> FormattedMember:

    if user is None:
        return {}
    rank: Rank = 'shadow'
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


def format_message(message: discord.Message) -> FormattedMessage:
    assert isinstance(message.channel, discord.TextChannel)
    author = message.author if hasattr(message, 'author') else None
    return {
        'id': str(message.id),
        'channel_name': message.channel.name,
        'content': filter_emojis(message.clean_content),
        'author': format_user(author),
        'created_at': get_epoch_from_datetime(message.created_at)
    }


# NOTE: For simplicity's sake the connection to Redis is not fully asynchronous
#       this could potentially lead to timeouts, but for how little traffic is
#       to be expected with a couple of channels with a few dozen users, this
#       should be fine.
class SticksBot(discord.Client):
    webchat_webhook:       discord.webhook.Webhook
    pubsub:                PubSub
    live_channel_id:       int
    last_whisper_sender:   dict[int, str]
    rate_limited_messages: asyncio.Queue[tuple[str, str]]
    ignore_on_delete:      set[int]

    def __init__(
        self,
        *,
        redis: Redis[bytes] | None = None
    ) -> None:

        intents = discord.Intents(
            guilds=True,
            members=True,
            messages=True,
            message_content=True,
            presences=True,
        )
        super().__init__(intents=intents)
        if redis is None:
            redis = Redis.from_url(config.redis_uri)
        self.live_channel_id = 0
        self.last_whisper_sender = {}
        self.redis = redis
        self.redis_loop_lock = asyncio.Lock()
        self.webchat_webhook_lock = asyncio.Lock()
        self.webchat_message_count = 0
        self.rate_limited_messages = asyncio.Queue()
        self.ignore_on_delete = set()
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        self.redis_loop.start()
        self.refresh_webhook_loop.start()
        self.dump_rate_limited_messages.start()
        self.reset_rate_limit_loop.start()

    async def init_slash_commands(self, guild: discord.Guild) -> None:
        self.tree.clear_commands(guild=guild)

        async def username_autocomplete(
            interaction: discord.Interaction,
            current: str
        ) -> list[app_commands.Choice[str]]:

            usernames: Iterable[str] = (
                member['username']
                for v in self.redis.hgetall('webchat-online-members').values()
                if (member := json.loads(v.decode('utf-8')))
            )

            if current:
                search = current.lower()

                # count how similar this is to the search, the better the match
                # the lower the value, so it will sort correctly ascending
                def leading_match(name: str) -> int:
                    for idx, (c1, c2) in enumerate(zip(name.lower(), search)):
                        if c1 != c2:
                            return -idx
                    return 1

                usernames = sorted(
                    (name for name in usernames if search in name.lower()),
                    # sort by quality of match and then alphabetically
                    key=lambda name: (leading_match(name), name)
                )
            else:
                usernames = sorted(usernames)

            return [
                app_commands.Choice(name=username, value=username)
                for username in islice(usernames, 0, 25)
            ]

        @self.tree.command(
            guild=guild,
            description='Whisper to a webchat user'
        )
        @app_commands.autocomplete(username=username_autocomplete)
        @app_commands.default_permissions(send_messages=True)
        async def whisper(
            context: discord.Interaction,
            username: str,
            message: str
        ) -> None:

            member = context.user
            assert isinstance(member, discord.Member)
            if await self.do_whisper(member, username, message):
                await context.response.send_message(
                    '✓',
                    ephemeral=True,
                    delete_after=15,
                )
            else:
                await context.response.send_message(
                    f'{username} is not online, use `/online` to '
                    'see who is online.',
                    ephemeral=True,
                    delete_after=60,
                )

        @self.tree.command(
            guild=guild,
            description='Reply to the last webchat whisper you received'
        )
        @app_commands.default_permissions(send_messages=True)
        async def reply(
            context: discord.Interaction,
            message: str
        ) -> None:

            member = context.user
            assert isinstance(member, discord.Member)
            username = self.last_whisper_sender.get(member.id)
            if username is None:
                await context.response.send_message(
                    'I don\'t remember who sent you the last whisper, please '
                    'use `/whisper username message` instead.',
                    ephemeral=True,
                    delete_after=60,
                )
                return

            if await self.do_whisper(member, username, message):
                await context.response.send_message(
                    '✓',
                    ephemeral=True,
                    delete_after=15
                )
            else:
                await context.response.send_message(
                    'Cannot reply because the user is no longer online, '
                    'use `/online` to see who is online.',
                    ephemeral=True,
                    delete_after=60,
                )

        @self.tree.command(
            guild=guild,
            description='Show who\'s online in the webchat'
        )
        @app_commands.default_permissions(send_messages=True)
        async def online(context: discord.Interaction) -> None:
            member = context.user
            assert isinstance(member, discord.Member)
            await context.response.send_message(
                self.format_online_webchat_members(),
                ephemeral=True
            )

        @self.tree.command(
            guild=guild,
            description='Send an important message to everyone '
                        'without it popping up on the show.'
        )
        @app_commands.default_permissions(moderate_members=True)
        async def broadcast(
            context: discord.Interaction,
            message: str
        ) -> None:

            member = context.user
            assert isinstance(member, discord.Member)
            error_response = await self.do_broadcast(member, message)
            if error_response is None:
                await context.response.send_message(
                    '✓',
                    ephemeral=True,
                    delete_after=15
                )
            else:
                await context.response.send_message(
                    error_response,
                    ephemeral=True,
                    delete_after=60,
                )

        if self.application_id is not None:  # pragma: no cover
            await self.tree.sync(guild=guild)

    def redis_next_message(self) -> list[bytes]:
        return self.pubsub.parse_response(False)

    @tasks.loop(seconds=0.1)
    async def redis_loop(self) -> None:
        if self.redis_loop_lock.locked():
            return
        async with self.redis_loop_lock:
            for message in iter(self.redis_next_message, None):
                try:
                    if message[0] != b'message':
                        continue
                    payload = json.loads(message[2].decode('utf-8'))
                    event = payload['ev']
                    kwargs = payload.get('d', {})
                    logger.debug(f'Received event {event} from webchat.')
                    self.dispatch(event, **kwargs)
                except (json.JSONDecodeError, KeyError):
                    logger.error('Received invalid message from webchat.')

    @redis_loop.before_loop
    async def before_redis_loop(self) -> None:
        await self.wait_until_ready()
        self.pubsub = self.redis.pubsub()
        self.pubsub.subscribe('sticks-bot')

    @tasks.loop(seconds=4.0)
    async def webchat_heartbeat(self) -> None:
        self.redis.set('sticks-bot-heartbeat', time.time())

    @webchat_heartbeat.before_loop
    async def before_webchat_heartbeat(self) -> None:
        await self.wait_until_ready()

    async def refresh_webhook(self) -> None:
        async with self.webchat_webhook_lock:
            if not self.live_channel_id:
                return

            channel = self.get_channel(self.live_channel_id)
            assert isinstance(channel, discord.TextChannel)
            # clean up old webhooks
            webhooks = await channel.webhooks()
            for webhook in webhooks:
                if (
                    webhook.name and
                    webhook.name.startswith('WEBCHAT-') and
                    webhook.user == self.user
                ):
                    await webhook.delete()

            # create new webhook
            webhook_name = f'WEBCHAT-{channel.name}'
            webhook = await channel.create_webhook(name=webhook_name)
            self.webchat_webhook = webhook

    @tasks.loop(seconds=config.discord.webhook_refresh_interval)
    async def refresh_webhook_loop(self) -> None:
        await self.refresh_webhook()

    @refresh_webhook_loop.before_loop
    async def before_refresh_webhook(self) -> None:
        await self.wait_until_ready()

    @tasks.loop(seconds=15)
    async def dump_rate_limited_messages(self) -> None:
        async with self.webchat_webhook_lock:
            if not self.live_channel_id:
                return

            channel = self.get_channel(self.live_channel_id)
            assert isinstance(channel, discord.TextChannel)
            messages = []
            while not self.rate_limited_messages.empty():
                try:
                    message = self.rate_limited_messages.get_nowait()
                    messages.append(message)
                    self.rate_limited_messages.task_done()
                except asyncio.QueueEmpty:
                    break

            if not messages:
                return

            formatted = '\n'.join(f'**{u}**\u2000{m}' for u, m in messages)
            await channel.send(
                f'Rate limited webchat messages:\n>>> {formatted}'
            )
            self.webchat_message_count += 1

    @dump_rate_limited_messages.before_loop
    async def before_dump_rate_limited_messages(self) -> None:
        await self.wait_until_ready()

    @tasks.loop(seconds=60)
    async def reset_rate_limit_loop(self) -> None:
        async with self.webchat_webhook_lock:
            self.webchat_message_count = 0

    async def publish_event(
        self,
        event: str,
        data:  Any = None  # FIXME: this is a bit lax
    ) -> None:

        payload = {
            'ev': event,
            'd': data or {},
        }
        self.redis.publish(config.discord.live_channel,
                           json.dumps(payload, separators=(',', ':')))

    async def close(self) -> None:
        # clear the commands
        guild = self.get_guild(int(config.discord.server_id))
        if guild is not None:
            self.tree.clear_commands(guild=guild)
            self.tree.clear_commands(guild=None)
            if self.application_id is not None:  # pragma: no cover
                await self.tree.sync(guild=guild)
                await self.tree.sync()
        # tell webchat the discord bot disconnected
        await self.publish_event('discord_disconnect')
        self.redis.delete('discord-online-members')
        # cancel all pending tasks
        self.redis_loop.cancel()
        self.refresh_webhook_loop.cancel()
        self.dump_rate_limited_messages.cancel()
        self.reset_rate_limit_loop.cancel()
        await super().close()

    def get_rank_colour(
        self,
        guild: discord.Guild,
        rank: str
    ) -> discord.Colour | None:

        for role in guild.roles:
            if rank in role.name.lower():
                return role.colour
        return None

    async def on_webchat_message(
        self,
        channel_name: str,
        username:     str,
        avatar_url:   str,
        content:      str
    ) -> None:

        if username[-5:-4] != '#':
            username += config.discord.webchat_user_suffix

        async with self.webchat_webhook_lock:
            # NOTE: The actual limit is 30 messages per minute, but we leave
            #       some headroom so mods can still do a broadcast and so the
            #       bot can dump rate limited messages before the minute is up
            if self.webchat_message_count < 26:
                self.webchat_message_count += 1
                await self.webchat_webhook.send(content, username=username,
                                                avatar_url=avatar_url)
            else:
                self.rate_limited_messages.put_nowait((username, content))

    async def on_webchat_broadcast(
        self,
        username:   str,
        avatar_url: str,
        content:    str
    ) -> None:

        if not self.live_channel_id:
            return None

        if username[-5:-4] != '#':
            username += config.discord.webchat_user_suffix

        channel = self.get_channel(self.live_channel_id)
        assert isinstance(channel, discord.TextChannel)
        embed = discord.Embed(description=content, colour=0xe74c3c)
        embed.set_author(name=username,
                         icon_url=avatar_url)
        async with self.webchat_webhook_lock:
            self.webchat_message_count += 1
            await channel.send('Webchat Broadcast:', embed=embed)

    async def on_webchat_whisper(
        self,
        target_id:  str,
        username:   str,
        avatar_url: str,
        rank:       str,
        content:    str
    ) -> None:

        guild = self.get_guild(int(config.discord.server_id))
        if not guild:
            return None

        member = guild.get_member(int(target_id))
        if not member:
            return None

        self.last_whisper_sender[member.id] = username
        embed = discord.Embed(
            description=content,
            colour=self.get_rank_colour(guild, rank) or 0,
        )
        if username[-5:-4] != '#':
            username += config.discord.webchat_user_suffix
        embed.set_author(name=f'{username} whispers:', icon_url=avatar_url)
        await member.send('', embed=embed)

    async def on_webchat_timeout_member(
        self,
        member: FormattedMember,
        reason: str = ''
    ) -> None:

        guild = self.get_guild(int(config.discord.server_id))
        if not guild:
            return None

        discord_id = member['discord_id']
        assert discord_id is not None
        _member = guild.get_member(int(discord_id))
        if not _member:
            return None

        if reason:
            reason = f' Reason: {reason}'
        await _member.send(
            f'You have been timed out.{reason}\n'
            'Your messages won\'t appear in the webchat or on show. '
            f'Please wait {config.webchat.timeout_duration} seconds.\n'
        )

    async def on_webchat_ban_member(
        self,
        member: FormattedMember,
        reason: str = ''
    ) -> None:

        guild = self.get_guild(int(config.discord.server_id))
        if not guild:
            return None

        discord_id = member['discord_id']
        assert discord_id is not None
        _member = guild.get_member(int(discord_id))
        if not _member:
            return None

        await _member.ban(reason=reason)
        if reason:
            reason = f' Reason: {reason}'
        await _member.send(f'You have been banned.{reason}')

    async def on_webchat_unban_member(
        self,
        member: FormattedMember,
        reason: str = ''
    ) -> None:

        guild = self.get_guild(int(config.discord.server_id))
        if not guild:
            return None

        discord_id = member['discord_id']
        assert discord_id is not None
        _member = guild.get_member(int(discord_id))
        if not _member:
            return None

        await _member.unban(reason=reason)
        await _member.send('Your timeout has been lifted.')

    async def command_help(self, member: discord.Member, argstr: str) -> None:
        await member.send(
            'Available commands: ```\n'
            '%![command] [arg1], [arg2]  -- [Command description]\n'
            '%!reply message             -- Reply to the last private message '
            'you received\n'
            '%!whisper username, message -- Whisper to a webchat user\n'
            '%!online                    -- List online Webchat users\n'
            '```'
        )

    async def do_whisper(
        self,
        member: discord.Member,
        username: str,
        content: str
    ) -> bool:

        webchat_members = (
            json.loads(v.decode('utf-8'))
            for v in self.redis.hgetall('webchat-online-members').values()
        )
        for webchat_member in webchat_members:
            if webchat_member['username'].lower() == username.lower():
                await self.publish_event('whisper', {
                    'id': str(uuid.uuid4()),
                    'content': content,
                    'target': webchat_member,
                    'author': format_user(member),
                    'created_at': time.time(),
                })
                return True
        return False

    async def command_whisper(
        self,
        member: discord.Member,
        argstr: str
    ) -> None:

        args = argstr.split(',', 1)
        if len(args) != 2:
            await member.send('Usage: `%!whisper username, message`')
            return
        username = args[0]
        content = args[1].strip()
        if await self.do_whisper(member, username, content) is False:
            await member.send(
                f'{username} is not online, use `%!online` to '
                'see who is online.'
            )

    async def command_reply(self, member: discord.Member, argstr: str) -> None:
        username = self.last_whisper_sender.get(member.id)
        if username is None:
            await member.send(
                'I don\'t remember who sent you the last whisper, please use '
                '`!whisper username, message` instead.'
            )
            return

        if await self.do_whisper(member, username, argstr) is False:
            await member.send(
                'Cannot reply because the user is no longer online, '
                'use `%!online` to see who is online.'
            )

    def format_online_webchat_members(self) -> str:
        members = (
            json.loads(v.decode('utf-8'))
            for v in self.redis.hgetall('webchat-online-members').values()
        )
        member_list = '\n'.join(m['username'].capitalize() for m in members)
        if not member_list:
            return 'No Webchat users online'
        return f'Online Webchat users:```\n{member_list}```'

    async def command_online(
        self,
        member: discord.Member,
        argstr: str
    ) -> None:
        await member.send(self.format_online_webchat_members())

    async def do_broadcast(
        self,
        member: discord.Member,
        content: str
    ) -> str | None:

        rank = format_role(member.top_role)
        if rank not in ('mod', 'crew'):
            return 'You do not have permission to send broadcasts.'

        if not self.live_channel_id:
            return None

        channel = self.get_channel(self.live_channel_id)
        embed = discord.Embed(description=content, colour=0xe74c3c)
        embed.set_author(name=member.display_name,
                         icon_url=str(member.avatar))
        async with self.webchat_webhook_lock:
            self.webchat_message_count += 1
            assert isinstance(channel, discord.TextChannel)
            await channel.send('Webchat Broadcast:', embed=embed)

        formatted: FormattedMessage = {
                'id': str(uuid.uuid4()),
                'channel_name': 'broadcast',
                'content': content,
                'author': format_user(member),
                'created_at': time.time(),
        }
        await self.publish_event('broadcast', formatted)
        util.zhaddex(
            self.redis,
            'webchat-message-history',
            formatted['id'],
            config.webchat.history_ttl,
            json.dumps(formatted, separators=(',', ':')),
            formatted['created_at'],
            config.webchat.history_length
        )
        return None

    async def command_broadcast(
        self,
        member: discord.Member,
        argstr: str
    ) -> None:

        response = await self.do_broadcast(member, argstr)
        if response:
            await member.send(response)

    async def dispatch_command(
        self,
        member: discord.Member,
        content: str
    ) -> None:

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
        # FIXME: This uses an undocumented method without type annotations
        #        this is a bit fragile and could break with future releases
        self._schedule_event(coro, command, member, argstr)  # type:ignore

    def is_relevant_message(self, message: discord.Message) -> bool:
        if message.type != discord.MessageType.default:
            return False

        if not message.content:
            return False

        if not hasattr(message.channel, 'guild'):
            return False

        assert isinstance(message.channel, discord.TextChannel)
        if str(message.channel.guild.id) != config.discord.server_id:
            return False

        if message.channel.name != config.discord.live_channel:
            return False

        if not hasattr(message, 'author'):
            return False

        return hasattr(message.author, 'top_role')

    async def on_private_message(self, message: discord.Message) -> None:
        guild = self.get_guild(int(config.discord.server_id))
        if not guild:
            return

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

    async def on_message(self, message: discord.Message) -> None:
        if hasattr(message, 'author') and message.author == self.user:
            return

        if message.channel.type == discord.ChannelType.private:
            await self.on_private_message(message)
            return

        if not self.is_relevant_message(message):
            return

        if message.content.startswith('%!'):
            assert isinstance(message.author, discord.Member)
            await self.dispatch_command(message.author, message.content)
            self.ignore_on_delete.add(message.id)
            await message.delete(delay=0)
            return

        timeout = util.shget(
            self.redis,
            'timed-out-members',
            str(message.author.id)
        )
        if timeout:
            self.ignore_on_delete.add(message.id)
            await message.delete(delay=0)
            ttl = util.shttl(
                self.redis,
                'timed-out-members',
                str(message.author.id)
            )
            await message.author.send(
                'You are still timed out. '
                f'Please wait another {ttl or 0} seconds.\n'
            )
            return

        formatted = format_message(message)
        await self.publish_event('message', formatted)
        # add message to history
        util.zhaddex(
            self.redis,
            'webchat-message-history',
            formatted['id'],
            config.webchat.history_ttl,
            json.dumps(formatted, separators=(',', ':')),
            formatted['created_at'],
            config.webchat.history_length
        )

    async def on_message_edit(
        self,
        before: discord.Message,
        after:  discord.Message
    ) -> None:

        # NOTE: If it was relevant before it still should be now
        #       we can't check after, since some of the parameters
        #       might be missing
        if not self.is_relevant_message(before):
            return

        if before.content == after.content:
            return

        formatted = format_message(after)
        await self.publish_event('message_edit', formatted)
        # edit message in history
        util.zhmod(
            self.redis,
            'webchat-message-history',
            formatted['id'],
            json.dumps(formatted, separators=(',', ':'))
        )

    async def on_raw_message_delete(
        self,
        event: discord.RawMessageDeleteEvent
    ) -> None:

        # early out for messages deleted by the bot
        if event.message_id in self.ignore_on_delete:
            self.ignore_on_delete.discard(event.message_id)
            return

        # we only really need to check the channel_id
        if event.channel_id == self.live_channel_id:
            message_id = str(event.message_id)
            await self.publish_event('message_delete', message_id)
            # remove message from history
            util.zhdel(self.redis, 'webchat-message-history', message_id)

    async def on_raw_bulk_message_delete(
        self,
        event: discord.RawBulkMessageDeleteEvent
    ) -> None:

        if event.channel_id != self.live_channel_id:
            return

        filtered_ids = [
            str(message_id)
            for message_id in event.message_ids
            # TODO: This check is probably unnecessary, the bot itself will
            #       probably never cause a bulk delete event. If we find
            #       that it does, then we should discard the message_ids
            #       from ignore_on_delete
            if message_id not in self.ignore_on_delete
        ]
        if filtered_ids:
            await self.publish_event('bulk_message_delete', filtered_ids)
            # remove messages from history
            util.zhdel(self.redis, 'webchat-message-history', *filtered_ids)

    async def on_guild_available(self, guild: discord.Guild) -> None:
        if str(guild.id) != config.discord.server_id:
            return

        await self.refresh_webhook()
        self.redis.delete('discord-online-members')
        members = {}
        for channel in guild.channels:
            if channel.name == config.discord.live_channel:
                assert isinstance(channel, discord.TextChannel)
                self.live_channel_id = channel.id
                for member in channel.members:
                    if member.status != discord.Status.offline:
                        await self.set_member_online(member, publish=False)
                        members[str(member.id)] = format_user(member)
        self.webchat_heartbeat.start()
        await self.publish_event('discord_connect', {'members': members})
        await self.init_slash_commands(guild)

    async def on_guild_unavailable(self, guild: discord.Guild) -> None:
        if str(guild.id) == config.discord.server_id:
            await self.publish_event('discord_disconnect')
            self.redis.delete('discord-online-members')
            self.webchat_heartbeat.cancel()
            self.tree.clear_commands(guild=guild)
            if self.application_id is not None:  # pragma: no cover
                await self.tree.sync(guild=guild)

    def is_live_channel_member(self, member: discord.Member) -> bool:
        if not self.live_channel_id:
            return False

        channel = self.get_channel(self.live_channel_id)
        assert isinstance(channel, discord.TextChannel)
        return member in channel.members

    async def set_member_online(
        self,
        member: discord.Member | discord.User,
        publish: bool = True
    ) -> None:

        formatted = format_user(member)
        self.redis.hset('discord-online-members',
                        str(member.id),
                        json.dumps(formatted,
                                   separators=(',', ':')))
        if publish:
            await self.publish_event('connect', formatted)

    async def set_member_offline(
        self,
        member: discord.Member | discord.User,
        publish: bool = True
    ) -> None:

        self.redis.hdel('discord-online-members', str(member.id))
        if publish:
            await self.publish_event('disconnect', format_user(member))

    async def on_presence_update(
        self,
        before: discord.Member,
        after: discord.Member
    ) -> None:

        if before.status == after.status:
            return

        if not self.is_live_channel_member(after):
            return

        if after.status == discord.Status.offline:
            await self.set_member_offline(after)
        elif before.status == discord.Status.offline:
            await self.set_member_online(after)

    # NOTE: Currently discord.py always sets members to offline on join
    #       I assume a presence update follows separatly...
    #       But just in case this ever changes I will leave this enabled
    #       However we can't currently properly test that this would work
    #       so I'll exclude it from test coverage.
    async def on_member_join(self, member: discord.Member) -> None:
        if member.status == discord.Status.offline:
            return

        if self.is_live_channel_member(member):  # pragma: no cover
            await self.set_member_online(member)

    async def on_raw_member_remove(
        self,
        event: discord.RawMemberRemoveEvent
    ) -> None:
        if self.redis.hexists('discord-online-members', str(event.user.id)):
            await self.set_member_offline(event.user)
