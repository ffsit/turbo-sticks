import asyncio
import discord
import json
import pytest
import pytest_asyncio
import discord.errors
import discord.ext.test as dpytest
import discord.ext.test.backend as backend
from datetime import datetime
from unittest.mock import AsyncMock, Mock

from turbo_sticks.bot import (
    filter_emojis, format_message, format_role, format_user,
    get_epoch_from_datetime, SticksBot
)
from turbo_sticks.util import shaddex, shget


# NOTE: With the use of pytest-gevent these tests are a little suspect
#       but they appear to work with or without it for now. We definitely
#       want to replace gevent with asyncio entirely in the future though
#       to gain more confidence that everything is working correctly...


@pytest_asyncio.fixture
async def base_bot(redisdb, monkeypatch):
    # HACK: We compensate for dpytest just letting that property fail
    #       which prevents us from calling bot.close()
    monkeypatch.setattr(
        'discord.gateway.DiscordWebSocket.open',
        False
    )
    bot = SticksBot(redis=redisdb)
    bot.refresh_webhook = AsyncMock(return_value=None)
    bot.webchat_webhook = AsyncMock()
    await bot._async_setup_hook()
    dpytest.configure(bot, 0, 0, 0)
    await bot.setup_hook()
    bot._handle_ready()
    yield bot
    await dpytest.empty_queue()
    await bot.close()


@pytest_asyncio.fixture
async def guild(base_bot):
    config = dpytest.get_config()
    guild = backend.make_guild('VGA', id_num=1)
    # add bot to guild
    backend.make_member(base_bot.user, guild)
    config.guilds.append(guild)
    return guild


@pytest_asyncio.fixture
async def roles(guild):
    return dict(
        crew=backend.make_role('crew', guild, id_num=6),
        moderator=backend.make_role('moderator', guild, id_num=5),
        helper=backend.make_role('helper', guild, id_num=4),
        vip=backend.make_role('vip', guild, id_num=3),
        turbo=backend.make_role('turbo', guild, id_num=2),
        default=backend.make_role('default', guild, id_num=1),
    )


@pytest_asyncio.fixture
async def channel(base_bot, guild):
    config = dpytest.get_config()
    channel = backend.make_text_channel('live_chat', guild)
    config.channels.append(channel)
    # we may want to trigger a guild_available event instead, so we
    # properly test that code path
    base_bot.live_channel_id = channel.id
    return channel


@pytest_asyncio.fixture
async def unrelated_channel(guild):
    config = dpytest.get_config()
    channel = backend.make_text_channel('unrelated', guild)
    config.channels.append(channel)
    return channel


@pytest_asyncio.fixture
async def member(guild, roles):
    config = dpytest.get_config()
    user = backend.make_user('test', 1234)
    member = backend.make_member(user, guild, roles=[roles['turbo']])
    config.members.append(member)
    return member


@pytest_asyncio.fixture
async def moderator(guild, roles):
    config = dpytest.get_config()
    user = backend.make_user('moderator', 1337)
    member = backend.make_member(user, guild, roles=[roles['moderator']])
    config.members.append(member)
    return member


@pytest_asyncio.fixture
async def bot(base_bot, channel, member):
    yield base_bot


@pytest.fixture
def webchat(redisdb):
    # subscribe to live_chat so we can see what the bot sent
    channel = redisdb.pubsub()
    channel.subscribe('live_chat')
    # check that the redis server actually subscribed us
    message = channel.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'subscribe'
    return channel


def test_get_epoch_from_datetime():
    assert get_epoch_from_datetime(datetime(1970, 1, 1)) == 0.0
    assert get_epoch_from_datetime(datetime(2020, 1, 1)) == 1577836800.0


def test_filter_emojis():
    assert filter_emojis('hello') == 'hello'
    assert filter_emojis('hello<:emoji:1234>') == 'hello'
    assert filter_emojis('hello<:emoji:1234> hi<:emoji:5678>') == 'hello hi'


@pytest.mark.asyncio
async def test_format_role(roles):
    assert [format_role(r) for r in roles.values()] == [
        'crew',
        'mod',
        'helper',
        'vip',
        'turbo',
        'shadow'
    ]


@pytest.mark.asyncio
async def test_format_user(member, roles, monkeypatch):
    assert format_user(None) == {}
    assert format_user(member) == {
        'username': 'test',
        'discord_id': str(member.id),
        'discriminator': '1234',
        'rank': 'turbo',
        'local': False
    }

    member = backend.update_member(
        member,
        roles=[]
    )
    assert format_user(member) == {
        'username': 'test',
        'discord_id': str(member.id),
        'discriminator': '1234',
        'rank': 'shadow',
        'local': False
    }

    member = backend.update_member(
        member,
        roles=[roles['moderator'], roles['turbo']]
    )
    assert format_user(member) == {
        'username': 'test',
        'discord_id': str(member.id),
        'discriminator': '1234',
        'rank': 'mod',
        'local': False
    }
    monkeypatch.delattr('discord.member.Member.top_role')
    assert format_user(member) == {
        'username': 'test',
        'discord_id': str(member.id),
        'discriminator': '1234',
        'rank': 'shadow',
        'local': False
    }

    user = backend.make_user('bot', 1111)
    user.bot = True
    assert format_user(user) == {
        'username': 'bot',
        'discord_id': str(user.id),
        'discriminator': '1111',
        'rank': 'bot',
        'local': False
    }


@pytest.mark.asyncio
async def test_format_message(member, channel):
    # NOTE: The id_num is a snowflake, so id_num 0 corresponds
    #       to the discord epoch 1420070400.0
    message = backend.make_message(
        'hello<:emoji:1234>', member, channel, id_num=0
    )
    assert format_message(message) == {
        'id': str(message.id),
        'channel_name': 'live_chat',
        'content': 'hello',
        'author': {
            'username': 'test',
            'discord_id': str(member.id),
            'discriminator': '1234',
            'rank': 'turbo',
            'local': False
        },
        'created_at': 1420070400.0
    }


@pytest.mark.asyncio
async def test_dump_rate_limited_messages(bot):
    for _ in range(30):
        pass


@pytest.mark.asyncio
async def test_close(bot, redisdb, webchat, monkeypatch):
    # insert some data into online members to test whether it gets cleared
    redisdb.hset('discord-online-members', 'some-member', '{}')
    assert redisdb.hgetall('discord-online-members') != {}

    # we monkeypatch discord.Client.close to do nothing, since the method
    # throws an exception in dpytest
    async def noop(self):
        return

    monkeypatch.setattr('discord.Client.close', noop)
    await bot.close()
    message = webchat.parse_response(block=False, timeout=0.2)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'discord_disconnect'
    assert not event['d']
    assert redisdb.hgetall('discord-online-members') == {}


@pytest.mark.asyncio
async def test_on_webchat_message(bot, channel, redisdb):
    event = {
        'ev': 'webchat_message',
        'd': {
            'channel_name': 'live_chat',
            'username': 'webchat_user',
            'avatar_url': 'http://example.com/avatar.png',
            'content': 'hello'
        }
    }
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    assert bot.webchat_message_count == 1
    bot.webchat_webhook.send.assert_called_once_with(
        'hello',
        username='webchat_user@turbo.chat',
        avatar_url='http://example.com/avatar.png'
    )


@pytest.mark.asyncio
async def test_on_webchat_message_rate_limit(bot, channel, redisdb):
    event = {
        'ev': 'webchat_message',
        'd': {
            'channel_name': 'live_chat',
            'username': 'webchat_user',
            'avatar_url': 'http://example.com/avatar.png',
            'content': 'hello'
        }
    }
    # let's not do too much work inside the loop
    payload = json.dumps(event).encode('utf-8')
    for _ in range(30):
        redisdb.publish('sticks-bot', payload)
    await asyncio.sleep(0.1)
    assert bot.webchat_message_count == 26
    assert bot.webchat_webhook.send.call_count == 26
    assert bot.rate_limited_messages.qsize() == 4

    # just so we don't have to wait 15 seconds we'll trigger the dump
    # of rate limited messages
    await bot.dump_rate_limited_messages()
    message = dpytest.get_message()
    assert message.channel == channel
    assert 'Rate limited webchat messages:\n' in message.content
    # header + 4 rate limited message
    assert len(message.content.splitlines()) == 5
    # this does not get reset by dumping
    assert bot.webchat_message_count == 27

    # but after 60 seconds it would be using this loop
    await bot.reset_rate_limit_loop()
    assert bot.webchat_message_count == 0


@pytest.mark.asyncio
async def test_on_webchat_broadcast(bot, channel, redisdb):
    event = {
        'ev': 'webchat_broadcast',
        'd': {
            'username': 'webchat_user',
            'avatar_url': 'http://example.com/avatar.png',
            'content': 'broadcast content'
        }
    }
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    assert bot.webchat_message_count == 1
    message = dpytest.get_message()
    assert message.channel == channel
    assert message.content == 'Webchat Broadcast:'
    embed = message.embeds[0]
    assert embed.description == 'broadcast content'
    assert embed.author.name == 'webchat_user@turbo.chat'
    assert embed.author.icon_url == 'http://example.com/avatar.png'


@pytest.mark.asyncio
async def test_on_webchat_whisper(bot, member, redisdb):
    event = {
        'ev': 'webchat_whisper',
        'd': {
            'target_id': str(member.id),
            'username': 'webchat_user',
            'avatar_url': 'http://example.com/avatar.png',
            'rank': 'turbo',
            'content': 'whisper content'
        }
    }
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    message = dpytest.get_message()
    assert message.channel == member.dm_channel
    assert message.content == ''
    embed = message.embeds[0]
    assert embed.description == 'whisper content'
    assert embed.author.name == 'webchat_user@turbo.chat whispers:'
    assert embed.author.icon_url == 'http://example.com/avatar.png'
    assert bot.last_whisper_sender[member.id] == 'webchat_user'


@pytest.mark.asyncio
async def test_on_webchat_timeout_member(bot, member, redisdb):
    event = {
        'ev': 'webchat_timeout_member',
        'd': {
            'member': format_user(member),
            'reason': '',
        }
    }
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    message = dpytest.get_message()
    assert message.channel == member.dm_channel
    assert 'You have been timed out.\n' in message.content
    assert 'Please wait 300 seconds.' in message.content


@pytest.mark.asyncio
async def test_on_webchat_timeout_member_reason(bot, member, redisdb):
    event = {
        'ev': 'webchat_timeout_member',
        'd': {
            'member': format_user(member),
            'reason': 'because',
        }
    }
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    message = dpytest.get_message()
    assert message.channel == member.dm_channel
    assert 'You have been timed out. Reason: because\n' in message.content
    assert 'Please wait 300 seconds.' in message.content


@pytest.mark.asyncio
async def test_on_webchat_ban_member(bot, member, redisdb, monkeypatch):
    event = {
        'ev': 'webchat_ban_member',
        'd': {
            'member': format_user(member),
            'reason': '',
        }
    }
    ban = AsyncMock()
    monkeypatch.setattr('discord.member.Member.ban', ban)
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    message = dpytest.get_message()
    assert message.channel == member.dm_channel
    assert message.content == 'You have been banned.'
    member.ban.assert_called_once_with(reason='')


@pytest.mark.asyncio
async def test_on_webchat_ban_member_reason(bot, member, redisdb, monkeypatch):
    event = {
        'ev': 'webchat_ban_member',
        'd': {
            'member': format_user(member),
            'reason': 'because',
        }
    }
    ban = AsyncMock()
    monkeypatch.setattr('discord.member.Member.ban', ban)
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    message = dpytest.get_message()
    assert message.channel == member.dm_channel
    assert message.content == 'You have been banned. Reason: because'
    member.ban.assert_called_once_with(reason='because')


@pytest.mark.asyncio
async def test_on_webchat_unban_member(bot, member, redisdb, monkeypatch):
    event = {
        'ev': 'webchat_unban_member',
        'd': {
            'member': format_user(member),
            'reason': '',
        }
    }
    unban = AsyncMock()
    monkeypatch.setattr('discord.member.Member.unban', unban)
    redisdb.publish('sticks-bot', json.dumps(event))
    await asyncio.sleep(0.1)
    message = dpytest.get_message()
    assert message.channel == member.dm_channel
    assert message.content == 'Your timeout has been lifted.'
    member.unban.assert_called_once_with(reason='')


@pytest.mark.asyncio
async def test_on_webchat_invalid(bot, redisdb, caplog):
    redisdb.publish('sticks-bot', b'garbage[')
    await asyncio.sleep(0.1)
    assert 'Received invalid message' in caplog.text


# NOTE: we use the help command to test general behavior of where users
#       can write commands to and whether the message will get deleted
#       we won't be as thorough with the other commands, we just make
#       sure they do what they are supposed to do in the channel case.
@pytest.mark.asyncio
@pytest.mark.flaky
async def test_command_help(bot, member, channel, unrelated_channel):
    # writing a command in #live_channel should work, the bot
    # should delete the message afterwards
    message = await dpytest.message('%!help')
    response = dpytest.get_message()
    assert response.channel == member.dm_channel
    assert 'Available commands: ```' in response.content
    # NOTE: flakyness forces us to sleep here
    await asyncio.sleep(0.01)
    with pytest.raises(discord.errors.NotFound):
        await channel.fetch_message(message.id)

    # dm's should also work and won't get deleted
    dm = await dpytest.message('%!help', channel=member.dm_channel)
    response = dpytest.get_message()
    assert response.channel == member.dm_channel
    assert 'Available commands: ```' in response.content
    # NOTE: flakyness forces us to sleep here
    await asyncio.sleep(0.01)
    assert await member.dm_channel.fetch_message(dm.id) == dm

    # unrelated channels should not trigger a response
    await dpytest.message('%!help', channel=unrelated_channel)
    with pytest.raises(asyncio.QueueEmpty):
        dpytest.get_message()


@pytest.mark.asyncio
async def test_command_invalid(bot, member):
    await dpytest.message('%!invalid')
    response = dpytest.get_message()
    assert response.channel == member.dm_channel
    assert 'Available commands: ```' in response.content


@pytest.mark.asyncio
async def test_command_whisper(bot, redisdb, webchat):
    await dpytest.message('%!whisper')
    response = dpytest.get_message().content
    assert response == 'Usage: `%!whisper username, message`'

    await dpytest.message('%!whisper admin, hi offline')
    response = dpytest.get_message().content
    assert 'admin is not online' in response

    # insert admin as online webchat user
    redisdb.hset('webchat-online-members', '1', json.dumps({
        'username': 'admin',
        'discord_id': '',
        'discriminator': '',
        'rank': 'admin',
        'local': True
    }))

    await dpytest.message('%!whisper admin, hi')
    message = webchat.parse_response(block=False, timeout=0.2)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'whisper'
    data = event['d']
    assert data['content'] == 'hi'
    assert data['target']['username'] == 'admin'
    assert data['author']['username'] == 'test'

    # this ensures we run the pending on_delete and avoid a warning
    await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_command_reply(bot, member, redisdb, webchat):
    await dpytest.message('%!reply hello forgetful')
    response = dpytest.get_message().content
    assert 'I don\'t remember who' in response

    # if a member dm's the bot we assumed they meant to reply
    await dpytest.message('hello', channel=member.dm_channel)
    response = dpytest.get_message().content
    assert 'To reply to the previous whisper' in response

    bot.last_whisper_sender[member.id] = 'admin'
    await dpytest.message('%!reply hello offline')
    response = dpytest.get_message().content
    assert 'Cannot reply because the user is no longer online' in response

    # insert admin as online webchat user
    redisdb.hset('webchat-online-members', '1', json.dumps({
        'username': 'admin',
        'discord_id': '',
        'discriminator': '',
        'rank': 'admin',
        'local': True
    }))

    await dpytest.message('%!reply hello')
    message = webchat.parse_response(block=False, timeout=0.2)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'whisper'
    data = event['d']
    assert data['content'] == 'hello'
    assert data['target']['username'] == 'admin'
    assert data['author']['username'] == 'test'

    # this ensures we run the pending on_delete and avoid a warning
    await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_command_online(bot, redisdb):
    await dpytest.message('%!online')
    response = dpytest.get_message().content
    assert response == 'No Webchat users online'

    redisdb.hset('webchat-online-members', '1', json.dumps({
        'username': 'admin',
        'discord_id': '',
        'discriminator': '',
        'rank': 'admin',
        'local': True
    }))
    await dpytest.message('%!online')
    response = dpytest.get_message().content
    assert response == 'Online Webchat users:```\nAdmin```'


@pytest.mark.asyncio
async def test_command_broadcast(bot, channel, moderator, redisdb, webchat):
    await dpytest.message('%!broadcast not allowed')
    response = dpytest.get_message().content
    assert 'You do not have permission' in response

    await dpytest.message('%!broadcast important', member=moderator)
    # discord broadcast
    response = dpytest.get_message()
    assert response.content == 'Webchat Broadcast:'
    assert response.embeds[0].description == 'important'
    assert response.embeds[0].author.name == 'moderator'
    assert response.embeds[0].author.icon_url == str(moderator.avatar)
    # webchat broadcast
    message = webchat.parse_response(block=False, timeout=0.2)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'broadcast'
    data = event['d']
    assert data['channel_name'] == 'broadcast'
    assert data['content'] == 'important'
    assert data['author']['username'] == 'moderator'
    # message history
    assert json.loads(shget(
        redisdb, 'webchat-message-history', data['id']
    ).decode('utf-8')) == data


@pytest.mark.asyncio
async def test_command_broadcast_shortcut(bot, channel, moderator):
    await dpytest.message('%! not allowed')
    response = dpytest.get_message().content
    assert 'You do not have permission' in response

    await dpytest.message('%! important', member=moderator)
    # discord broadcast
    response = dpytest.get_message()
    assert response.content == 'Webchat Broadcast:'


@pytest.mark.asyncio
@pytest.mark.flaky
async def test_on_message(bot, channel, redisdb, webchat):
    # this message should not get deleted
    msg = await dpytest.message('hello')
    # NOTE: flakyness forces us to sleep here
    await asyncio.sleep(0.01)
    assert await channel.fetch_message(msg.id) == msg

    # and get forwarded to webchat
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'message'
    data = event['d']
    assert data['id'] == str(msg.id)
    assert data['channel_name'] == 'live_chat'
    assert data['content'] == 'hello'
    assert data['author']['username'] == 'test'

    # and got added to history
    assert json.loads(shget(
        redisdb, 'webchat-message-history', msg.id
    ).decode('utf-8')) == data


@pytest.mark.asyncio
@pytest.mark.flaky
async def test_on_message_timed_out(bot, channel, member, redisdb, webchat):
    # time out member
    shaddex(redisdb, 'timed-out-members', str(member.id), 60, b'data')

    # this message should get deleted, because member is timed out
    message = await dpytest.message('hello')
    response = dpytest.get_message()
    assert response.channel == member.dm_channel
    assert 'You are still timed out.' in response.content
    # NOTE: flakyness forces us to sleep here
    await asyncio.sleep(0.01)
    with pytest.raises(discord.errors.NotFound):
        await channel.fetch_message(message.id)

    # and not get forwarded to webchat
    assert webchat.parse_response(block=False, timeout=0.1) is None

    # and did not get added to history
    assert shget(redisdb, 'webchat-message-history', message.id) is None


async def edit_message(message, **fields):
    # HACK: This gets around there not being a proper edit_message method
    state = backend.get_state()
    data = backend.facts.dict_from_message(message)
    data['channel_id'] = message.channel.id
    data.update(**fields)
    state.parse_message_update(data)
    await dpytest.run_all_events()


@pytest.mark.asyncio
async def test_on_message_edit(bot, channel, redisdb, webchat):
    original = await dpytest.message('hello')
    # original message being sent to webchat
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'message'

    await edit_message(original, content='edited')
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'message_edit'
    data = event['d']
    assert data['id'] == str(original.id)
    assert data['author']['username'] == 'test'
    assert data['content'] == 'edited'

    # ensure message got edited in history as well
    assert json.loads(shget(
        redisdb, 'webchat-message-history', original.id
    ).decode('utf-8')) == data


@pytest.mark.asyncio
async def test_on_raw_message_delete(bot, redisdb, webchat):
    original = await dpytest.message('hello')
    # original message being sent to webchat
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'message'

    backend.delete_message(original)
    await dpytest.run_all_events()

    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'message_delete'
    assert event['d'] == str(original.id)

    # ensure message got deleted in history
    assert shget(redisdb, 'webchat-message-history', original.id) is None

    # TODO: Test ignore on delete


@pytest.mark.asyncio
async def test_bulk_message_delete(bot, guild, channel, member, redisdb,
                                   webchat):
    messages = [
        await dpytest.message('hello'),
        await dpytest.message('hi'),
    ]
    # skip webchat events for the two messages being sent
    webchat.parse_response(block=False, timeout=0.1)
    webchat.parse_response(block=False, timeout=0.1)

    # we trigger the bulk event manually in this case for simplicity
    await bot.on_raw_bulk_message_delete(discord.RawBulkMessageDeleteEvent({
        'ids': [str(message.id) for message in messages],
        'channel_id': str(channel.id),
        'guild_id': str(guild.id),
    }))

    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'bulk_message_delete'
    assert event['d'] == [str(messages[0].id), str(messages[1].id)]

    assert shget(redisdb, 'webchat-message-history', messages[0].id) is None
    assert shget(redisdb, 'webchat-message-history', messages[1].id) is None


@pytest.mark.asyncio
async def test_on_guild_available(bot, guild, channel, member, monkeypatch,
                                  redisdb, webchat):
    # let's pretend all members are online
    monkeypatch.setattr('discord.member.Member.status', discord.Status.online)
    bot.webchat_heartbeat.start = Mock()
    unrelated_guild = backend.make_guild('Unrelated')
    bot.live_channel_id = 0
    # TODO: Trigger availability update through backend
    await bot.on_guild_available(unrelated_guild)
    assert bot.live_channel_id == 0
    assert sum(1 for _ in bot.tree.walk_commands()) == 0
    bot.webchat_heartbeat.start.assert_not_called()

    await bot.on_guild_available(guild)
    assert bot.live_channel_id == channel.id
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'discord_connect'
    data = event['d']
    assert str(member.id) in data['members']
    assert redisdb.hget('discord-online-members', str(member.id)) is not None
    bot.webchat_heartbeat.start.assert_called_once()


@pytest.mark.asyncio
async def test_on_guild_unavailable(bot, guild, channel, member, redisdb,
                                    webchat):
    # let's populate discord-online-members without triggering an event
    await bot.set_member_online(member, publish=False)
    bot.webchat_heartbeat.cancel = Mock()
    unrelated_guild = backend.make_guild('Unrelated')
    # TODO: Trigger availability update through backend
    await bot.on_guild_unavailable(unrelated_guild)
    assert bot.live_channel_id == channel.id
    assert redisdb.hgetall('discord-online-members') != {}
    bot.webchat_heartbeat.cancel.assert_not_called()

    await bot.on_guild_unavailable(guild)
    assert sum(1 for _ in bot.tree.walk_commands()) == 0
    assert bot.live_channel_id == channel.id
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'discord_disconnect'
    assert not event['d']
    assert redisdb.hgetall('discord-online-members') == {}
    bot.webchat_heartbeat.cancel.assert_called_once()


async def update_presence(bot, member, status):
    # HACK: This gets around there not being a proper presence update method
    state = backend.get_state()
    data = backend.facts.dict_from_member(member)
    data['status'] = status.name
    data['client_status'] = {'desktop': status.name}
    data['activities'] = []
    state.parse_presence_update(data)
    await dpytest.run_all_events()


@pytest.mark.asyncio
async def test_on_member_update(bot, channel, member, redisdb, webchat):
    # NOTE: Test members always start out as offline
    await update_presence(bot, member, discord.Status.online)
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'connect'
    data = event['d']
    assert data['username'] == 'test'
    assert data['discord_id'] == str(member.id)
    assert redisdb.hget('discord-online-members', str(member.id)) is not None

    await update_presence(bot, member, discord.Status.offline)
    assert member.status == discord.Status.offline
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'disconnect'
    data = event['d']
    assert data['username'] == 'test'
    assert data['discord_id'] == str(member.id)
    assert redisdb.hget('discord-online-members', str(member.id)) is None


@pytest.mark.asyncio
async def test_on_member_remove_offline(bot, member, redisdb, webchat):
    backend.delete_member(member)
    await dpytest.run_all_events()
    assert webchat.parse_response(block=False, timeout=0.1) is None
    assert redisdb.hget('discord-online-members', str(member.id)) is None


@pytest.mark.asyncio
async def test_on_member_remove(bot, channel, member, redisdb, webchat):
    await update_presence(bot, member, discord.Status.online)
    # skip connect message
    webchat.parse_response(block=False, timeout=0.1)

    backend.delete_member(member)
    await dpytest.run_all_events()
    message = webchat.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'message'
    event = json.loads(message[2].decode('utf-8'))
    assert event['ev'] == 'disconnect'
    data = event['d']
    assert data['username'] == 'test'
    assert data['discord_id'] == str(member.id)
    assert redisdb.hget('discord-online-members', str(member.id)) is None
