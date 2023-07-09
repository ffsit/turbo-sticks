import gevent
import gevent.monkey
import json
import logging
import pytest
import tempfile
from contextlib import contextmanager
from oauthlib.oauth2 import OAuth2Error
from unittest.mock import Mock

import turbo_sticks.util as util
from turbo_sticks.db import DBError
from turbo_sticks.enums import ACL
from turbo_sticks.websockets import (
    channel_job, client_job, Channel, ClientDisconnect, ClientError,
    ClientState, ClientTimeout, DiscordChannel, init_redis_state, JobState
)
from turbo_sticks.user import User


# TODO: Do we need to tell coverage.py that we use gevent to measure coverage
#       correctly?

# NOTE: If we happen to run tests without gevent-pytest, we want to skip this
#       module, since the test results don't really reflect reality without
#       a patched socket module.
pytestmark = pytest.mark.skipif(
    not gevent.monkey.is_module_patched('socket'),
    reason="Requires using pytest-gevent"
)


@pytest.fixture
def uwsgi(monkeypatch):
    def _gid():
        return id(gevent.getcurrent())

    class MockUWSGI:
        def __init__(self):
            self.in_fds = {}
            self.out_fds = {}
            self.in_messages = {}
            self.out_messages = {}
            self.side_effects = {}

        def websocket_handshake(self):
            gid = _gid()
            tmp_file = tempfile.NamedTemporaryFile('wb')
            self.in_fds[gid] = tmp_file
            self.out_fds[gid] = open(tmp_file.name, 'rb')
            self.in_messages[gid] = b''
            self.out_messages[gid] = []

        def connection_fd(self):
            return self.out_fds[_gid()]

        def websocket_recv_nb(self):
            gid = _gid()
            if (side_effect := self.side_effects.get(gid)) is not None:
                raise side_effect
            msg = self.in_messages[gid]
            self.in_messages[gid] = b''
            return msg

        def websocket_send(self, message):
            self.out_messages[_gid()].append(message)

        def disconnect(self):
            gid = _gid()
            self.in_fds[gid].close()
            self.out_fds[gid].close()
            del self.in_fds[gid]
            del self.out_fds[gid]
            del self.in_messages[gid]
            # NOTE: We leave out_messages intact so they can be retrieved
            #       even after the disconnect
            if gid in self.side_effects:
                del self.side_effects[gid]

        def send_websocket_client_message(self, greenlet, message):
            gid = id(greenlet)
            self.in_messages[gid] = message
            # trigger select on fileno()
            self.in_fds[gid].write(message)

        def send_websocket_client_event(self, greenlet, event, data=None):
            # convenience function to make sending events a bit more simple
            payload = {'ev': event, 'd': data or {}}
            message = json.dumps(
                payload,
                separators=(',', ':')
            ).encode('utf-8')
            self.send_websocket_client_message(greenlet, message)

        def set_side_effect(self, greenlet, side_effect):
            self.side_effects[id(greenlet)] = side_effect

        def receive_websocket_server_messages(self, greenlet):
            gid = id(greenlet)
            result = self.out_messages[gid]
            self.out_messages[gid] = []
            return result

        def receive_websocket_server_events(self, greenlet):
            return [
                json.loads(msg.decode('utf-8'))
                for msg in self.receive_websocket_server_messages(greenlet)
            ]

    uwsgi = MockUWSGI()
    monkeypatch.setattr('turbo_sticks.websockets.uwsgi', uwsgi)
    yield uwsgi
    for fd in uwsgi.out_fds.values():
        fd.close()
    for fd in uwsgi.in_fds.values():
        fd.close()


@contextmanager
def cleanup_channel(channel):
    # NOTE: This ensures our tests will close the channel even if there
    #       are failures in-between. If the channel doesn't get cleaned
    #       up we get spammed by error messages from that test
    channel.spawn_jobs()
    yield
    channel.close()


@pytest.fixture
def redis(redisdb, monkeypatch):
    monkeypatch.setattr('turbo_sticks.websockets.Channel._redis', redisdb)
    init_redis_state(redisdb)
    return redisdb


@pytest.fixture
def redis_channel(redis):
    # subscribe to live_chat so we can see what the bot sent
    channel = redis.pubsub()
    channel.subscribe('test')
    # check that the redis server actually subscribed us
    message = channel.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'subscribe'
    return channel


@pytest.fixture
def bot_channel(redis):
    # subscribe to live_chat so we can see what the bot sent
    channel = redis.pubsub()
    channel.subscribe('sticks-bot')
    # check that the redis server actually subscribed us
    message = channel.parse_response(block=False, timeout=0.1)
    assert message and message[0] == b'subscribe'
    return channel


def test_client_job_no_errors(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def no_errors(c):
        return

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    no_errors(client)
    # state should remain unmodified
    assert client.state == ClientState.new
    on_error.assert_not_called()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 2
    assert 'Started greenlet no_errors' in messages[0]
    assert 'Finished greenlet no_errors' in messages[1]


def test_client_job_timeout(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def timeout(c):
        raise ClientTimeout

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    timeout(client)
    assert client.state == ClientState.suspended
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet timeout' in messages[0]
    assert 'Client timeout' in messages[1]
    assert 'Finished greenlet timeout' in messages[2]


def test_client_job_disconnect(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def disconnect(c):
        raise ClientDisconnect

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    disconnect(client)
    assert client.state == ClientState.exited
    on_error.assert_not_called()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet disconnect' in messages[0]
    assert 'Client disconnected' in messages[1]
    assert 'Finished greenlet disconnect' in messages[2]


def test_client_job_client_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def client_error(c):
        raise ClientError('Some error')

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    client_error(client)
    assert client.state == ClientState.exited
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet client_error' in messages[0]
    assert 'Client error: Some error' in messages[1]
    assert 'Finished greenlet client_error' in messages[2]


def test_client_job_db_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def db_error(c):
        raise DBError()

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    db_error(client)
    assert client.state == ClientState.exited
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet db_error' in messages[0]
    assert 'Database error occured' in messages[1]
    assert 'Finished greenlet db_error' in messages[2]


def test_client_job_oauth_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def oauth_error(c):
        raise OAuth2Error('Some error')

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    oauth_error(client)
    assert client.state == ClientState.exited
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet oauth_error' in messages[0]
    assert 'OAuth 2.0 error occured:' in messages[1]
    assert 'Some error' in messages[1]
    assert 'Finished greenlet oauth_error' in messages[2]


def test_client_job_unexpected_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)
    client = channel.add_client({})

    on_error = Mock()
    on_finish = Mock()

    @client_job(on_error=on_error, on_finish=on_finish)
    def unexpected_error(c):
        raise Exception('Some error')

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    unexpected_error(client)
    assert client.state == ClientState.exited
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet unexpected_error' in messages[0]
    assert 'Unexpected error occured: Some error' in messages[1]
    assert 'Finished greenlet unexpected_error' in messages[2]


def test_channel_job_no_errors(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)

    on_error = Mock()
    on_finish = Mock()

    @channel_job(on_error=on_error, on_finish=on_finish)
    def no_errors(c):
        return

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    no_errors(channel)
    on_error.assert_not_called()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 2
    assert 'Started greenlet no_errors' in messages[0]
    assert 'Finished greenlet no_errors' in messages[1]


def test_channel_job_db_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)

    on_error = Mock()
    on_finish = Mock()

    @channel_job(on_error=on_error, on_finish=on_finish)
    def db_error(c):
        raise DBError()

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    db_error(channel)
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet db_error' in messages[0]
    assert 'Database error occured' in messages[1]
    assert 'Finished greenlet db_error' in messages[2]


def test_channel_job_oauth_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)

    on_error = Mock()
    on_finish = Mock()

    @channel_job(on_error=on_error, on_finish=on_finish)
    def oauth_error(c):
        raise OAuth2Error('Some error')

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    oauth_error(channel)
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet oauth_error' in messages[0]
    assert 'OAuth 2.0 error occured:' in messages[1]
    assert 'Some error' in messages[1]
    assert 'Finished greenlet oauth_error' in messages[2]


def test_channel_job_unexpected_error(uwsgi, redis, caplog):
    # we don't initiate any actual greenlets
    # we just create the objects to test job functions on them
    channel = Channel('test', '/test', ACL.guest)

    on_error = Mock()
    on_finish = Mock()

    @channel_job(on_error=on_error, on_finish=on_finish)
    def unexpected_error(c):
        raise Exception('Some error')

    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    caplog.clear()
    unexpected_error(channel)
    on_error.assert_called_once_with()
    on_finish.assert_called_once_with()
    messages = caplog.messages
    assert len(messages) == 3
    assert 'Started greenlet unexpected_error' in messages[0]
    assert 'Unexpected error occured: Some error' in messages[1]
    assert 'Finished greenlet unexpected_error' in messages[2]


def test_client_init_context(uwsgi, redis, env):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        client1 = channel.add_client(env)
        client2 = channel.add_client({})
        gevent.spawn(client1.start)
        gevent.sleep(0.1)
        user = client1.context['user']
        assert user is not None
        assert user.username == 'test'
        assert client1.context['access_level'] is ACL.turbo
        gevent.spawn(client2.start)
        gevent.sleep(0.1)
        assert client2.context['user'] is None
        assert client2.context['access_level'] is ACL.guest


def test_client_suspend_resume(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        client_1 = channel.add_client({})
        orig_id = client_1.id
        greenlet_1 = gevent.spawn(client_1.start)
        uwsgi.set_side_effect(greenlet_1, IOError)
        gevent.sleep(0.01)
        assert client_1.state == ClientState.suspended
        client_2 = channel.add_client({})
        gevent.spawn(client_2.start)
        gevent.sleep(0.01)
        assert len(channel.clients) == 2
        client_2.resume(client_1)
        assert client_2.id == orig_id
        assert client_1.state == ClientState.merged
        assert len(channel.clients) == 1


def test_client_exit(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        client = channel.add_client({})
        gevent.spawn(client.start)
        gevent.sleep(0.01)
        assert redis.get('websocket-clients') == b'1'
        client.exit(timeout=5.0)
        assert client.state == ClientState.exited
        assert client.id not in channel.clients
        assert redis.get('websocket-clients') == b'0'


def test_client_disconnect(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        client = channel.add_client({})
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.01)
        assert redis.get('websocket-clients') == b'1'
        uwsgi.set_side_effect(greenlet, ClientDisconnect)
        client.join(timeout=5.0)
        assert client.state == ClientState.exited
        assert client.id not in channel.clients
        assert redis.get('websocket-clients') == b'0'


def test_get_client(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        client = channel.add_client({})
        assert channel.get_client(client.id) is client


def test_channel_insufficient_privileges(uwsgi, redis):
    channel = Channel('test', '/test')
    with cleanup_channel(channel):
        def insufficient():
            client = channel.add_client({})
            # so we don't catch the exception in the wrapper
            client.start.__wrapped__(client)
        greenlet = gevent.spawn(insufficient)

        with pytest.raises(ClientError, match=r'Insufficient privileges\.'):
            # this reraises the exception from the greenlet
            greenlet.get(timeout=5.0)


def test_channel_no_available_slots(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        # client 1
        gevent.spawn(channel.open_websocket, {})
        gevent.sleep(0.1)
        assert redis.get('websocket-clients') == b'1'
        # client 2
        gevent.spawn(channel.open_websocket, {})
        gevent.sleep(0.1)
        assert redis.get('websocket-clients') == b'2'

        # client 3 will be too many with test config
        def too_many():
            client = channel.add_client({})
            # so we don't catch the exception in the wrapper
            client.start.__wrapped__(client)
        greenlet = gevent.spawn(too_many)

        with pytest.raises(ClientError, match=r'No available slots\.'):
            # this reraises the exception from the greenlet
            greenlet.get(timeout=5.0)

        assert redis.get('websocket-clients') == b'2'


def test_channel_publish(env, uwsgi, redis_channel):
    channel = Channel('test', '/test')
    with cleanup_channel(channel):
        greenlet = gevent.spawn(channel.open_websocket, env)
        gevent.sleep(0.01)
        uwsgi.send_websocket_client_message(greenlet, b'test')
        gevent.sleep(0.01)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message' and message[2] == b'test'
        gevent.sleep(0.01)
        assert uwsgi.receive_websocket_server_messages(greenlet) == [b'test']


def test_channel_dispatch_client_message_suspended(env, uwsgi, redis_channel):
    # FIXME: It is a bit weird to test this with a single client, technically
    #        this shouldn't really work this way, if we want to be strict
    channel = Channel('test', '/test')
    with cleanup_channel(channel):
        channel.spawn_jobs()
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.01)
        client.job_state = JobState.suspended
        uwsgi.send_websocket_client_message(greenlet, b'test')
        gevent.sleep(0.01)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message' and message[2] == b'test'
        # the sending of the message has been delayed
        assert uwsgi.receive_websocket_server_messages(greenlet) == []
        gevent.sleep(0.6)
        # but now it should be here
        assert uwsgi.receive_websocket_server_messages(greenlet) == [b'test']


def test_channel_recover_jobs(uwsgi, redis_channel):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        gevent.sleep(0.01)
        channel.recover_jobs()
        client = channel.add_client({})
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.01)
        uwsgi.send_websocket_client_message(greenlet, b'test')
        gevent.sleep(0.01)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message' and message[2] == b'test'
        gevent.sleep(0.01)
        assert uwsgi.receive_websocket_server_messages(greenlet) == [b'test']


def test_channel_recover_jobs_on_error(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        channel.redis_channel = Mock(side_effect=ValueError)
        channel.recover_jobs = Mock()
        channel.spawn_jobs()
        gevent.sleep(0.01)
        channel.recover_jobs.assert_called()


def test_channel_kill_jobs(uwsgi, redis):
    channel = Channel('test', '/test', ACL.guest)
    with cleanup_channel(channel):
        gevent.sleep(0.01)
        channel.kill_jobs(timeout=5.0)
        client = channel.add_client({})
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.01)
        uwsgi.send_websocket_client_message(greenlet, b'test')
        gevent.sleep(0.01)
        # job isn't going so nothing is sent to the websocket
        assert uwsgi.receive_websocket_server_messages(greenlet) == []


def test_discord_client_init_context(uwsgi, redis, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        gevent.spawn(client.start)
        gevent.sleep(0.01)
        user = client.context['user']
        assert user is not None
        assert user.username == 'test'
        assert client.context['access_level'] is ACL.turbo
        assert client.context['connected'] is False
        assert client.context['discord_id'] is None
        assert client.context['discriminator'] is None
        assert client.context['local'] is True
        assert client.context['rank'] == 'turbo'
        assert client.context['username'] == 'test'
        assert client.context['avatar_url'] == 'http://example.com/test.png'


def test_discord_client_init_context_discord(uwsgi, redis, env, user):
    user.set_discord_id(999)
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        gevent.spawn(client.start)
        gevent.sleep(0.01)
        user = client.context['user']
        assert user is not None
        assert user.username == 'test'
        assert client.context['access_level'] is ACL.turbo
        assert client.context['connected'] is False
        assert client.context['discord_id'] == '999'
        assert client.context['discriminator'] is None
        assert client.context['local'] is True
        assert client.context['rank'] == 'turbo'
        assert client.context['username'] == 'test'
        assert client.context['avatar_url'] == 'http://example.com/test.png'


def test_discord_client_invalid_payload(uwsgi, redis, env, caplog):
    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.01)
        # send malformed json
        uwsgi.send_websocket_client_message(greenlet, b'malformed{]')
        gevent.sleep(0.1)
        assert 'Received invalid websockets payload.' in caplog.messages[-1]
        # send malformed paylod
        uwsgi.send_websocket_client_message(greenlet, b'[]')
        gevent.sleep(0.1)
        assert 'Received invalid websockets payload.' in caplog.messages[-1]
        # send invalid event type
        uwsgi.send_websocket_client_message(greenlet, b'{"ev":0}')
        gevent.sleep(0.1)
        assert 'Received invalid websockets payload.' in caplog.messages[-1]
        # send invalid data type
        uwsgi.send_websocket_client_message(greenlet, b'{"ev":"event","d":0}')
        gevent.sleep(0.1)
        assert 'Received invalid websockets payload.' in caplog.messages[-1]
        # send any event other than connect/resume before client is connected
        uwsgi.send_websocket_client_message(greenlet, b'{"ev":"message"}')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'You are not connected.'}
        # force set the client to connected
        client.context['connected'] = True
        # send a non-existent event
        uwsgi.send_websocket_client_message(greenlet, b'{"ev":"bogus"}')
        gevent.sleep(0.1)
        assert 'Received invalid event bogus.' in caplog.messages[-1]


def test_discord_client_on_connect(uwsgi, redis, redis_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        assert client.context['connected'] is True
        assert client.context.get('heartbeat') is not None
        assert client.is_alive()
        assert redis.hget('webchat-clients', 'test') == b'1'
        member = json.loads(
            redis.hget('webchat-online-members', 'test').decode('utf-8')
        )
        expected_member = client.format_user(client.context)
        assert member == expected_member
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        assert payload['d'] == expected_member
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # NOTE: The order of events can change depending on which greenlet
        #       gets control back first after yielding to send the event
        #       out to the redis channel, but we don't really care
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['hello'] == {'client_id': client.id}
        # the channel message will get distributed back to the client
        assert unordered_events['connect'] == expected_member
        data = unordered_events['connection_success']
        assert data['you'] == expected_member
        assert data['online_members'] == {
            'discord': {},
            'webchat': {'test': expected_member}
        }


def test_discord_client_on_resume(uwsgi, redis, redis_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client_1 = channel.add_client(env)
        greenlet_1 = gevent.spawn(client_1.start)
        gevent.sleep(0.1)
        # issue connect to receive hello event with client_id
        uwsgi.send_websocket_client_event(greenlet_1, 'connect')
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        events = uwsgi.receive_websocket_server_events(greenlet_1)
        assert len(events) == 3
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        orig_id = unordered_events['hello']['client_id']
        uwsgi.set_side_effect(greenlet_1, IOError)
        gevent.sleep(0.01)
        assert client_1.state == ClientState.suspended
        client_2 = channel.add_client(env)
        greenlet_2 = gevent.spawn(client_2.start)
        gevent.sleep(0.01)
        assert len(channel.clients) == 2
        # send resume event using the original client id
        uwsgi.send_websocket_client_event(
            greenlet_2,
            'resume',
            {'client_id': orig_id}
        )
        # resuming can take some time since it has to clean up the old client
        gevent.sleep(0.5)
        assert client_2.id == orig_id
        assert client_1.state == ClientState.merged
        assert len(channel.clients) == 1
        assert client_2.context['connected'] is True
        assert client_2.context.get('heartbeat') is not None
        assert client_2.is_alive()
        assert redis.hget('webchat-clients', 'test') == b'1'
        member = json.loads(
            redis.hget('webchat-online-members', 'test').decode('utf-8')
        )
        # a resume should cause neither a connect nor a disconnect to be sent
        # to the channel as a whole
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        expected_member = client_2.format_user(client_2.context)
        assert member == expected_member
        events = uwsgi.receive_websocket_server_events(greenlet_2)
        assert len(events) == 1
        assert events[0]['ev'] == 'hello'
        assert events[0]['d'] == {'client_id': orig_id}


def test_discord_client_on_disconnect(uwsgi, redis, redis_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        expected_member = client.format_user(client.context)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        assert payload['d'] == expected_member
        assert redis.hget('webchat-clients', 'test') == b'1'
        assert redis.hexists('webchat-online-members', 'test') == 1
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        uwsgi.send_websocket_client_event(greenlet, 'disconnect')
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'disconnect'
        assert payload['d'] == expected_member
        assert redis.hexists('webchat-clients', 'test') == 0
        assert redis.hexists('webchat-online-members', 'test') == 0


def test_discord_client_on_heartbeat(uwsgi, redis, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        old_heartbeat = client.context['heartbeat']
        uwsgi.send_websocket_client_event(greenlet, 'heartbeat')
        gevent.sleep(0.1)
        assert client.context['heartbeat'] > old_heartbeat
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }


def test_discord_client_on_message(uwsgi, redis_channel, bot_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        uwsgi.send_websocket_client_event(
            greenlet,
            'message',
            {'channel_name': 'live_chat', 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        expected_member = client.format_user(client.context)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'message'
        message = payload['d']
        assert message['content'] == 'hello world'
        assert message['channel_name'] == 'live_chat'
        assert message['author'] == expected_member
        expected_message = message
        message = bot_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'webchat_message'
        message = payload['d']
        assert message['channel_name'] == 'live_chat'
        assert message['username'] == 'test'
        assert message['avatar_url'] == 'http://example.com/test.png'
        assert message['content'] == 'hello world'
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert 'ack' in unordered_events
        assert unordered_events['message'] == expected_message
        assert client.get_message_history() == [expected_message]


def test_discord_client_on_message_banned(uwsgi, redis, redis_channel, env,
                                          user):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        user.ban()
        uwsgi.send_websocket_client_event(
            greenlet,
            'message',
            {'channel_name': 'live_chat', 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        expected_member = client.format_user(client.context)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'You have been banned.'}
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'disconnect'
        assert payload['d'] == expected_member
        assert redis.hexists('webchat-clients', 'test') == 0
        assert redis.hexists('webchat-online-members', 'test') == 0


@pytest.mark.flaky
def test_discord_client_on_message_timed_out(uwsgi, redis, redis_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        member = client.format_user(client.context)
        util.shaddex(
            redis,
            'timed-out-members',
            'test',
            30,
            json.dumps({'member': member}).encode('utf-8')
        )
        uwsgi.send_websocket_client_event(
            greenlet,
            'message',
            {'channel_name': 'live_chat', 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {
            'message': 'You have been timed out.',
            # NOTE: This is the flaky part, if for some reason we slept
            #       more than a second this might be down to 29 seconds
            'detail': 'You have to wait another 30 seconds.'
        }
        assert redis_channel.parse_response(block=False, timeout=0.1) is None


def test_discord_client_on_message_timed_out_reason(uwsgi, redis, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        member = client.format_user(client.context)
        util.shaddex(
            redis,
            'timed-out-members',
            'test',
            30,
            json.dumps({
                'member': member,
                'reason': 'Spoilers'
            }).encode('utf-8')
        )
        uwsgi.send_websocket_client_event(
            greenlet,
            'message',
            {'channel_name': 'live_chat', 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d']['detail'].endswith('\nReason: Spoilers')


def test_discord_client_on_whisper(uwsgi, redis_channel, bot_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        # for simplicity we whisper ourselves, technically we could just
        # whisper some non-existent account, since the existance check happens
        # client side for both webchat and discord but in practice the result
        # is the same
        member = client.format_user(client.context)
        uwsgi.send_websocket_client_event(
            greenlet,
            'whisper',
            {'member': member, 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'whisper'
        message = payload['d']
        assert message['content'] == 'hello world'
        assert message['target'] == member
        assert message['author'] == member
        expected_message = message
        # since the discord_id is not set it doesn't go to the discord bot
        assert bot_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        # since we're both the sender/recipient of the whisper we should also
        # get a client side event
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert 'ack' in unordered_events
        assert unordered_events['whisper'] == expected_message
        # whispers do not go into the message history
        assert client.get_message_history() == []


def test_discord_client_on_whisper_discord(uwsgi, redis_channel, bot_channel,
                                           env, user):
    user.set_discord_id(999)
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        member = client.format_user(client.context)
        uwsgi.send_websocket_client_event(
            greenlet,
            'whisper',
            {'member': member, 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'whisper'
        message = payload['d']
        assert message['content'] == 'hello world'
        assert message['target'] == member
        assert message['author'] == member
        message = bot_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'webchat_whisper'
        message = payload['d']
        assert message['target_id'] == '999'
        assert message['username'] == 'test'
        assert message['avatar_url'] == 'http://example.com/test.png'
        assert message['rank'] == 'turbo'
        assert message['content'] == 'hello world'
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        assert {ev['ev'] for ev in events} == {'ack', 'whisper'}
        assert client.get_message_history() == []


def test_discord_client_on_broadcast(uwsgi, redis_channel, bot_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        # first we try to send it as a turbo, which should fail
        member = client.format_user(client.context)
        uwsgi.send_websocket_client_event(
            greenlet,
            'broadcast',
            {'member': member, 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Insufficient privileges.'}
        # we force elevate the privileges of the client
        client.context['access_level'] = ACL.moderator
        uwsgi.send_websocket_client_event(
            greenlet,
            'broadcast',
            {'member': member, 'content': 'hello world'}
        )
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'broadcast'
        message = payload['d']
        assert message['channel_name'] == 'broadcast'
        assert message['content'] == 'hello world'
        assert message['author'] == member
        expected_message = message
        message = bot_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'webchat_broadcast'
        message = payload['d']
        assert message['username'] == 'test'
        assert message['avatar_url'] == 'http://example.com/test.png'
        assert message['content'] == 'hello world'
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert 'ack' in unordered_events
        assert unordered_events['broadcast'] == expected_message
        assert client.get_message_history() == [expected_message]


def test_discord_client_on_timeout_member(uwsgi, redis, redis_channel,
                                          bot_channel, env, patch_config):
    # the account we wanna timeout
    other_member = {
        'discord_id': None,
        'username': 'other_test',
        'discriminator': None,
        'rank': 'turbo',
        'local': True
    }
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        # first we try to send it as a turbo, which should fail
        uwsgi.send_websocket_client_event(
            greenlet,
            'timeout_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Insufficient privileges.'}

        # we force elevate the privileges of the client
        # but it should still fail because the user does not exist locally
        client.context['access_level'] = ACL.moderator
        uwsgi.send_websocket_client_event(
            greenlet,
            'timeout_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Could not find user to timeout.'}

        # after creation the command should succeed...
        User.create({
            'id': '2',
            'username': 'other_test',
            'acct': 'other_test',
            'display_name': 'Other test',
            'avatar_static': 'http://example.com/other_test.png',
            'locked': False,
        })
        # ...unless we make the other user a moderator (or higher)
        with patch_config(special_users={'other_test': 'moderator'}):
            uwsgi.send_websocket_client_event(
                greenlet,
                'timeout_member',
                {'member': other_member, 'reason': 'spoilers'}
            )
            gevent.sleep(0.1)
            assert redis_channel.parse_response(
                block=False, timeout=0.1
            ) is None
            events = uwsgi.receive_websocket_server_events(greenlet)
            assert len(events) == 1
            assert events[0]['ev'] == 'error'
            assert events[0]['d'] == {
                'message': 'Cannot timeout user with same or higher rank.'
            }

        # but now that he's back to being just a turbo it should work
        uwsgi.send_websocket_client_event(
            greenlet,
            'timeout_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'timeout_member'
        assert payload['d'] == {'member': other_member, 'reason': 'spoilers'}
        # the discord id is not set so it should not propagate to the bot
        assert bot_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been timed out successfully.'
        }
        assert unordered_events['timeout_member'] == {
            'member': other_member, 'reason': 'spoilers'
        }
        data = util.shget(redis, 'timed-out-members', 'other_test')
        assert data is not None
        info = json.loads(data.decode('utf-8'))
        assert info['member'] == other_member
        assert info['reason'] == 'spoilers'


def test_discord_client_on_timeout_member_discord(uwsgi, redis, redis_channel,
                                                  bot_channel, env):
    # the account we wanna timeout
    other_member = {
        'discord_id': '444',
        'username': 'other_test',
        'discriminator': '1234',
        'rank': 'turbo',
        'local': False
    }
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'

        # we force our client to be a moderator
        client.context['access_level'] = ACL.moderator

        # since the account is not local the event should just go out
        # without the existance check
        uwsgi.send_websocket_client_event(
            greenlet,
            'timeout_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'timeout_member'
        assert payload['d'] == {'member': other_member, 'reason': 'spoilers'}
        # the discord id is set so the bot should also receive an event
        message = bot_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'webchat_timeout_member'
        assert payload['d'] == {'member': other_member, 'reason': 'spoilers'}
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been timed out successfully.'
        }
        assert unordered_events['timeout_member'] == {
            'member': other_member, 'reason': 'spoilers'
        }
        # it will be timed out using the discord id instead of the username
        data = util.shget(redis, 'timed-out-members', '444')
        assert data is not None
        info = json.loads(data.decode('utf-8'))
        assert info['member'] == other_member
        assert info['reason'] == 'spoilers'


def test_discord_client_on_ban_member(uwsgi, redis_channel, bot_channel, env,
                                      patch_config):
    # the account we wanna ban
    other_member = {
        'discord_id': None,
        'username': 'other_test',
        'discriminator': None,
        'rank': 'turbo',
        'local': True
    }
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        # first we try to send it as a turbo, which should fail
        uwsgi.send_websocket_client_event(
            greenlet,
            'ban_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Insufficient privileges.'}

        # we force elevate the privileges of the client
        # but it should still fail because the user does not exist locally
        client.context['access_level'] = ACL.moderator
        uwsgi.send_websocket_client_event(
            greenlet,
            'ban_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Could not find user to ban.'}

        # after creation the command should succeed...
        other_user = User.create({
            'id': '2',
            'username': 'other_test',
            'acct': 'other_test',
            'display_name': 'Other test',
            'avatar_static': 'http://example.com/other_test.png',
            'locked': False,
        })
        # ...unless we make the other user a moderator (or higher)
        with patch_config(special_users={'other_test': 'moderator'}):
            uwsgi.send_websocket_client_event(
                greenlet,
                'ban_member',
                {'member': other_member, 'reason': 'spoilers'}
            )
            gevent.sleep(0.1)
            assert redis_channel.parse_response(
                block=False, timeout=0.1
            ) is None
            events = uwsgi.receive_websocket_server_events(greenlet)
            assert len(events) == 1
            assert events[0]['ev'] == 'error'
            assert events[0]['d'] == {
                'message': 'Cannot ban user with same or higher rank.'
            }
            assert not other_user.is_banned()

        # but now that he's back to being just a turbo it should work
        uwsgi.send_websocket_client_event(
            greenlet,
            'ban_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        # because the member was banned it should now be rank 'shadow'
        expected_member = other_member.copy()
        expected_member['rank'] = 'shadow'
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'ban_member'
        assert payload['d'] == {
            'member': expected_member, 'reason': 'spoilers'
        }
        # the discord id is not set so it should not propagate to the bot
        assert bot_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been banned successfully.'
        }
        assert unordered_events['ban_member'] == {
            'member': expected_member, 'reason': 'spoilers'
        }
        assert other_user.is_banned()


def test_discord_client_on_ban_member_discord(uwsgi, redis_channel,
                                              bot_channel, env):
    # the account we wanna ban
    other_member = {
        'discord_id': '444',
        'username': 'other_test',
        'discriminator': '1234',
        'rank': 'turbo',
        'local': False
    }
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'

        # we force our client to be a moderator
        client.context['access_level'] = ACL.moderator

        # since the account is not local the event should just go out
        # without the existance check
        uwsgi.send_websocket_client_event(
            greenlet,
            'ban_member',
            {'member': other_member, 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        # the member object will stay unchanged since its not a local account
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'ban_member'
        assert payload['d'] == {'member': other_member, 'reason': 'spoilers'}
        # the discord id is set so it should propagate to the bot
        message = bot_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'webchat_ban_member'
        assert payload['d'] == {'member': other_member, 'reason': 'spoilers'}
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been banned successfully.'
        }
        assert unordered_events['ban_member'] == {
            'member': other_member, 'reason': 'spoilers'
        }


def test_discord_client_on_unban_member(uwsgi, redis, redis_channel,
                                        bot_channel, env, patch_config):
    # the account we wanna unban
    other_member = {
        'discord_id': None,
        'username': 'other_test',
        'discriminator': None,
        'rank': 'turbo',
        'local': True
    }
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'
        # first we try to send it as a turbo, which should fail
        uwsgi.send_websocket_client_event(
            greenlet,
            'unban_member',
            {'member': other_member}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Insufficient privileges.'}

        # we force elevate the privileges of the client
        # but it should still fail because the user does not exist locally
        client.context['access_level'] = ACL.moderator
        uwsgi.send_websocket_client_event(
            greenlet,
            'unban_member',
            {'member': other_member}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Could not find user to unban.'}

        # after creation the command should succeed...
        other_user = User.create({
            'id': '2',
            'username': 'other_test',
            'acct': 'other_test',
            'display_name': 'Other test',
            'avatar_static': 'http://example.com/other_test.png',
            'locked': False,
        })
        # we ban the user to make sure unban works
        other_user.ban()
        # we set a timeout to make sure clearing the timeout works
        util.shaddex(
            redis,
            'timed-out-members',
            'other_test',
            300,
            json.dumps(other_member).encode('utf-8')
        )
        # ...unless we make the other user a moderator (or higher)
        with patch_config(special_users={'other_test': 'moderator'}):
            uwsgi.send_websocket_client_event(
                greenlet,
                'unban_member',
                {'member': other_member}
            )
            gevent.sleep(0.1)
            assert redis_channel.parse_response(
                block=False, timeout=0.1
            ) is None
            events = uwsgi.receive_websocket_server_events(greenlet)
            assert len(events) == 1
            assert events[0]['ev'] == 'error'
            assert events[0]['d'] == {
                'message': 'Cannot unban user with same or higher rank.'
            }
            assert util.shget(
                redis, 'timed-out-members', 'other_test'
            ) is not None

        uwsgi.send_websocket_client_event(
            greenlet,
            'unban_member',
            {'member': other_member}
        )
        gevent.sleep(0.1)
        # because the member was unbanned the member object should still match
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'unban_member'
        assert payload['d'] == {'member': other_member}
        # the discord id is not set so it should not propagate to the bot
        assert bot_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been unbanned successfully. '
                    'They will need to be unbanned from Discord manually.'
        }
        assert unordered_events['unban_member'] == {'member': other_member}
        assert not other_user.is_banned()
        assert util.shget(redis, 'timed-out-members', 'other_test') is None


def test_discord_client_on_unban_member_discord(uwsgi, redis_channel,
                                                bot_channel, env):
    # the account we wanna ban
    other_member = {
        'discord_id': '444',
        'username': 'other_test',
        'discriminator': '1234',
        'rank': 'turbo',
        'local': False
    }
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'

        # we force our client to be a moderator
        client.context['access_level'] = ACL.moderator

        # since the account is not local the event should just go out
        # without the existance check
        uwsgi.send_websocket_client_event(
            greenlet,
            'unban_member',
            {'member': other_member}
        )
        gevent.sleep(0.1)
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'unban_member'
        assert payload['d'] == {'member': other_member}
        # the discord id is set so it should propagate to the bot
        message = bot_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'webchat_unban_member'
        assert payload['d'] == {'member': other_member}
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been unbanned successfully. '
                    'They will need to be unbanned from Discord manually.'
        }
        assert unordered_events['unban_member'] == {'member': other_member}


def test_discord_client_on_ban_username(uwsgi, redis_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'

        # we force elevate the privileges of the client
        client.context['access_level'] = ACL.moderator
        # banning by username requires a local user, so this should fail
        uwsgi.send_websocket_client_event(
            greenlet,
            'ban_username',
            # case of username should not matter
            {'username': 'Other_Test', 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Could not find user to ban.'}

        # after creation the command should succeed
        other_user = User.create({
            'id': '2',
            'username': 'other_test',
            'acct': 'other_test',
            'display_name': 'Other test',
            'avatar_static': 'http://example.com/other_test.png',
            'locked': False,
        })
        # we just do this to check whether it gets formatted correctly
        other_user.set_discord_id(444)
        uwsgi.send_websocket_client_event(
            greenlet,
            'ban_username',
            {'username': 'Other_Test', 'reason': 'spoilers'}
        )
        gevent.sleep(0.1)
        expected_member = {
            'discord_id': '444',
            'username': 'other_test',
            'discriminator': None,
            'rank': 'shadow',
            'local': True
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'ban_member'
        assert payload['d'] == {
            'member': expected_member, 'reason': 'spoilers'
        }
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been banned successfully.'
        }
        assert unordered_events['ban_member'] == {
            'member': expected_member, 'reason': 'spoilers'
        }
        assert other_user.is_banned()


def test_discord_client_on_unban_username(uwsgi, redis_channel, env):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'connect'

        # we force elevate the privileges of the client
        client.context['access_level'] = ACL.moderator
        # unbanning by username requires a local user, so this should fail
        uwsgi.send_websocket_client_event(
            greenlet,
            'unban_username',
            # case of username should not matter
            {'username': 'Other_Test'}
        )
        gevent.sleep(0.1)
        assert redis_channel.parse_response(block=False, timeout=0.1) is None
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 1
        assert events[0]['ev'] == 'error'
        assert events[0]['d'] == {'message': 'Could not find user to unban.'}

        # after creation the command should succeed
        other_user = User.create({
            'id': '2',
            'username': 'other_test',
            'acct': 'other_test',
            'display_name': 'Other test',
            'avatar_static': 'http://example.com/other_test.png',
            'locked': False,
        })
        # we ban the user to ensure unbanning works
        other_user.ban()
        # we just do this to check whether it gets formatted correctly
        other_user.set_discord_id(444)
        uwsgi.send_websocket_client_event(
            greenlet,
            'unban_username',
            {'username': 'Other_Test'}
        )
        gevent.sleep(0.1)
        expected_member = {
            'discord_id': '444',
            'username': 'other_test',
            'discriminator': None,
            'rank': 'turbo',
            'local': True
        }
        message = redis_channel.parse_response(block=False, timeout=0.1)
        assert message and message[0] == b'message'
        payload = json.loads(message[2])
        assert payload['ev'] == 'unban_member'
        assert payload['d'] == {'member': expected_member}
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 2
        unordered_events = {ev['ev']: ev['d'] for ev in events}
        assert unordered_events['ack'] == {
            'info': 'other_test has been unbanned successfully. '
                    'They will need to be unbanned from Discord manually.'
        }
        assert unordered_events['unban_member'] == {'member': expected_member}
        assert not other_user.is_banned()


def test_discord_channel_invalid_payload(uwsgi, redis, env, caplog):
    caplog.set_level(logging.DEBUG, logger='sticks.wss')
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        gevent.spawn(client.start)
        gevent.sleep(0.1)
        # send malformed json
        redis.publish('test', b'malformed{]')
        gevent.sleep(0.1)
        assert 'Received invalid channel payload.' in caplog.messages[-1]
        # send malformed paylod
        redis.publish('test', b'[]')
        gevent.sleep(0.1)
        assert 'Received invalid channel payload.' in caplog.messages[-1]
        # send invalid event type
        redis.publish('test', b'{"ev":0}')
        gevent.sleep(0.1)
        assert 'Received invalid channel payload.' in caplog.messages[-1]
        # send invalid data type
        redis.publish('test', b'{"ev":"event","d":0}')
        gevent.sleep(0.1)
        assert 'Received invalid channel payload.' in caplog.messages[-1]


def test_discord_channel_heartbeat_timeout(uwsgi, redis, env, monkeypatch):
    channel = DiscordChannel('test', '/test')
    with cleanup_channel(channel):
        client = channel.add_client(env)
        greenlet = gevent.spawn(client.start)
        gevent.sleep(0.1)
        uwsgi.send_websocket_client_event(greenlet, 'connect')
        gevent.sleep(0.1)
        events = uwsgi.receive_websocket_server_events(greenlet)
        assert len(events) == 3
        # we don't care about the order of events
        assert {ev['ev'] for ev in events} == {
            'hello',
            'connection_success',
            'connect'
        }

        # patch time.monotonic to report a time that will result in a timeout
        heartbeat = client.context['heartbeat']
        monkeypatch.setattr('time.monotonic', lambda: heartbeat + 8.1)
        # send any event to the channel to trigger the timeout check
        event = {'ev': 'some_event', 'd': {}}
        redis.publish('test', json.dumps(event).encode('utf-8'))
        gevent.sleep(0.1)
        # the client should have been suspended
        assert client.state is ClientState.suspended
        assert client.context['connected'] is False
