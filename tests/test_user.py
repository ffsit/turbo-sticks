from turbo_sticks.enums import ACL
from turbo_sticks.user import User, generate_app_password
from turbo_sticks.util import encrypt


def test_generate_app_password():
    password = generate_app_password()
    assert len(password) == 16
    assert password != generate_app_password()


def test_get(user):
    assert user.uid > 0
    assert User.get(uid=0) is None
    assert User.get(uid=user.uid) == user
    assert User.get(username=None) is None
    assert User.get(username='') is None
    assert User.get(username='bogus') is None
    assert User.get(username=user.username) == user
    assert User.get(username=user.username.upper()) is None
    assert User.get(username=user.username.upper(), fuzzy=True) == user


def test_load(user):
    unloaded = User()
    assert unloaded.uid == 0
    assert unloaded.load(0) is False
    assert unloaded.load(999) is False
    assert unloaded.load(user.uid) is True
    assert unloaded.uid > 0


def test_load_updated_username(user):
    assert user.username == user.account['username']

    user.account['username'] = 'new_name'
    user.load(user.uid)
    assert user.username == 'new_name'


def test_reload(account, user):
    unloaded = User()
    assert unloaded.reload() is False

    copy = User(account)
    copy.set_discord_id(1)
    assert copy.discord_id == 1
    assert user.discord_id is None

    assert user.reload() is True
    assert user.discord_id == 1


def test_app_password_plain(db):
    user = User()
    assert user.app_password_plain is None

    user.app_password = encrypt('password')
    assert user.app_password != 'password'
    assert user.app_password_plain == 'password'


def test_reset_app_password(account, user):
    unregistered = User()
    assert unregistered.app_password is None
    assert unregistered.app_password_plain is None
    assert unregistered.app_password_hash is None

    unregistered.reset_app_password()
    assert unregistered.app_password is None
    assert unregistered.app_password_plain is None
    assert unregistered.app_password_hash is None

    original = user.app_password
    original_plain = user.app_password_plain
    original_hash = user.app_password_hash

    user.reset_app_password()
    assert user.app_password != original
    assert user.app_password_plain != original_plain
    assert user.app_password_hash != original_hash

    copy = User(account)
    assert copy.app_password == user.app_password
    assert copy.app_password_plain == user.app_password_plain
    assert copy.app_password_hash == user.app_password_hash


def test_set_discord_id(account, user):
    unregistered = User()
    assert unregistered.discord_id is None

    unregistered.set_discord_id(5)
    assert unregistered.discord_id is None

    assert user.discord_id is None
    user.set_discord_id(5)
    assert user.discord_id == 5

    copy = User(account)
    assert copy.discord_id == 5

    user.set_discord_id(None)
    assert user.discord_id is None

    copy.reload()
    assert copy.discord_id is None


def test_ban(account, user):
    unregistered = User()
    assert unregistered.banned is True
    assert unregistered.access_level == ACL.guest

    unregistered.ban()
    assert unregistered.banned is True
    assert unregistered.access_level == ACL.guest

    assert user.banned is False
    assert user.access_level == ACL.turbo

    user.ban()
    assert user.banned is True
    assert user.access_level == ACL.guest

    user.ban()
    assert user.banned is True
    assert user.access_level == ACL.guest

    copy = User(account)
    assert copy.banned is True
    assert copy.access_level == ACL.guest


def test_unban(account, user):
    unregistered = User()
    assert unregistered.banned is True
    assert unregistered.access_level == ACL.guest

    unregistered.unban()
    assert unregistered.banned is True
    assert unregistered.access_level == ACL.guest

    user.ban()
    user.reload()
    assert user.banned is True
    assert user.access_level == ACL.guest

    user.unban()
    assert user.banned is False
    assert user.access_level == ACL.turbo

    user.unban()
    assert user.banned is False
    assert user.access_level == ACL.turbo

    copy = User(account)
    assert not copy.banned
    assert copy.access_level == ACL.turbo


def test_is_banned(account, user):
    unregistered = User()
    assert unregistered.is_banned() is True

    copy = User(account)
    assert user.banned is False
    assert user.access_level == ACL.turbo
    assert user.is_banned() is False
    assert user.banned is False
    assert user.access_level == ACL.turbo
    assert copy.banned is False
    assert copy.access_level == ACL.turbo
    assert copy.is_banned() is False
    assert copy.banned is False
    assert copy.access_level == ACL.turbo

    user.ban()
    assert user.banned is True
    assert user.access_level == ACL.guest
    assert user.is_banned() is True
    assert user.banned is True
    assert user.access_level == ACL.guest
    assert copy.banned is False
    assert copy.access_level == ACL.turbo
    assert copy.is_banned() is True
    assert copy.banned is True
    assert copy.access_level == ACL.guest

    user.unban()
    assert user.banned is False
    assert user.access_level == ACL.turbo
    assert user.is_banned() is False
    assert user.banned is False
    assert user.access_level == ACL.turbo
    assert copy.banned is True
    assert copy.access_level == ACL.guest
    assert copy.is_banned() is False
    assert copy.banned is False
    assert copy.access_level == ACL.turbo


def test_uid_from_username(user):
    assert user.uid > 0
    assert User.uid_from_username(None) == 0
    assert User.uid_from_username('') == 0
    assert User.uid_from_username(user.username) == user.uid
    assert User.uid_from_username(user.username.upper()) == 0
    assert User.uid_from_username(
        user.username.upper(), fuzzy=True
    ) == user.uid


def test_uid_from_mastodon_id(user):
    assert user.uid > 0
    assert User.uid_from_mastodon_id(-1) == 0
    assert User.uid_from_mastodon_id(0) == 0
    assert User.uid_from_mastodon_id(user.mastodon_id) == user.uid


def test_get_access_level(user):
    assert User.get_access_level(None) == ACL.guest
    assert User.get_access_level(User()) == ACL.guest
    assert User.get_access_level(user) == ACL.turbo


def test_eq(user):
    unloaded = User()
    assert unloaded != user
    assert unloaded != object()

    unloaded.load(user.uid)
    assert unloaded == user
    assert unloaded != object()

    unloaded.ban()
    assert unloaded == user
    assert unloaded != object()


def test_create(db, account):
    assert User.create(None) is None
    assert User.create({}) is None
    user = User.create(account)
    assert user.uid > 0
    assert user.mastodon_id == int(account['id'])
    assert user.username == account['username']
