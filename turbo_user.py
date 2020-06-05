from enum import IntEnum
from hashlib import md5
from turbo_db import DBSession
from turbo_util import encrypt, decrypt, urandom
from turbo_config import special_users


# Password Helpers
def generate_app_password():
    # Chosen alphabet attempts to avoid ambiguous or url unsafe characters
    # Also its length of 64 makes sure each character is hit evenly
    alphabet = ('abcdefghijkmnopqrstuvwxyz'
                'ABCDEFGHJKLMNPQRSTUVWXYZ'
                '123456789*!-.+_')
    seed = urandom(16)
    return ''.join(alphabet[byte % len(alphabet)] for byte in seed)


class ACL(IntEnum):
    guest = 0
    patron = 10
    turbo = 20
    helper = 30
    moderator = 40
    crew = 50
    admin = 60

    def __getitem__(self, key):
        return getattr(self, key)

    @staticmethod
    def by_username(username, default='turbo'):
        return ACL[special_users.get(username, default)]


class BaseUser(object):
    uid = None
    account = None
    mastodon_id = None
    discord_id = None
    username = None
    access_level = ACL.guest
    banned = None
    app_password = None
    app_password_hash = None

    def __init__(self):
        self.db = DBSession()

    @property
    def app_password_plain(self):
        if self.app_password:
            return decrypt(self.app_password)
        return self.app_password

    @classmethod
    def get(cls, *, uid=None, username=None, fuzzy=False):
        if username:
            uid = BaseUser.uid_from_username(username, fuzzy)
        if uid:
            user = BaseUser()
            user.load(uid)
            if user.uid:
                return user
        return None

    # Public Methods
    def load(self, uid):
        if self.db is not None and uid > 0:
            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            SELECT username,
                                   discord_id,
                                   app_password,
                                   app_password_hash,
                                   banned
                              FROM users
                             WHERE id = %s"""
                    cur.execute(sql, (uid,))
                    row = cur.fetchone()
                    if(row is None):
                        self = None
                        return
                    self.uid = uid
                    self.username = row[0]
                    self.discord_id = row[1]
                    self.app_password = row[2]
                    self.app_password_hash = row[3]
                    self.banned = row[4]
                    if not self.banned:
                        self.access_level = ACL.by_username(self.username)

    def get_user(self, *, uid=None, username=None, fuzzy=False):
        return BaseUser.get(uid=uid, username=username, fuzzy=fuzzy)

    def reset_app_password(self):
        if self.db is not None and self.uid > 0:
            app_password_plain = generate_app_password()
            self.app_password = encrypt(app_password_plain)
            self.app_password_hash = md5(
                app_password_plain.encode('utf-8')).hexdigest()

            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            UPDATE users
                               SET app_password = %s,
                                   app_password_hash = %s
                             WHERE id = %s"""

                    cur.execute(sql, (
                        self.app_password,
                        self.app_password_hash,
                        self.uid
                    ))

    def set_discord_id(self, discord_id):
        if self.db is not None and self.uid > 0:
            self.discord_id = discord_id
            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            UPDATE users
                               SET discord_id = %s
                             WHERE id = %s"""

                    cur.execute(sql, (
                        self.discord_id,
                        self.uid
                    ))

    def ban(self):
        if self.banned:
            return

        if self.db is not None and self.uid > 0:
            self.banned = True
            self.access_level = ACL.guest
            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            UPDATE users
                               SET banned = %s
                             WHERE id = %s"""

                    cur.execute(sql, (
                        True,
                        self.uid
                    ))

    def unban(self):
        if not self.banned:
            return

        if self.db is not None and self.uid > 0:
            self.banned = False
            self.access_level = ACL.by_username(self.username)
            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            UPDATE users
                               SET banned = %s
                             WHERE id = %s"""

                    cur.execute(sql, (
                        False,
                        self.uid
                    ))

    # live reloaded version of banned property
    def is_banned(self):
        if self.db is not None and self.uid > 0:
            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            SELECT banned
                              FROM users
                             WHERE id = %s"""

                    cur.execute(sql, (self.uid, ))
                    return cur.fetchone()[0]

    # Static Methods
    @staticmethod
    def uid_from_username(username, fuzzy=False):
        db = DBSession()
        if db is not None and username:
            with db.connection as conn:
                with conn.cursor() as cur:
                    sql = 'SELECT id FROM users WHERE username = %s'
                    if fuzzy:
                        sql = """
                            SELECT id
                              FROM users
                             WHERE LOWER(username) = LOWER(%s)"""
                    cur.execute(sql, (username,))
                    row = cur.fetchone()
                    if(row is not None and row[0] > 0):
                        return row[0]
                    return 0
        return None

    @staticmethod
    def uid_from_mastodon_id(mastodon_id):
        db = DBSession()
        if db is not None and mastodon_id > 0:
            with db.connection as conn:
                with conn.cursor() as cur:
                    sql = 'SELECT id FROM users WHERE mastodon_id = %s'
                    cur.execute(sql, (mastodon_id,))
                    row = cur.fetchone()
                    if(row is not None and row[0] > 0):
                        return row[0]
                    return 0
        return None

    @staticmethod
    def get_access_level(user):
        if hasattr(user, 'access_level'):
            return user.access_level
        return ACL.guest


# User class ties into the mastodon account from our session
# It handles user creation. BaseUser can't add new users.
class User(BaseUser):
    def __init__(self, account):
        if account is None:
            return

        self.db = DBSession()
        self.account = account
        self.mastodon_id = int(account.get('id', '0'))
        self.username = account.get('username', '')
        uid = User.uid_from_mastodon_id(self.mastodon_id)
        self.access_level = ACL.guest
        self.banned = False
        if uid > 0:
            self.load(uid)
        else:
            self._create_new_user()

        if not self.banned:
            self.access_level = ACL.by_username(self.username)

    # Use this, so you get None if account is None
    @classmethod
    def create(cls, account):
        user = cls(account)
        if user.uid:
            return user
        return None

    def load(self, uid):
        super().load(uid)
        self._update_username_if_necessary()

    # Private Helper Methods
    def _update_username_if_necessary(self):
        if self.db is not None and self.account is not None and self.uid > 0:
            new_username = self.account.get('username', '')
            if len(self.username) > 0 and new_username != self.username:
                self.username = new_username
                with self.db.connection as conn:
                    with conn.cursor() as cur:
                        sql = """
                                UPDATE users
                                   SET username = %s
                                 WHERE id = %s"""
                        cur.execute(sql, (self.username, self.uid))

    def _create_new_user(self):
        if self.db is not None and self.mastodon_id > 0 and self.username:
            app_password_plain = generate_app_password()
            self.app_password = encrypt(app_password_plain)
            self.app_password_hash = md5(
                app_password_plain.encode('utf-8')).hexdigest()

            with self.db.connection as conn:
                with conn.cursor() as cur:
                    sql = """
                            INSERT INTO users
                            (
                                mastodon_id,
                                username,
                                app_password,
                                app_password_hash
                            )
                            VALUES
                            (
                                %s,
                                %s,
                                %s,
                                %s
                            )"""

                    cur.execute(sql, (
                        self.mastodon_id,
                        self.username,
                        self.app_password,
                        self.app_password_hash
                    ))
            self.uid = User.uid_from_mastodon_id(self.mastodon_id)
