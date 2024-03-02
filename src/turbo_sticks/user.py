from __future__ import annotations

from hashlib import md5
from typing import overload, TypeVar, TYPE_CHECKING

import turbo_sticks.config as config
from turbo_sticks.db import DBSession
from turbo_sticks.enums import ACL
from turbo_sticks.util import encrypt, decrypt, urandom

if TYPE_CHECKING:
    from .types import MastodonAccount

    _U = TypeVar('_U', bound='BaseUser')


# Password Helpers
def generate_app_password() -> str:
    # Chosen alphabet attempts to avoid ambiguous or url unsafe characters
    # Also its length of 64 makes sure each character is hit evenly
    alphabet = ('abcdefghijkmnopqrstuvwxyz'
                'ABCDEFGHJKLMNPQRSTUVWXYZ'
                '123456789*!-.+_')
    seed = urandom(16)
    return ''.join(alphabet[byte % len(alphabet)] for byte in seed)


class BaseUser:
    db:                DBSession
    uid:               int
    account:           MastodonAccount | None
    mastodon_id:       int | None
    discord_id:        int | None
    username:          str | None
    access_level:      ACL
    banned:            bool
    app_password:      str | None
    app_password_hash: str | None

    def __init__(self) -> None:
        self.db = DBSession()
        self.uid = 0
        self.account = None
        self.mastodon_id = None
        self.discord_id = None
        self.username = None
        self.access_level = ACL.guest
        self.banned = True  # default to banned for unregistered
        self.app_password = None
        self.app_password_hash = None

    @property
    def app_password_plain(self) -> str | None:
        if self.app_password:
            return decrypt(self.app_password)
        return None

    @overload
    @classmethod
    def get(cls: type[_U], *, uid: int) -> _U | None: ...
    @overload  # noqa: E301
    @classmethod
    def get(cls: type[_U], *, username: str, fuzzy: bool = False
            ) -> _U | None: ...

    @classmethod
    def get(
        cls: type[_U],
        *,
        uid:      int | None = None,
        username: str | None = None,
        fuzzy:    bool = False
    ) -> _U | None:

        if username:
            uid = BaseUser.uid_from_username(username, fuzzy)
        if uid:
            user = cls()
            if user.load(uid):
                return user
        return None

    # Public Methods
    def load(self, uid: int) -> bool:
        if uid <= 0:
            return False

        with self.db.connection() as conn, conn.cursor() as cur:
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
            if row is None:
                return False

            self.uid = uid
            self.username = row[0]
            self.discord_id = row[1]
            self.app_password = row[2]
            self.app_password_hash = row[3]
            self.banned = row[4]
            if self.banned is True:
                self.access_level = ACL.guest
            else:
                assert self.username is not None
                self.access_level = config.special_users.get(
                    self.username,
                    ACL.turbo
                )
            return self.uid > 0

    def reload(self) -> bool:
        return self.load(self.uid)

    # Alias for get
    get_user = get

    def reset_app_password(self) -> None:
        if self.uid <= 0:
            return

        app_password_plain = generate_app_password()
        self.app_password = encrypt(app_password_plain)
        # NOTE: MD5 is totally fine for randomly generated app passwords
        self.app_password_hash = md5(  # nosec
            app_password_plain.encode('utf-8')
        ).hexdigest()

        with self.db.connection() as conn, conn.cursor() as cur:
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

    def set_discord_id(self, discord_id: int | None) -> None:
        if self.uid <= 0:
            return

        self.discord_id = discord_id
        with self.db.connection() as conn, conn.cursor() as cur:
            sql = """
                    UPDATE users
                       SET discord_id = %s
                     WHERE id = %s"""

            cur.execute(sql, (
                self.discord_id,
                self.uid
            ))

    def ban(self) -> None:
        if self.uid <= 0:
            return

        # NOTE: We don't early out, since banned might have changed
        #       and using is_banned() instead would just add another
        #       query to the mix already anyways.
        self.banned = True
        self.access_level = ACL.guest
        with self.db.connection() as conn, conn.cursor() as cur:
            sql = """
                    UPDATE users
                       SET banned = %s
                     WHERE id = %s"""

            cur.execute(sql, (
                True,
                self.uid
            ))

    def unban(self) -> None:
        if self.uid <= 0:
            return

        # NOTE: We don't early out, since banned might have changed
        #       and using is_banned() instead would just add another
        #       query to the mix already anyways.
        self.banned = False
        assert self.username is not None
        self.access_level = config.special_users.get(self.username, ACL.turbo)
        with self.db.connection() as conn, conn.cursor() as cur:
            sql = """
                    UPDATE users
                       SET banned = %s
                     WHERE id = %s"""

            cur.execute(sql, (
                False,
                self.uid
            ))

    # live reloaded version of banned property, that also refreshes it
    def is_banned(self) -> bool:
        if self.uid <= 0:
            return self.banned

        with self.db.connection() as conn, conn.cursor() as cur:
            sql = """
                    SELECT banned
                      FROM users
                     WHERE id = %s"""

            cur.execute(sql, (self.uid, ))
            row = cur.fetchone()
            if row is not None and row[0] is not self.banned:
                self.banned = row[0]
                if self.banned:
                    self.access_level = ACL.guest
                else:
                    assert self.username is not None
                    self.access_level = config.special_users.get(
                        self.username,
                        ACL.turbo
                    )
        return self.banned

    # Static Methods
    @staticmethod
    def uid_from_username(username: str | None, fuzzy: bool = False) -> int:
        if not username:
            return 0

        db = DBSession()
        with db.connection() as conn, conn.cursor() as cur:
            if fuzzy:
                sql = """
                    SELECT id
                      FROM users
                     WHERE LOWER(username) = LOWER(%s)"""
            else:
                sql = 'SELECT id FROM users WHERE username = %s'
            cur.execute(sql, (username,))
            row: tuple[int] | None = cur.fetchone()
            if row is not None and row[0] > 0:
                return row[0]
            return 0

    @staticmethod
    def uid_from_mastodon_id(mastodon_id: int) -> int:
        if mastodon_id <= 0:
            return 0

        db = DBSession()
        with db.connection() as conn, conn.cursor() as cur:
            sql = 'SELECT id FROM users WHERE mastodon_id = %s'
            cur.execute(sql, (mastodon_id,))
            row: tuple[int] | None = cur.fetchone()
            if row is not None and row[0] > 0:
                return row[0]
            return 0

    @staticmethod
    def get_access_level(user: BaseUser | None) -> ACL:
        if user is None:
            return ACL.guest
        return user.access_level

    def __eq__(self, other: object) -> bool:
        if self.uid <= 0:
            # unloaded users are never considered equal
            return False

        if not isinstance(other, BaseUser):
            return False

        # NOTE: While properties might differ between instanced of the same
        #       user, we still consider them equal.
        return self.uid == other.uid


# User class ties into the mastodon account from our session
# It handles user creation. BaseUser can't add new users.
class User(BaseUser):
    def __init__(self, account: MastodonAccount | None = None):
        super().__init__()
        if account is None:
            return

        self.account = account
        self.mastodon_id = int(account.get('id', '0'))
        self.username = account.get('username', '')

        uid = User.uid_from_mastodon_id(self.mastodon_id)
        if uid > 0:
            self.load(uid)
        else:
            self.banned = False
            self._create_new_user()

        if self.banned is False:
            self.access_level = config.special_users.get(
                self.username,
                ACL.turbo
            )

    # Use this, so you get None if account is None
    @classmethod
    def create(cls, account: MastodonAccount | None) -> User | None:
        user = cls(account)
        if user.uid > 0:
            return user
        return None

    def load(self, uid: int) -> bool:
        if not super().load(uid):
            return False

        # Update the username in case it was changed on Mastodon
        if self.account is not None and self.uid > 0:
            new_username = self.account.get('username', '')
            if new_username and new_username != self.username:
                self.username = new_username
                with self.db.connection() as conn, conn.cursor() as cur:
                    sql = """
                            UPDATE users
                               SET username = %s
                             WHERE id = %s"""
                    cur.execute(sql, (self.username, self.uid))
        return True

    def _create_new_user(self) -> None:
        assert isinstance(self.mastodon_id, int)

        if self.mastodon_id > 0 and self.username:
            app_password_plain = generate_app_password()
            self.app_password = encrypt(app_password_plain)
            # NOTE: MD5 is totally fine for randomly generated app passwords
            self.app_password_hash = md5(  # nosec
                app_password_plain.encode('utf-8')
            ).hexdigest()

            with self.db.connection() as conn, conn.cursor() as cur:
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
