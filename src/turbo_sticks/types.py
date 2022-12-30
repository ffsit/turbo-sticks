from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, TypedDict, TypeVar, TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Protocol, Union
    # NOTE: Based on a comment from https://github.com/python/typing/issues/182
    #       It might be fragile, due to the ignores, but it appears to work
    JSON = Union[str, int, float, bool, None, 'JSONObject', 'JSONArray']

    class JSONArray(list[JSON], Protocol):  # type: ignore
        __class__: type[list[JSON]]  # type: ignore

    class JSONObject(dict[str, JSON], Protocol):  # type: ignore
        __class__: type[dict[str, JSON]]  # type: ignore

    _F = TypeVar('_F', bound=Callable[..., Any])

    class Decorator(Protocol):
        def __call__(self, func: _F) -> _F: ...

# NOTE: In the future we may need to parametrize this
MultiDict = dict[str, list[str]]
HTTPHeader = tuple[str, str]
Response = tuple[bytes, list[HTTPHeader], str]

HTTPScheme = Literal['http', 'https']
WSScheme = Literal['ws', 'wss']

URLBase = Literal['base', 'api', 'websockets']


class StreamEmbed(TypedDict):
    embed_type: str
    embed: str
    label: str


class _OAuth2Token(TypedDict):
    access_token: str
    token_type:   str


class OAuth2Token(_OAuth2Token, total=False):
    refresh_token: str
    expires_in:    str


# Webchat types
Rank = Literal[
    'crew',
    'mod',
    'helper',
    'vip',
    'turbo',
    'patron',
    'shadow',
    'bot',
]


class FormattedMember(TypedDict, total=False):
    username:      str
    discord_id:    str | None
    discriminator: str | None
    rank:          Rank
    local:         bool


class FormattedMessage(TypedDict):
    id:           str
    channel_name: str
    content:      str
    author:       FormattedMember
    created_at:   float


class OnlineMembers(TypedDict):
    webchat: dict[str, FormattedMember]
    discord: dict[str, FormattedMember]


# Mastodon API types
MastodonAccountPrivacy = Literal[
    'public',
    'unlisted',
    'private',
    'direct',
]


class _MastodonEmoji(TypedDict):
    shortcode:         str
    url:               str
    static_url:        str
    visible_in_picker: bool


class MastodonEmoji(_MastodonEmoji, total=False):
    category: str


class _MastodonField(TypedDict):
    name:  str
    value: str


class MastodonField(_MastodonField, total=False):
    verified_at: str | None  # ISO 8601


class MastodonSource(TypedDict):
    note:   str  # plain text
    fields: list[MastodonField]

    # Nullable attributes
    privacy:               MastodonAccountPrivacy | None
    sensitive:             bool | None
    language:              str | None  # ISO 639-1
    follow_requests_count: int | None


# According to https://docs.joinmastodon.org/entities/account/
# We may decide to use pydantic to validate the contents from the API call
class _MastodonAccount(TypedDict):
    # Base
    id:       str  # should convert to int for valid accounts
    username: str
    acct:     str
    url:      str

    # Display
    display_name:  str
    note:          str  # contains HTML
    avatar:        str  # URL
    avatar_static: str  # URL
    header:        str  # URL
    header_static: str  # URL
    locked:        bool
    emojis:        list[MastodonEmoji]
    discoverable:  bool

    # Statistical
    created_at:      str  # ISO 8601
    last_status_at:  str  # ISO 8601
    statuses_count:  int
    followers_count: int
    following_count: int


class MastodonAccount(_MastodonAccount, total=False):
    # Optional attributes
    moved:           dict[str, Any]
    fields:          list[MastodonField]
    bot:             bool
    source:          MastodonSource
    suspended:       bool
    mute_expires_at: str  # ISO 8601


# Discord API types
class _DiscordUser(TypedDict):
    id:            int
    username:      str
    discriminator: str
    avatar:        str | None


class DiscordUser(_DiscordUser, total=False):
    bot:          bool
    system:       bool
    mfa_enabled:  bool
    banner:       str | None
    accent_color: int | None
    locale:       str   # Probably ISO 639-1, but unspecified in spec
    verified:     bool  # requires email scope
    email:        str | None  # requires email scope
    flags:        int
    premium_type: int
    public_flags: int


class _DiscordGuildMember(TypedDict):
    roles:     list[int]
    joined_at: str  # ISO 8601
    deaf:      bool
    mute:      bool


class DiscordGuildMember(_DiscordGuildMember, total=False):
    user:          DiscordUser
    nick:          str | None
    avatar:        str | None
    premium_since: str | None  # ISO 8601
    pending:       bool
    permissions:   str
    communcations_disabled_until: str | None  # ISO 8601


class DiscordRoleTags(TypedDict, total=False):
    bot_id:             int
    integration_id:     int
    premium_subscriber: None


# We use this to be lazy since we only care about name and color at the end
class MinimalRole(TypedDict):
    name:  str
    color: int


class _DiscordRole(MinimalRole):
    id:          int
    hoist:       bool
    position:    int
    permissions: str
    managed:     bool
    mentionable: bool


class DiscordRole(_DiscordRole, total=False):
    icon:          str | None
    unicode_emoji: str | None
    tags:          DiscordRoleTags
