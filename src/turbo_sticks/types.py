from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, Protocol, TypeVar
from typing_extensions import NotRequired, TypedDict


_F = TypeVar('_F', bound=Callable[..., Any])

JSON = dict[str, 'JSON'] | list['JSON'] | str | int | float | bool | None
JSONObject = dict[str, JSON]
JSONArray = list[JSON]


class Decorator(Protocol):
    def __call__(self, __func: _F) -> _F: ...


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


class OAuth2Token(TypedDict):
    access_token:  str
    token_type:    str
    refresh_token: NotRequired[str]
    expires_in:    NotRequired[str]


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


class MastodonEmoji(TypedDict):
    shortcode:         str
    url:               str
    static_url:        str
    visible_in_picker: bool
    category:          NotRequired[str]


class MastodonField(TypedDict):
    name:        str
    value:       str
    verified_at: NotRequired[str | None]  # ISO 8601


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
class MastodonAccount(TypedDict):
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

    # Optional attributes
    moved:           NotRequired[dict[str, Any]]
    fields:          NotRequired[list[MastodonField]]
    bot:             NotRequired[bool]
    source:          NotRequired[MastodonSource]
    suspended:       NotRequired[bool]
    mute_expires_at: NotRequired[str]  # ISO 8601


# Discord API types
class DiscordUser(TypedDict):
    id:            int
    username:      str
    discriminator: str
    avatar:        str | None

    # Optional attributes
    bot:           NotRequired[bool]
    system:        NotRequired[bool]
    mfa_enabled:   NotRequired[bool]
    banner:        NotRequired[str | None]
    accent_color:  NotRequired[int | None]
    locale:        NotRequired[str]         # Probably ISO 639-1
    verified:      NotRequired[bool]        # requires email scope
    email:         NotRequired[str | None]  # requires email scope
    flags:         NotRequired[int]
    premium_type:  NotRequired[int]
    public_flags:  NotRequired[int]


class DiscordGuildMember(TypedDict):
    roles:     list[int]
    joined_at: str  # ISO 8601
    deaf:      bool
    mute:      bool

    # Optional attributes
    user:                         NotRequired[DiscordUser]
    nick:                         NotRequired[str | None]
    avatar:                       NotRequired[str | None]
    premium_since:                NotRequired[str | None]  # ISO 8601
    pending:                      NotRequired[bool]
    permissions:                  NotRequired[str]
    communcations_disabled_until: NotRequired[str | None]  # ISO 8601


class DiscordRoleTags(TypedDict, total=False):
    bot_id:             int
    integration_id:     int
    premium_subscriber: None


# We use this to be lazy since we only care about name and color at the end
class MinimalRole(TypedDict):
    name:  str
    color: int


class DiscordRole(MinimalRole):
    id:          int
    hoist:       bool
    position:    int
    permissions: str
    managed:     bool
    mentionable: bool

    icon:          NotRequired[str | None]
    unicode_emoji: NotRequired[str | None]
    tags:          NotRequired[DiscordRoleTags]
