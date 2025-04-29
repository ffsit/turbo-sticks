from __future__ import annotations

import os
import yaml
from collections.abc import Iterator
from contextlib import contextmanager
from pydantic_core.core_schema import ValidationInfo
from pydantic import (
    BaseModel, PositiveInt, PostgresDsn, SecretStr, field_validator
)
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource
from typing import Any

from .enums import ACL
from .types import HTTPScheme
from .types import StreamEmbed
from .types import WSScheme


class WebsocketsConfig(BaseModel):
    path:        str = '/websockets'
    scheme:      WSScheme = 'wss'
    max_clients: PositiveInt = 90

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class MastodonConfig(BaseModel):
    client_id:       str
    client_secret:   SecretStr
    scope:           list[str] = []
    authorize_url:   str = 'https://toot.turbo.chat/oauth/authorize'
    token_url:       str = 'https://toot.turbo.chat/oauth/token'
    get_account_url: str = (
        'https://toot.turbo.chat/api/v1/accounts/verify_credentials'
    )

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class WebchatConfig(BaseModel):
    history_ttl:      PositiveInt = 2*60*60
    history_length:   PositiveInt = 50
    timeout_duration: PositiveInt = 5*60

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class DiscordConfig(BaseModel):
    client_id:                str
    client_secret:            SecretStr
    scope:                    list[str] = []
    bot_token:                SecretStr
    live_channel:             str = 'live_chat'
    # NOTE: These ids used to be strings, but since Discord ids are snowflakes
    #       they should always be a positive int, pydantic2 is more pedantic
    #       so it won't accept an integer as a string, so this just saves us
    #       the trouble of having to deal with that, since YAML will read it
    #       as an integer unless it's quoted anyways
    server_id:                PositiveInt
    turbo_role_id:            PositiveInt
    webhook_refresh_interval: PositiveInt = 60*60
    webchat_user_suffix:      str = '@turbo.chat'
    authorize_url:            str = 'https://discord.com/api/oauth2/authorize'
    token_url:                str = 'https://discord.com/api/oauth2/token'
    api_endpoint:             str = 'https://discord.com/api/v6'

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class PatreonConfig(BaseModel):
    client_id:       str
    client_secret:   SecretStr
    scope:           list[str] = []
    access_token:    SecretStr
    refresh_token:   SecretStr
    authorize_url:   str = 'https://discord.com/api/oauth2/authorize'
    token_url:       str = 'https://discord.com/api/oauth2/token'
    api_endpoint:    str = 'https://discord.com/api/v6'
    campaign_id:     str
    theatre_cents:   PositiveInt = 500
    session_max_age: PositiveInt = 60*60

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class DBPoolConfig(BaseModel):
    uri:      PostgresDsn = PostgresDsn(
        'postgresql://turbo@127.0.0.1/turbo_bridge'
    )
    min_size: PositiveInt = 4
    max_size: PositiveInt = 8
    max_idle: PositiveInt = 60*10
    max_age:  PositiveInt = 60*60

    @field_validator('max_size')
    @classmethod
    def max_ge_min(cls, v: int, info: ValidationInfo) -> None:
        if v < info.data.get('min_size', 0):
            raise ValueError('needs to be greater or equal to min_size.')

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class CSRFConfig(BaseModel):
    expiration_interval: PositiveInt = 60*60
    flush_interval:      PositiveInt = 60*5

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class SessionConfig(BaseModel):
    max_age:      PositiveInt = 7*24*60*60
    cookie_scope: str = 'turbo.chat'

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True
    }


class SticksConfig(BaseSettings):
    web_uri:          str = 'sticks.turbo.chat'
    web_scheme:       HTTPScheme = 'https'
    page_title:       str = 'TURBO Sticks'
    page_description: str = (
        'TURBO Sticks is an authentication bridge between various '
        'TURBO services.'
    )
    app_secret:       SecretStr
    base_path:        str = ''
    api_path:         str = '/api'
    websockets:       WebsocketsConfig
    static_dir:       str = './static'
    redis_uri:        str = 'unix:///var/run/redis/redis.sock'
    debug_mode:       bool = False
    special_users:    dict[str, ACL] = {}
    mastodon:         MastodonConfig
    webchat:          WebchatConfig = WebchatConfig()
    discord:          DiscordConfig
    patreon:          PatreonConfig
    db_pool:          DBPoolConfig
    csrf:             CSRFConfig = CSRFConfig()
    session:          SessionConfig = SessionConfig()
    stream_sources:   list[StreamEmbed] = []

    model_config = {
        # NOTE: For now this seems more sensible but maybe in the future we
        #       want the configuration to be mutable in some way at runtime
        'frozen': True,
        'secrets_dir': '/var/run',
        'env_prefix': 'STICKS_',
        'env_nested_delimiter': '__'
    }

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            env_settings,
            init_settings,
            # FIXME: Something about file_secret_settings broke in pydantic 2.0
            #        figure it out and re-enable it when it is fixed
            # file_secret_settings
        )


# TODO: We probably want an explicit function call to load the config.
#       However, right now this may pose some structural restrictions.
_config_file = os.getenv('STICKS_CONFIG', 'turbo-config.yaml')
with open(_config_file) as fp:
    _config = SticksConfig(**yaml.safe_load(fp))


# NOTE: This is currently only used for testing, patches config then returns
#       it to original state.
@contextmanager
def patch_config(**kwargs: Any) -> Iterator[SticksConfig]:
    global _config
    original = _config
    values = original.model_dump()
    # merge config values two levels deep
    for key, value in kwargs.items():
        if isinstance(value, dict):
            values[key].update(value)
        else:
            values[key] = value

    _config = SticksConfig(**values)
    yield _config
    _config = original


# NOTE: This is probably a bad idea. But for now this is easier than changing
#       all the functions that make use of config variables.
def __getattr__(name: str) -> Any:
    return getattr(_config, name)
