from __future__ import annotations

import logging
import requests
from typing import TYPE_CHECKING

from turbo_sticks.config import discord
from turbo_sticks.util import user_agent

if TYPE_CHECKING:
    from .types import DiscordGuildMember
    from .types import DiscordRole
    from .types import DiscordUser
    from .types import MinimalRole
    from .types import OAuth2Token


logger = logging.getLogger('sticks.discord')
request_headers = {
    'Authorization': 'Bot ' + discord.bot_token.get_secret_value(),
    'User-Agent': user_agent(),
}
cdn_url = 'https://cdn.discordapp.com'
guild_url = f'{discord.api_endpoint}/guilds/{discord.server_id}'


def get_member(discord_id: int | None) -> DiscordGuildMember | None:
    if discord_id is None:
        return None
    member_url = f'{guild_url}/members/{discord_id}'
    return requests.get(member_url, headers=request_headers).json()


def get_user(member: DiscordGuildMember | None) -> DiscordUser | None:
    if member is None:
        return None
    return member.get('user')


def get_roles() -> list[DiscordRole]:
    get_roles_url = f'{guild_url}/roles'
    return requests.get(get_roles_url, headers=request_headers).json()


_roles: dict[int, MinimalRole] | None = None


def get_role(role_id: int) -> MinimalRole:
    global _roles
    if _roles is None:
        _roles = {
            _id: role for role in get_roles()
            if (_id := role.get('id', 0))
        }
    return _roles.get(role_id, {'name': '', 'color': 0})


def get_avatar_url(discord_user: DiscordUser | None) -> str:
    if discord_user is None:
        return f'{cdn_url}/embed/avatars/1.png'

    avatar_hash = discord_user.get('avatar')
    if avatar_hash is None:
        default_avatar = int(discord_user.get('discriminator', 0)) % 5
        return f'{cdn_url}/embed/avatars/{default_avatar}.png'

    user_id = discord_user['id']
    return f'{cdn_url}/avatars/{user_id}/{avatar_hash}.png'


def render_username(discord_user: DiscordUser | None) -> str:
    if discord_user is None:
        return '<span class="gray"><i>Not connected</i></span>'
    username = discord_user.get('username', '')
    discriminator = discord_user.get('discriminator', '0000')
    return f'{username}<span class="gray">#{discriminator}</span>'


def render_roles(discord_member: DiscordGuildMember | None) -> str:
    if discord_member is None:
        return ''

    role_ids = discord_member.get('roles')
    if not role_ids:
        return ''

    return '&emsp;'.join(
        '<span style="color:#{color:06X}">{name}</span>'.format(
            **get_role(role_id)
        )
        for role_id in role_ids
    )


def add_turbo_role(
    discord_id: int,
    token:      OAuth2Token | None = None
) -> bool:

    member_url = f'{guild_url}/members/{discord_id}'

    # join the user to the server if not already joined
    if token is not None:
        requests.put(
            member_url,
            json={'access_token': token['access_token']},
            headers=request_headers
        )

    # add member to role
    response = requests.put(
        f'{member_url}/roles/{discord.turbo_role_id}',
        json={},
        headers=request_headers
    )

    return response.status_code == 204


def remove_turbo_role(discord_id: int) -> bool:
    member_url = f'{guild_url}/members/{discord_id}'

    # check if member exists, if not report success to prevent lock
    response = requests.get(member_url, headers=request_headers)
    error = response.json()
    if response.status_code == 404 or error.get('key', 0) == 10007:
        return True

    # remove member from role
    response = requests.delete(
        f'{member_url}/roles/{discord.turbo_role_id}',
        headers=request_headers
    )

    if response.status_code == 204:
        return True
    # if we errored we want to log the error
    error = response.json()
    logger.warning('Discord Error: ' + error.get('message'))
    return False
