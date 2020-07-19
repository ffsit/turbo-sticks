import logging
import requests
import json

from turbo_config import discord

# Logger
logger = logging.getLogger('sticks.discord')

request_header = {
    'Authorization': 'Bot ' + discord.bot_token,
    'User-Agent': 'TURBOSticks (https://github.com/ffsit/turbo-sticks, 2.3.1)',
}
roles = []

guild_url = f'{discord.api_endpoint}/guilds/{discord.server_id}'


def get_member(discord_id):
    if discord_id is None:
        return None
    member_url = f'{guild_url}/members/{discord_id}'
    return json.loads(
        requests.get(member_url, headers=request_header).text)


def get_user(discord_member):
    if discord_member is None:
        return None
    return discord_member.get('user')


def get_roles():
    get_roles_url = f'{guild_url}/roles'
    return json.loads(requests.get(get_roles_url, headers=request_header).text)


def get_role(role_id):
    global roles
    if roles is None or len(roles) == 0:
        roles = get_roles()
        if roles is None:
            roles = []
    for role in roles:
        if role.get('id') == role_id:
            return role
    return {'color': 0, 'name': ''}


# requires discord user object returned by get_user
def get_avatar_url(discord_user):
    cdn_url = 'https://cdn.discordapp.com'

    if discord_user is None:
        return f'{cdn_url}/embed/avatars/1.png'

    avatar_hash = discord_user.get('avatar')
    if avatar_hash is None:
        default_avatar = int(discord_user.get('discriminator', 0)) % 5
        return f'{cdn_url}/embed/avatars/{default_avatar}.png'
    else:
        user_id = discord_user['id']
        return f'{cdn_url}/avatars/{user_id}/{avatar_hash}.png'


def render_username(discord_user):
    if discord_user is None:
        return '<span class="gray"><i>Not connected</i></span>'
    username = discord_user.get('username', '')
    discriminator = discord_user.get('discriminator', '0000')
    return f'{username}<span class="gray">#{discriminator}</span>'


def render_roles(discord_member):
    if discord_member is None or discord_member.get('roles') is None:
        return ''
    return '&emsp;'.join(
        '<span style="color:#%(color)X">%(name)s</span>' %
        get_role(t) for t in discord_member['roles']
    )


# returns True on success
def add_turbo_role(discord_id, token=None):
    member_url = f'{guild_url}/members/{discord_id}'

    # join the user to the server if not already joined
    if token is not None:
        join_payload = {'access_token': token['access_token']}
        requests.put(
            member_url, json=join_payload, headers=request_header)

    # add member to role
    response = requests.put(
        f'{member_url}/roles/{discord.turbo_role_id}',
        json={},
        headers=request_header
    )

    return response.status_code == 204


# returns True on success
def remove_turbo_role(discord_id):
    member_url = f'{guild_url}/members/{discord_id}'

    # check if member exists, if not report success to prevent lock
    response = requests.get(member_url, headers=request_header)
    error = response.json()
    if response.status_code == 404 or error.get('key', 0) == 10007:
        return True

    # remove member from role
    response = requests.delete(
        '%s/roles/%s' % (member_url, discord.turbo_role_id),
        headers=request_header
    )

    if response.status_code == 204:
        return True
    # if we errored we want to log the error
    error = response.json()
    logger.warning('Discord Error: ' + error.get('message'))
    return False
