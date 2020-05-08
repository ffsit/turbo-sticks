import requests
import json

from turbo_config import discord
from turbo_util import print_info

request_header = {'Authorization': 'Bot ' + discord.bot_token}
roles = []

endpoint = discord.api_endpoint
server_id = discord.server_id


def get_member(discord_id):
    if(discord_id is None):
        return None
    member_url = '%s/guilds/%s/members/%s' % (endpoint, server_id, discord_id)
    return json.loads(
        requests.get(member_url, headers=request_header).text)


def get_user(discord_member):
    if(discord_member is None):
        return None
    return discord_member.get('user')


def get_roles():
    get_roles_url = '%s/guilds/%s/roles' % (endpoint, server_id)
    return json.loads(requests.get(get_roles_url, headers=request_header).text)


def get_role(role_id):
    global roles
    if(roles is None or len(roles) == 0):
        roles = get_roles()
        if(roles is None):
            roles = []
    for role in roles:
        if(role.get('id') == role_id):
            return role
    return {'color': 0, 'name': ''}


# requires discord user object returned by get_user
def get_avatar_url(discord_user):
    cdn_url = 'https://cdn.discordapp.com'

    if(discord_user is None):
        return '%s/embed/avatars/1.png' % (cdn_url,)

    avatar_hash = discord_user.get('avatar')
    if avatar_hash is None:
        default_avatar = int(discord_user.get('discriminator', 0)) % 5
        return '%s/embed/avatars/%s.png' % (cdn_url, default_avatar)
    else:
        user_id = discord_user['id']
        return '%s/avatars/%s/%s.png' % (cdn_url, user_id, avatar_hash)


def render_username(discord_user):
    if(discord_user is None):
        return '<span class="gray"><i>Not connected</i></span>'
    username = discord_user.get('username', '')
    discriminator = discord_user.get('discriminator', '0000')
    return '%s<span class="gray">#%s</span>' % (username, discriminator)


def render_roles(discord_member):
    if(discord_member is None or discord_member.get('roles') is None):
        return ''
    return '&emsp;'.join(
        '<span style="color:#%(color)X">%(name)s</span>' %
        get_role(t) for t in discord_member['roles']
    )


# returns True on success
def add_turbo_role(discord_id, token=None):
    member_url = '%s/guilds/%s/members/%s' % (endpoint, server_id, discord_id)

    # join the user to the server if not already joined
    if(token is not None):
        join_payload = {'access_token': token['access_token']}
        requests.put(
            member_url, json=join_payload, headers=request_header)

    # add member to role
    response = requests.put(
        '%s/roles/%s' % (member_url, discord.turbo_role_id),
        json={},
        headers=request_header
    )

    return response.status_code == 204


# returns True on success
def remove_turbo_role(discord_id):
    member_url = '%s/guilds/%s/members/%s' % (endpoint, server_id, discord_id)

    # check if member exists, if not report success to prevent lock
    response = requests.get(member_url, headers=request_header)
    error = json.loads(response.text)
    if(response.status_code == 404 or error.get('key', 0) == 10007):
        return True

    # remove member from role
    response = requests.delete(
        '%s/roles/%s' % (member_url, discord.turbo_role_id),
        headers=request_header
    )

    if(response.status_code == 204):
        return True
    # if we errored we want to log the error
    error = json.loads(response.text)
    print_info('Discord Error: ' + error.get('message'))
    return False
