import requests
import json

from turbo_config import discord

request_header = {'Authorization': 'Bot ' + discord.bot_token}
roles = []

def get_member(discord_id):
	if(discord_id is None):
		return None
	guild_member_url = discord.api_endpoint + '/guilds/' + discord.server_id + '/members/' + str(discord_id)
	return json.loads(requests.get(guild_member_url, headers=request_header).text)

def get_user(discord_member):
	if(discord_member is None):
		return None
	return discord_member.get('user')

def get_roles():
	get_roles_url = discord.api_endpoint + '/guilds/' + discord.server_id + '/roles'
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
	cdn_url = 'https://cdn.discordapp.com/'

	if(discord_user is None):
		return cdn_url + 'embed/avatars/1.png'

	avatar_hash = discord_user.get('avatar')
	if avatar_hash is None:
		default_avatar = str(int(discord_user.get('discriminator','0000')) % 5);
		return cdn_url + 'embed/avatars/' + default_avatar + '.png'
	else:
		return cdn_url + 'avatars/' + discord_user['id'] + '/' + avatar_hash + '.png'

def render_username(discord_user):
	if(discord_user is None):
		return '<span class="gray"><i>Not connected</i></span>'
	return discord_user.get('username','') + '<span class="gray">#' + discord_user.get('discriminator','0000') + '</span>'

def render_roles(discord_member):
	if(discord_member is None or discord_member.get('roles') is None):
		return ''
	return '&emsp;'.join('<span style="color:#%(color)X">%(name)s</span>' % get_role(t) for t in discord_member['roles'])

# returns True on success
def add_turbo_role(discord_id, token=None):
	guild_member_url = discord.api_endpoint + '/guilds/' + discord.server_id + '/members/' + str(discord_id)

	# join the user to the server if not already joined
	if(token is not None):
		join_payload = {'access_token': token['access_token']}
		requests.put(guild_member_url, json=join_payload, headers=request_header)

	# add member to role
	response = requests.put(guild_member_url + '/roles/' + discord.turbo_role_id, json={}, headers=request_header)

	return response.status_code == 201

# returns True on success
def remove_turbo_role(discord_id):
	# remove member from role	
	guild_member_url = discord.api_endpoint + '/guilds/' + discord.server_id + '/members/' + str(discord_id)
	response = requests.delete(guild_member_url + '/roles/' + discord.turbo_role_id, headers=request_header)
	return response.status_code == 204

