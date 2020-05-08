# this only works if you've specified the bot_token in turbo_config.py
import os
import sys
import json
import requests

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from turbo_config import discord

get_guilds_url = discord.api_endpoint + '/users/@me/guilds'
get_roles_url = discord.api_endpoint + '/guilds/%s/roles'
request_headers = {'Authorization': 'Bot ' + discord.bot_token}

print('Retrieving information from Discord API...')
guilds = json.loads(requests.get(get_guilds_url, headers=request_headers).text)
for guild in guilds:
    roles = json.loads(requests.get(get_roles_url % guild['id'],
                       headers=request_headers).text)

    print('========================================')
    print('Guild: ' + guild['name'] + ' (' + guild['id'] + ')')
    for role in roles:
        print('Role: ' + role['name'] + ' (' + role['id'] + ')')
    print('========================================')
    print('')
