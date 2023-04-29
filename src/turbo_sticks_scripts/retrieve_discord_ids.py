# this only works if you've specified the bot_token in turbo_config.py
import requests

from turbo_sticks.config import discord


def main() -> None:
    get_guilds_url = discord.api_endpoint + '/users/@me/guilds'
    get_roles_url = discord.api_endpoint + '/guilds/%s/roles'
    request_headers = {
        'Authorization': 'Bot ' + discord.bot_token.get_secret_value()
    }

    print('Retrieving information from Discord API...')
    guilds = requests.get(
        get_guilds_url,
        headers=request_headers,
        timeout=(5, 10)
    ).json()
    for guild in guilds:
        roles = requests.get(
            get_roles_url % guild['id'],
            headers=request_headers,
            timeout=(5, 10)
        ).json()

        print('========================================')
        print(f'Guild: {guild["name"]} ({guild["id"]})')
        for role in roles:
            print(f'Role: {role["name"]} ({role["id"]})')
        print('========================================')


if __name__ == '__main__':
    main()
