# Actual configuration needs to be named turbo_config.py
from types import SimpleNamespace

# Config
web_uri = 'https://sticks.turbo.chat'
page_title = 'Turbo Sticks Account Management'
page_description = 'Turbo Sticks is an authentication bridge between various Turbo services.'
app_secret = 'itsasecret'  # Secret used for crypto
base_path = ''
api_path = '/api'  # JSON calls, local only for now
debug_mode = False

# Mastodon OAuth 2.0 Setup Vars
mastodon = SimpleNamespace()
mastodon.client_id = 'your mastodon apps client id'
mastodon.client_secret = 'your mastodon apps client secret'
mastodon.scope = ['read:accounts']

# Mastodon API nodes
mastodon.authorize_url = 'https://toot.turbo.chat/oauth/authorize'
mastodon.token_url = 'https://toot.turbo.chat/oauth/token'
mastodon.get_account_url = 'https://toot.turbo.chat/api/v1/accounts/verify_credentials'

# Discord OAuth 2.0 Setup Vars
discord = SimpleNamespace()
discord.client_id = 'your discord apps client id'
discord.client_secret = 'your discord apps client secret'
discord.scope = ['identify', 'guilds.join']

# Discord Bot (requires CREATE_INSTANT_INVITE|MANAGE_ROLES permissions)
discord.bot_token = 'your bots access token'

# Discord Server Information (you can use retrieve_discord_ids.py)
discord.server_id = 'your server/guild id'
discord.turbo_role_id = 'your turbo role id'

# Discord API nodes
discord.authorize_url = 'https://discordapp.com/api/oauth2/authorize'
discord.token_url = 'https://discordapp.com/api/oauth2/token'
discord.api_endpoint = 'https://discordapp.com/api/v6'

# Patreon OAuth 2.0 Setup Vars
patreon = SimpleNamespace()
patreon.client_id = 'your patreon apps client id'
patreon.client_secret = 'your patreon apps client secret'
patreon.scope = ['identity', 'identity[email]']

# Patreon creator's access token (only for initial setup)
patreon.access_token = 'your patreon creators access token'
patreon.refresh_token = 'your patreon creators refresh token'

# Patreon API nodes (make sure to replace {campaign_id} with the relevant id)
patreon.authorize_url = 'https://www.patreon.com/oauth2/authorize'
patreon.token_url = 'https://www.patreon.com/api/oauth2/token'
patreon.api_endpoint = 'https://www.patreon.com/api/oauth2/v2'

# Patreon IDs (can be determined with the help of retrieve_patreon_ids.py)
patreon.campaign_id = 'your patreon campaign id'

# Patreon minimum pledge amount for theatre access in cents
patreon.theatre_cents = 500

# DB Connection
db_host = '127.0.0.1'
db_name = 'turbo_bridge'
db_user = 'turbo'
db_pass = 'ttturbo'
db_max_age = 10*60  # Establish a fresh connection every 10 minutes

# CSRF Protection
expiration_interval = 60*60  # 1 hour
flush_interval = 5*60  # Flush expired tokens every 5 minutes

# Sessions
session_max_age = 60*60*24*7  # 1 Week
cookie_scope = 'turbo.chat'  # turbo.chat including all subdomains

# Stream
stream_sources = [
    {
        'embed_type': 'html',
        'embed': '<iframe id="player-frame" frameborder="0" scrolling="no" src="https://player.twitch.tv/?channel=ffstv" allowfullscreen></iframe>',
        'label': 'Twitch'
    }
]

# Theatre
theatre_password = 'ttturbo'  # Used to authenticate non turbo viewers
theatre_sources = [
    {
        'embed_type': 'oven-webrtc',
        'embed': 'wss://v-cdn.acra.cloud:3333/app/stream_o',
        'label': 'Oven Test'
    }
]
