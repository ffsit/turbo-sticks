# Config
web_uri = 'https://sticks.turbo.chat'
page_title = 'Turbo Sticks Account Management'
page_description = 'Turbo Sticks is an authentication bridge between various Turbo services.'
app_secret = 'itsasecret' # Secret used for crypto
base_path = ''
api_path = '/api' # JSON calls, local only for now
debug_mode = False;

# OAuth 2.0 Setup Vars
client_id = 'your mastadon apps client id'
client_secret = 'your mastadon apps client secret'
scope = ['read:accounts']

# API nodes 
authorize_url = 'https://toot.turbo.chat/oauth/authorize'
token_url = 'https://toot.turbo.chat/oauth/token'
account_url = 'https://toot.turbo.chat/api/v1/accounts/verify_credentials'

# DB Connection
db_host = '127.0.0.1'
db_name = 'turbo_bridge'
db_user = 'turbo'
db_pass = 'ttturbo'
db_max_age = 10*60 # Establish a fresh connection every 10 minutes

# CSRF Protection
expiration_interval = 60*60 # 1 hour
flush_interval = 60 # Flush expired tokens every minute

# Sessions
session_max_age = 60*60*24*7 # 1 Week
cookie_scope = 'turbo.chat' # turbo.chat including all subdomains

# Theatre
theatre_password = 'ttturbo' # Used to authenticate non turbo viewers
