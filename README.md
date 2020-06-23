TURBO Sticks Account Management
===========

This authentication bridge authenticates against an OAuth 2.0 provider to present users with member only functionalities.

* Website: [https://sticks.turbo.chat/](https://sticks.turbo.chat/)

NOTES
-----------
* This web application utilizes uwsgi with Python 3.5+ and uses PostgreSQL as its database backend.
* The static content will have to be served using nginx or another HTTP server of your liking, preferably with builtin WSGI support so uWSGI can talk to the proxy using the WSGI protocol, rather than the HTTP protocol.
* The web application may currently not be thread safe, so it is recommended to run it using a single uWSGI worker.

Requirements
-----------
For production use:
* A HTTP server with WSGI support (e.g. nginx)
* uWSGI
* Python 3.6+
  * discord
  * gevent
  * oauthlib
  * redis
  * requests
  * requests_oauthlib
  * psycopg2
  * pycrypto
* PostgreSQL
* Redis

For compiling static CSS and JS resources:
* sassc
* css-purge
* uglifyjs2

Setup
-----------
* Install all the requirements
* Run `setup.sh` in folder `setup` to generate the JS and CSS
* Configure nginx to serve /static and forward wsgi on `/<app path>` and `/<api path>`
* Setup Postgres database and user for use with turbo sticks. Run `initdb.sql` to initialize tables
* (optional) Setup Redis with unix socket
* Setup an App in Mastodon with read:accounts privileges
* Setup an App in Discord with identify and guilds.join scope
* Create a Discord Bot and [authorize it](https://discordapp.com/developers/docs/topics/oauth2#bot-authorization-flow) with `CREATE_INSTANT_INVITE`, `MANAGE_ROLES`, `KICK_MEMBERS`, `BAN_MEMBERS`, `MANAGE_MESSAGES`, `VIEW_CHANNEL`, `SEND_MESSAGE` and `MANAGE_WEBHOOKS` permissions
* Adjust settings in `turbo_config.example.py` and rename to `turbo_config.py`
* Run `retrieve_discord_ids.py` in tools folder to determine your server and role ids
* Add server id and role id to `turbo_config.py`
* Run `turbo_bridge.py` using uWSGI
* (optional) Setup cronjob to run `turbo_cron.py` daily
* (optional) Run `sticks_bot.py` to add discord integration to webchat

Upgrade
-----------
* Run `setup.sh` in folder `setup` to generate the JS and CSS
* Check `setup` folder for `upgradedb-v{major version}{minor version}.sql` if it's your first time upgrading to a specific minor or major revision.
* Run database upgrade scripts in order from the oldest to newest version if you're skipping ahead multiple releases.

Change Log
-----------
#### 2.3.1
Removed legacy chat. Websocket webchat is now considered stable.
#### 2.3.0
Added a websockets webchat with a discord bot to talk to. Removed Python 3.5 support.
#### 2.2.0
Added ACl and admin view to manage AWESOME Piece Theatre password and stream source
#### 2.1.0
Added initial Patreon support for accessing /theatre based on your pledge to a campaign
#### 2.0.1
Minor bug and consistency fixes as well as code cleanup
#### 2.0.0
Added Discord integration, improved security for upcoming integrations (requires DB reset)
#### 1.1.0
Ported turbo-sticks to Python 3.5+ from 2.7
#### 1.0.0
Proper Release after some cleanup.
#### 0.9.0
Beta Release.
