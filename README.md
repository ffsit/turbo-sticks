TURBO Sticks ![Tests](https://github.com/ffsit/turbo-sticks/actions/workflows/tests.yml/badge.svg) [![codecov](https://codecov.io/gh/ffsit/turbo-sticks/branch/master/graph/badge.svg?token=FwmwmUFWnq)](https://codecov.io/gh/ffsit/turbo-sticks) [![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
===========

This authentication bridge authenticates against an OAuth 2.0 provider to present users with member only functionalities.

* Website: [https://sticks.turbo.chat/](https://sticks.turbo.chat/)

NOTES
-----------
* This web application utilizes uwsgi with Python 3.10+ and uses PostgreSQL as its database backend.
* The static content will have to be served using nginx or another HTTP server of your liking, preferably with builtin WSGI support so uWSGI can talk to the proxy using the WSGI protocol, rather than the HTTP protocol.
* The web application may currently not be thread safe, so it is recommended to run it using a single uWSGI worker.

Requirements
-----------
For production use:
* A HTTP server with WSGI support (e.g. nginx)
* uWSGI (including greenlet and gevent plugin)
* Python 3.10+ (including development headers for building psycopg)
* PostgreSQL (including development headers for building psycopg)
* Redis

For compiling static CSS and JS resources:
* [sassc](https://github.com/sass/sassc)
* [css-purge](https://github.com/rbtech/css-purge)
* [uglifyjs3](https://github.com/ckfinder/UglifyJS2)

Setup
-----------
* Install using `pip install .[bot,uwsgi]`
* Run `setup.sh` in folder `setup` to generate the JS and CSS
* Configure nginx to serve /static and forward wsgi on `/<app path>` and `/<api path>`
* Setup Postgres database and user for use with turbo sticks. Run `initdb.sql` to initialize tables
* (optional) Setup Redis with unix socket
* Setup an App in Mastodon with read:accounts privileges
* Setup an App in Discord with identify and guilds.join scope
* Create a Discord Bot and [authorize it](https://discordapp.com/developers/docs/topics/oauth2#bot-authorization-flow) with `CREATE_INSTANT_INVITE`, `MANAGE_ROLES`, `KICK_MEMBERS`, `BAN_MEMBERS`, `MANAGE_MESSAGES`, `VIEW_CHANNEL`, `SEND_MESSAGE` and `MANAGE_WEBHOOKS` permissions
* Adjust settings in `turbo-config.example.yaml` and rename to `turbo-config.yaml`
* Run `retrieve-discord-ids` to determine your server and role ids
* Add server id and role id to `turbo-config.yaml`
* Run `turbo-sticks.wsgi` using uWSGI
* (optional) Setup cronjob to run `sticks-cron` daily
* (optional) Run `sticks-bot` to add discord integration to webchat

Upgrade
-----------
* Run `setup.sh` in folder `setup` to generate the JS and CSS
* Check `setup` folder for `upgradedb-v{major version}{minor version}.sql` if it's your first time upgrading to a specific minor or major revision.
* Run database upgrade scripts in order from the oldest to newest version if you're skipping ahead multiple releases.

Change Log
-----------
#### 4.0.0
Removed Python <3.12 support
Updated version pins
Switched to requirements.txt for pins
#### 3.1.2
Updated version pins
#### 3.1.1
Updated version pins
Disables rendering of Discord discriminator entirely
#### 3.1.0
Updated to pydantic 2.0
Updated version pins
Hides the discriminator for Discord users that no longer have one
Addded Cache-Control: no-store headers to non-public views
#### 3.0.3
Updated version pins
#### 3.0.2
Updated version pins
#### 3.0.1
Tries to make webhook messages in the Discord bot more robust.
#### 3.0.0
Properly packaged sticks.
Added type annotations and tests.
Removed Python <3.10 support.
#### 2.3.1
Removed legacy chat. Websocket webchat is now considered stable.
#### 2.3.0
Added a websockets webchat with a discord bot to talk to.
Removed Python 3.5 support.
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
