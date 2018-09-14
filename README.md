Turbo Sticks Account Management
===========

This authentication bridge authenticates against an OAuth 2.0 provider to present users with member only functionalities.

* Website: [https://sticks.turbo.chat/](https://sticks.turbo.chat/)

NOTES
-----------

* This web application is being run using uwsgi on Python 2.7 and utilizes PostgreSQL as its database backend.
* The static content will have to be served using nginx or another HTTP server of your liking, preferably with builtin WSGI support so uWSGI can talk to the proxy using the WSGI protocol, rather than the HTTP protocol.
* The web application may currently not be thread safe, so it is recommended to run it using a single uWSGI worker.

Requirements
-----------

For production use:
* A HTTP server with WSGI support (e.g. nginx)
* uWSGI
* Python 2.7
  * oauthlib
  * requests
  * requests_oauthlib
  * psycopg2
  * pycrypto
* PostgreSQL

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
* Setup an App in Mastadon with read:accounts privileges
* Adjust settings in `turbo_config.py`
* Run turbo_sticks.py using uWSGI

Change Log
-----------

#### 0.9.0
Beta Release.
