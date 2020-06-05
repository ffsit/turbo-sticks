DROP TABLE oauth;
DROP TABLE users;
DROP TABLE sessions;

CREATE TABLE oauth (
	app_name varchar(32) UNIQUE,
	access_token varchar(2080), -- encrypted access token
	refresh_token varchar(2080), -- encrypted refresh token
	token_expires_on integer -- unix timestamp
);

CREATE TABLE properties (
	key varchar(128) UNIQUE,
	value varchar(4128) -- encrypted value
);

CREATE TABLE users (
	id bigserial PRIMARY KEY,
	mastodon_id bigint UNIQUE,
	discord_id bigint UNIQUE,
	username varchar(31) UNIQUE,
	app_password varchar(64), -- encrypted password, using password_secret
	app_password_hash varchar(32), -- md5 hash
	banned boolean NOT NULL DEFAULT(FALSE),
);

CREATE TABLE sessions (
	session_token varchar(128) PRIMARY KEY,
	access_token varchar(1024),
	refresh_token varchar(1024),
	token_type varchar(32),
	token_expires_on integer, -- unix timestamp
	session_expires_on timestamp
);
