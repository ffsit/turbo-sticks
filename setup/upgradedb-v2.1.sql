-- upgrade db from v2.0.x to v2.1+
CREATE TABLE oauth (
	app_name varchar(32),
	access_token varchar(2080), -- encrypted access token
	refresh_token varchar(2080), -- encrypted refresh token
	token_expires_on integer -- unix timestamp
);
