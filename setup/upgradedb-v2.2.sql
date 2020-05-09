-- upgrade db from v2.1.x to v2.2+
CREATE TABLE properties (
	key varchar(128) UNIQUE,
	value varchar(4128) -- encrypted value
);

ALTER TABLE oauth
ADD UNIQUE (app_name);
