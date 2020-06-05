-- upgrade db from v2.2.x to v2.3+
ALTER TABLE users
ADD banned boolean NOT NULL DEFAULT(FALSE);
