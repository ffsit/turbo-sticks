# scheduled tasks to be run outside uwsgi
import psycopg2
from turbo_config import db_host, db_name, db_user, db_pass, db_max_age 

connection_params = {
	'host': db_host,
	'database': db_name,
	'user': db_user,
	'password': db_pass
}

db = psycopg2.connect(**connection_params)

# flush old sessions
with db:
	with db.cursor() as cur:
		sql = """
				DELETE
				  FROM sessions
				 WHERE session_expires_on < current_timestamp"""
		cur.execute(sql)
db.close()
