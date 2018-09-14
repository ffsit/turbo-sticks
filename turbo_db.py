import sys
import psycopg2
from psycopg2 import Warning as DBWarning, Error as DBError
from time import time
from turbo_config import db_host, db_name, db_user, db_pass, db_max_age

this = sys.modules[__name__]

# DB Handle
this.db = None
this.db_initialized = None

def init_db():
	# DB connection already initialized and not timed out
	if(this.db is not None and
	   db_max_age is not None and
	   this.db_initialized is not None and
	   this.db_initialized + db_max_age < time()):
		return True

	# Close old connection if it exists
	if(this.db is not None):
		this.db.close()

	try:
		connection_params = {
			'host': db_host,
			'database': db_name,
			'user': db_user,
			'password': db_pass
		}
		this.db = psycopg2.connect(**connection_params)
		this.db_initialized = time()
		return this.db is not None
	except:
		return False
