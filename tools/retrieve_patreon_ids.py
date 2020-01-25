# this only works if you've supplied a currently valid access and refresh token for patreon in the config
import os
import sys
import json
import requests

sys.path.insert(1, os.path.join(sys.path[0], '..'))
import turbo_patreon
import turbo_db

turbo_db.init_db()
db = turbo_db.db

if(db is not None):
	turbo_patreon.init_oauth(db)
	campaigns = turbo_patreon.get_campaigns(db)
	for campaign in campaigns:
		print('========================================')
		print('Campaign: %s (%s)' % (campaign['creation_name'], campaign['id']))
		for tier in campaign['tiers']:
			print('    Tier: $%d+ %s (%s)' % (tier['amount_cents']//100, tier['title'], tier['id']))
		print('========================================')
else:
	print('Failed to establish connection to database.')
