import os
from hashlib import md5
from Crypto.Cipher import AES
from turbo_config import app_secret

# Password Helpers
def generate_app_password():
	# Chosen alphabet attempts to avoid ambiguous or url unsafe characters
	# Also its length of 64 makes sure each character is hit evenly
	alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789*!-.+_'
	seed = os.urandom(16)
	return ''.join(alphabet[ord(char) % len(alphabet)] for char in seed)

def encrypt(plaintext):
	cipher = AES.new(app_secret)
	return cipher.encrypt(plaintext).encode('hex')

def decrypt(ciphertext):
	cipher = AES.new(app_secret)
	return cipher.decrypt(ciphertext.decode('hex'))

# Begin class User
class User:
	def __init__(self, account, db):
		if(account is None or db is None):
			return

		self.db = db
		self.account = account
		self.mastodon_id = account.get('id', 0)
		self.username = account.get('username', '')
		self.uid = User.get_user_id(self.mastodon_id, self.db)
		if(self.uid > 0):
			self.__load(self.uid)
		else:
			self.__create_new_user()

	# Use this, so you get None if account is None
	@classmethod
	def create(cls, account, db):
		if(account is None or db is None):
			return None
		return cls(account, db)

	# Private Helper Methods
	def __load(self, uid):
		if(self.db is not None and uid > 0):
			with self.db:
				with self.db.cursor() as cur:
					sql = """
							SELECT username,
							       app_password,
							       app_password_hash
							  FROM users
							 WHERE id = %s"""
					cur.execute(sql, (uid,))
					row = cur.fetchone()
					if(row is None):
						self = None
						return
					self.uid = uid
					self.username = row[0]
					self.app_password = row[1]
					self.app_password_hash = row[2]
					self.app_password_plain = decrypt(self.app_password)
					self.__update_username_if_necessary()

	def __update_username_if_necessary(self):
		if(self.db is not None and self.account is not None and self.uid > 0):
			new_username = self.account.get('username', '')
			if(len(self.username) > 0 and new_username != self.username):
				self.username = new_username
				with self.db:
					with self.db.cursor() as cur:
						sql = """
								UPDATE users
								   SET username = %s
								 WHERE id = %s"""
						cur.execute(sql, (self.username, self.uid))

	def __create_new_user(self):
		if(self.db is not None and self.mastodon_id > 0 and len(self.username) > 0):
			self.app_password_plain = generate_app_password()
			self.username = self.username
			self.app_password = encrypt(self.app_password_plain)
			self.app_password_hash = md5(self.app_password_plain).hexdigest()

			with self.db:
				with self.db.cursor() as cur:
					sql = """
							INSERT INTO users
							(
								mastodon_id,
								username,
								app_password,
								app_password_hash
							)
							VALUES
							(
								%s,
								%s,
								%s,
								%s
							)"""

					cur.execute(sql,
						(
							self.mastodon_id,
							self.username,
							self.app_password,
							self.app_password_hash
						))
	# Public Methods
	def reset_app_password(self):
		if(self.db is not None and self.uid > 0):
			self.app_password_plain = generate_app_password()
			self.app_password = encrypt(self.app_password_plain)
			self.app_password_hash = md5(self.app_password_plain).hexdigest()

			with self.db:
				with self.db.cursor() as cur:
					sql = """
							UPDATE users
							   SET app_password = %s,
							       app_password_hash = %s
							 WHERE id = %s"""

					cur.execute(sql,
						(
							self.app_password,
							self.app_password_hash,
							self.uid
						))

	# Static Methods
	@staticmethod
	def get_user_id(mastodon_id, db):
		if(db is not None and mastodon_id > 0):
			with db:
				with db.cursor() as cur:
					sql = 'SELECT id FROM users WHERE mastodon_id = %s'
					cur.execute(sql, (mastodon_id,))
					row = cur.fetchone()
					if(row is not None and row[0] > 0):
						return row[0]
					return 0
		return None
# End class User