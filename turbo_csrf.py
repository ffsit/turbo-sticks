import os
import binascii
from time import time
from hashlib import sha256
from turbo_config import app_secret, expiration_interval, flush_interval

def random_token():
	return binascii.hexlify(os.urandom(64/2))

def sign_token(csrf_token, time_signature, session_token):
	token = csrf_token[:64]
	return token + sha256(token + str(time_signature) + session_token + app_secret).hexdigest()

class TokenClerk:
	def __init__(self):
		self.next_flush = time() + flush_interval 
		self.tokens = {}

	def __flush_if_necessary(self):
		if(self.next_flush < time() and len(self.tokens) > 0):
			for token in self.tokens.keys():
				if(self.tokens[token] + expiration_interval < self.next_flush):
					del self.tokens[token]
			self.next_flush = time() + flush_interval

	def register(self, session_token):
		self.__flush_if_necessary()
		time_signature = time()
		token = sign_token(random_token(), time_signature, session_token)
		self.tokens[token] = time_signature
		return token

	def validate(self, session_token, csrf_token):
		self.__flush_if_necessary()
		if(csrf_token is not None):
			time_signature = self.tokens.get(csrf_token, 0)
			return (csrf_token == sign_token(csrf_token, time_signature, session_token))
		return False
