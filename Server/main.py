#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
from template import template
import os, base64, hashlib, uuid, urlparse, urllib, json, datetime
from google.appengine.ext import ndb
from google.appengine.api import users
import jwt

class Keypair(ndb.Model):
	domains = ndb.TextProperty() # separated by spaces
	secret_token = ndb.TextProperty()
	public_token = ndb.StringProperty()
	display = ndb.StringProperty()

	def allows_netloc(self, netloc):
		if netloc.startswith('localhost:'):
			netloc = 'localhost'
		ds = [d for d in self.domains.split(' ') if len(d)>0]
		return netloc in ds

def new_keypair(domains, secret='', display=''):
	if len(secret) == 0:
		secret = base64.urlsafe_b64encode(os.urandom(128))
	secret = str(secret) # ensure !unicode
	kp = Keypair(secret_token=secret, public_token=uuid.uuid4().hex, domains=domains, display=display)
	kp.put()
	return kp

class MainHandler(webapp2.RequestHandler):
	def get(self):
		# on /, we implement a simple auth system
		secret = 'TBTCUdWMdlqmXI20amAE_tnTqbuniB4PPkAGQY7388PXxZM3eFDW3gE9xKCPNWv-m1LrOzLuFY3MDyCRdj3gWiNAtgT6gJ3AgE-JgasdLfTpUbbylHXTSPFK7MxlxTNt4Y7OARLCucNFmRuNqoIViKvwb9tjggcK7NqZQprzLgM='
		public = '18c2d2ba4c7f41df9587fa0188d26959'

		token = self.request.get('jwt')
		if len(token):
			self.response.set_cookie("jwt", token)
		elif 'jwt' in self.request.cookies:
			token = self.request.cookies['jwt']
		if len(token):
			identity = jwt.decode(token, secret)['d']['uid']
		else:
			identity = None
		self.response.write(template("index.html", {"identity": identity, "auth_url": "/login?callback=%2F&public_token="+public}))

class DeveloperHandler(webapp2.RequestHandler):
	def get(self):
		self.response.write(template("developer.html"))
	def post(self):
		domains = self.request.get('domains')
		secret = self.request.get('secret')
		display = self.request.get('display')
		self.response.write(template("creds.html", {"keypair": new_keypair(domains, secret, display), "domains": domains, "display": display}))

def full_callback_url(callback_passed_in, referrer, keypair, identity):
	parsed = urlparse.urlparse(callback_passed_in)
	if parsed.netloc == '':
		if referrer:
			referrer_parsed = urlparse.urlparse(referrer)
			parsed = parsed._replace(netloc=referrer_parsed.netloc, scheme=referrer_parsed.scheme)
	if not keypair.allows_netloc(parsed.netloc):
		return None
	query_dict = urlparse.parse_qs(parsed.query)
	payload = {
		"iat": datetime.datetime.utcnow(),
		"d": {"uid": identity},
		"v": 0
		}
	print "JWT: ", jwt.encode(payload, keypair.secret_token)
	query_dict['jwt'] = jwt.encode(payload, keypair.secret_token)
	parsed = parsed._replace(query=urllib.urlencode(query_dict))
	return urlparse.urlunparse(parsed).encode('utf-8')

def do_redirect(handler, identity):
	data = json.loads(handler.request.get("data"))
	keypairs = list(Keypair.query(Keypair.public_token == data['public_token']))
	if len(keypairs):
		callback_url = full_callback_url(data['callback'], data['referrer'], keypairs[0], identity)
		if callback_url:
			handler.redirect(callback_url)
	else:
		pass

class LoginHandler(webapp2.RequestHandler):
	def get(self):
		if self.request.host == 'hey-there-its.me':
			return self.redirect('http://hey-there-its-me.appspot.com' + self.request.path_qs)
		query_args = {}
		query_args['data'] = json.dumps(
			{"public_token": self.request.get('public_token'), 
			"callback": self.request.get('callback'), 
			"referrer": self.request.referrer})
		providers = []
		for name, openid_url, font_awesome in [
					("Google", "https://www.google.com/accounts/o8/id", "fa-google"), 
					("Yahoo", "yahoo.com", "fa-yahoo"), 
					("Stack Exchange", "openid.stackexchange.com", "fa-stack-exchange")]:
			providers.append({"name": name, "font_awesome": font_awesome, "url": users.create_login_url("/openid_auth_response?" + urllib.urlencode(query_args), federated_identity=openid_url)})
		template_args = {
			"providers": providers
		}
		self.response.write(template("login.html", template_args))

class OpenIDAuthResponseHandler(webapp2.RequestHandler):
	def get(self):
		user = users.get_current_user()
		if user:
			identity = "openid:{0}".format(user.email())
			do_redirect(self, identity)
		else:
			self.redirect('/login?' + self.request.query_string)

class DocsHandler(webapp2.RequestHandler):
	def get(self):
		self.response.write(template("docs.html"))

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/developer', DeveloperHandler),
	('/login', LoginHandler),
	('/openid_auth_response', OpenIDAuthResponseHandler),
	('/docs', DocsHandler)
], debug=True)
