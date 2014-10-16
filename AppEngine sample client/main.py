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
import urllib, urlparse
import jwt

# generate your own at http://hey-there-its-me.appspot.com/developer
SECRET_TOKEN = "5Sp-5uguAW5QEmDk8TzIv7VbmrV1gOFNZoOgA1uoDGuQtq28Etny6I4lyDfTll_9O9S8Q_PtLxn7_fhImINAMvgSe5fdasWbyq70YNPdawBd4nMNl6O2wkn0mDaLJCY8t0TZUiBFAOvE3SV3ztWK0tKh00qR7suAelnzrhf87HQ="
PUBLIC_TOKEN = "c15b5cab8e3c4c5681533dc9efa6c673"
LOGIN_SERVER_DOMAIN = "hey-there-its-me.appspot.com"

def create_login_url(callback_url):
    # deconstruct the callback URL and add query string properties 
    query_dict = {"callback": callback_url, "public_token": PUBLIC_TOKEN}
    return "http://{0}/login?{1}".format(LOGIN_SERVER_DOMAIN, urllib.urlencode(query_dict))

def get_identity_name(token):
    if len(token):
        payload = jwt.decode(token, SECRET_TOKEN) # this will throw an exception if the token was not signed with SECRET_TOKEN
        identity = payload['d']['uid'] # "nate@nateparrott.com from Google", for example
        return identity
    else:
        return None

class MainHandler(webapp2.RequestHandler):
    def get(self):
        login_url = create_login_url("/") # direct the user to this URL in order to log in
    	token = self.request.get('jwt', '') # when they finish, we'll redirect them to the callback URL (which is, in this case, the same '/' url), with a 'jwt' key
        identity = get_identity_name(token) # this verifies the identity token was signed using SECRET_TOKEN, and extracts the user identifier (e.g. "nateparro2t@gmail.com from Google")
        self.response.write("""
        	<h1>You are verified to be: <strong>{0}</strong></h1>
        	<a href='{1}'>Log in</a>
            <p>This is admittedly a pretty dumb example, but the point is, you can <a href='http://github.com/nate-parrott/hey-there-its-me'>view the source on Github</a></p>
        	""".format(identity, login_url))

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
