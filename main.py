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
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import logging

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")	
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)


COOKIE_EXP="; Expires=True, 1 Jan 2025 00:00:00 GMT"
class BaseHandler(webapp2.RequestHandler):
    
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val, rem):
        cookie_val = make_secure_val(val)
        remember = ""
        if rem:
        	remember = COOKIE_EXP
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/%s' % (name, cookie_val, remember))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user, remember):
        self.set_secure_cookie('user_id', str(user.key().id()), remember)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class Signup(BaseHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		params = dict(username = self.username, email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "Invalid username"
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "Invalid password"
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your password didn't match"
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "Invalid email"
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
			#self.redirect('/blog/welcome?username=' + username)
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u, False)
            self.redirect('/blog/welcome?username=' + self.username)

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        remember = self.request.get('remember')

        rem = False

        if remember and remember == 'on':
        	rem = True

        u = User.login(username, password)
        if u:
            self.login(u, rem)
            self.redirect('/blog/welcome?username=' + username)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(BaseHandler):
	def get(self):
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))
		logged_username = self.user and self.user.name
		logging.error(logged_username)

		username = self.request.get('username')
		if  valid_username(username) and username == logged_username:
			self.render('welcome.html', username = logged_username)
		elif logged_username == '' or logged_username == None:
			self.redirect('/blog/login')
		else:
			error_username = 'Pillin, %s no es el usuario logado!! El usuario logado es %s' % (username, logged_username)
			self.render('welcome.html', username = logged_username, error_username = error_username)
			
			#self.redirect('/blog/login')

class Init(BaseHandler):
	def get(self):
		self.render('index.html')

app = webapp2.WSGIApplication([
    ('/', Init),
    ('/blog/signup', Register),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/welcome', Welcome)], debug=True)
