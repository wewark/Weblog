import os
import webapp2
import jinja2
import cgi
import re
import urllib2
import json
import hashlib
import hmac
import string
import random
import logging
import time
from xml.dom import minidom
from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),)

# Functions
def hash_str(s, salt):
	return hmac.new(salt, s).hexdigest()

salt_size = 5
def make_secure_val(s, salt = ""):
	if salt == "":
		salt = ''.join(
			random.choice(string.ascii_lowercase + string.digits)
			for i in range(salt_size))
	return "%s|%s%s" % (s, hash_str(s, str(salt)), salt)

def check_secure_val(val):
	l = val.split('|')[0]
	if make_secure_val(l, val[-salt_size:]) == val:
		return l

def hashpassword(password, salt = ""):
	if salt == "":
		salt = ''.join(
			random.choice(string.ascii_lowercase + string.digits)
			for i in range(salt_size))
	return "%s%s" % (hash_str(password, str(salt)), salt)

def compare_password(password, hashed):
	return hashpassword(password, hashed[-salt_size:]) == hashed

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_username(username):
	return username and USER_RE.match(username)
def valid_password(password):
	return password and PASS_RE.match(password)
def valid_email(email):
	return not email or EMAIL_RE.match(email)

# Data bases
class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()
class Pages(db.Model):
	name = db.StringProperty(required = True)
	content = db.TextProperty(required = True)

# Handles all output, don't edit
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)

		# Read user id from cookies
		user_id_cookie_str = self.request.cookies.get('user_id')
		username = get_username(user_id_cookie_str)
		params['username_top'] = username

		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class Signup(Handler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		params = dict(username = username, email = email, page = None)

		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True
		if not valid_password(password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True
		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		# check if user exists
		user = db.GqlQuery("SELECT * FROM Users WHERE username = :username",username = username).get()
		if user != None:
			params['error_username'] = "Username is already taken."
			have_error = True
		else:
			# add user to database
			user = Users(
				username = username,
				password = hashpassword(password),
				email = email)
			user.put()

		params['page'] = None
		if have_error:
			self.render('signup-form.html', **params)
		else:
			# set cookie
			self.response.headers.add_header('Set-Cookie',
				'user_id=%s' % make_secure_val(str(user.key().id())))
			self.redirect('/')

class Login(Handler):
	def get(self):
		self.render('login-form.html', page = None)

	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')

		user = db.GqlQuery("SELECT * FROM Users WHERE username = :username",username = username).get()
		if user == None or not compare_password(password, user.password):
			error = "Wrong username or password"
			self.render('login-form.html', username = username, error = error, page = None)
		else:
			# set cookie
			self.response.headers.add_header('Set-Cookie',
				'user_id=%s' % make_secure_val(str(user.key().id())))
			self.redirect('/')

class Logout(Handler):
	def get(self):
		user_id = self.request.cookies.get('user_id')
		self.response.headers.add_header('Set-Cookie',
			'user_id=s; access_token=deleted; Expires=Thu, 01-Jan-1970 00:00:00 GMT')
		self.redirect('/')

def get_username(user_id_cookie_str):
	username = None
	if user_id_cookie_str:
		user_id_val = check_secure_val(user_id_cookie_str)
		if user_id_val:
			user_id = int(user_id_val)
			username = memcache.get(user_id_val)
			if username is None:
				logging.error('DB QUERY')
				username = Users.get_by_id(user_id).username
				memcache.set(user_id_val, username)
	return username

def get_page(name):
	page = memcache.get(name)
	if page is None:
		logging.error("DB QUERY")
		page = Pages.all().filter('name =', name).get()
		if page:
			logging.error(page.content)
			memcache.set(name, page)
	return page

class Home(Handler):
	def get(self, name):
		if not name: name = 'home'
		page = get_page(name)
		if page is None:
			self.redirect('/_edit/' + name)
		self.render('home.html', page = page)

class EditPage(Handler):
	def get(self, name):
		if not name: name = 'home'
		page = get_page(name)
		self.render('edit-form.html', page = page)

	def post(self, name):
		if not name or name == '/':
			name = 'home'
		else:
			name = name[1:]
		page = get_page(name)
		if page:
			page.content = self.request.get('content')
		else:
			page = Pages(name = name, content = self.request.get('content'))
		logging.error('DB QUERY')
		page.put()
		memcache.set(name, page)
		if name == 'home':
			self.redirect('/')
		else:
			self.redirect('/' + name)

#PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
	('/signup', Signup),
	('/login', Login),
	('/logout', Logout),
	('/_edit(/\S+|/|)', EditPage),
	('/(\S+|)', Home),
	#(PAGE_RE, WikiPage),
], debug=True)
