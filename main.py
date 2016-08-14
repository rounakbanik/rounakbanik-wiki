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
import os
import re
import cgi
import random
import hashlib
import hmac
import logging
import json
from string import letters

import jinja2
import time

from google.appengine.ext import db
from google.appengine.api import memcache

PAGE_RE = r'((?:[a-zA-Z0-9_-]+/?)*)'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
POST_RE = re.compile(r"^/blog/(\d+)")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, cookie_val):
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        return self.request.cookies.get(name)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('uid')
        self.user = uid and User.by_id(int(uid))

class User(db.Model):
   username = db.StringProperty(required = True)
   pw_hash = db.StringProperty(required = True)
   email = db.StringProperty()
   created = db.DateTimeProperty(auto_now_add = True)

   @classmethod
   def by_id(cls, uid):
        return User.get_by_id(uid)

class WikiPost(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add= True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", wikipost= self)

class WikiPage(WikiHandler):
	def get(self, subject):
		wikipost = db.GqlQuery('select * from WikiPost where subject=:1', subject).get()
		if not self.user:
			if not wikipost:
				self.write('This page does not exist. To create this page and edit, please register or login.')
			else:
				self.render('post_unregistered.html', wikipost=wikipost)
		else:
			if not wikipost:
				self.redirect('/_edit/'+subject)
			else:
				self.render('post.html', wikipost=wikipost)


class Signup(WikiHandler):
    def get(self):
        if self.user:
            self.redirect('/')
        else:
            self.render('signup.html')

    def post(self):
        username= self.request.get('username')
        password = self.request.get('password')
        verify= self.request.get('verify')
        email = self.request.get('email')

        username_error= self.validate_username(username)
        password_error = self.validate_password(password, verify)
        verify_error = self.validate_verify(verify, password)
        email_error = self.validate_email(email)

        if (not username_error) and (not password_error) and (not verify_error) and (not email_error):
            pw_hash = hashlib.md5(password).hexdigest()

            user = User(username=username, pw_hash=pw_hash, email=email)
            user.put()
            self.set_cookie('username', str(username))
            self.set_cookie('pw_hash', str(pw_hash))
            self.set_cookie('uid', str(user.key().id()))

            self.redirect('/')
        else:
            self.render('signup.html', username_error=username_error, password_error=password_error, verify_error=verify_error, email_error=email_error)

    def validate_username(self,username):
        if USER_RE.match(username):
            user = db.GqlQuery("select * from User where username=:1", username).get()
            if user:
                return "Sorry! This username already exists."
            else:
                return ""
        return "Username is not valid."

    def validate_password(self,password, verify):
        if PASSWORD_RE.match(password):
            return ""
        return "Password is not valid"

    def validate_verify(self,verify, password):
        if verify == password:
            return ""
        return "Passwords do not match"

    def validate_email(self, email):
    	if EMAIL_RE.match(email) or not email:
    		return ""
    	return "Email is not valid"



class Login(WikiHandler):
	def get(self):
		if self.user:
			self.redirect('/')
		else:
			self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		pw_hash = hashlib.md5(password).hexdigest()

		user = db.GqlQuery('select * from User where username=:1 and pw_hash=:2', username, pw_hash).get()

		if user:
			self.set_cookie('username', str(username))
			self.set_cookie('pw_hash', str(pw_hash))
			self.set_cookie('uid', str(user.key().id()))
			self.redirect('/')
		else:
			self.render('login.html', error='Incorrect username or password')

		
class Logout(WikiHandler):
    def get(self):
        self.set_cookie('username', '')
        self.set_cookie('pw_hash', '')
        self.set_cookie('uid', '')
        referrer = self.request.headers.get('referer')
        if referrer:
        	self.redirect(referrer)
        else:
        	self.redirect('/')


class EditPage(WikiHandler):
	def get(self, subject):
		if not self.user:
			self.redirect('/')
		else:
			wikipost = db.GqlQuery('select * from WikiPost where subject=:1', subject).get()
			if wikipost:
				content = wikipost.content
			else:
				content = ""
			self.render('edit.html', content=content)

	def post(self, subject):
		if not self.user:
			self.redirect('/')
		else:
			content = self.request.get('content')
			if not content:
				error = "Content cannot be blank"
				self.render('edit.html', error=error)
			else:
				wikipost = WikiPost(subject=subject, content=content)
				wikipost.put()
				time.sleep(1)
				self.redirect('/'+subject)

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit/' + PAGE_RE, EditPage),
                               ('/' + PAGE_RE, WikiPage),
                               ],
                              debug=True)
