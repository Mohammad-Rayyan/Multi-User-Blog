import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

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

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

def render_post(response, post):
	response.out.write('<b>' + post.subject + '</b><br>')
	response.out.write(post.content)

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

##### blog stuff

def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	userID	= db.IntegerProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	likeList = db.ListProperty(item_type = int)
	commentList = db.StringListProperty()

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		username = User.by_id(self.userID)
		postID = self.key().id()
		return render_str("post.html", p = self,postId = postID, username = username.name)

	@classmethod
	def by_id(cls, uid):
		return Post.get_by_id(uid, parent = blog_key())

class BlogFront(BlogHandler):
	def get(self):
		posts = greetings = Post.all().order('-created')
		self.render('front.html', posts = posts)

	def post(self):
		comment = self.request.get('comment')


class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect('/')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content, userID = self.user.key().id())
			p.put()
			self.redirect('/%s' % str(p.key().id()))
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
	def get(self):
		self.render("signup-form.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup-form.html', **params)
		else:
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

			self.login(u)
			self.redirect('/')

class Login(BlogHandler):
	def get(self):
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/welcome')
		else:
			msg = 'Invalid login'
			self.render('login-form.html', error = msg)

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/signup')

class Welcome(BlogHandler):
	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/signup')
		
class DeletePost(BlogHandler):
	def get(self):
		postId = self.request.get('postId')
		p = Post.by_id(int(postId))
		if self.user and p:
			if(self.user.key().id() == p.userID):
				db.delete(p)
				self.redirect("/")
			else:
				self.write("you are not allowed to delete.")
		else:
			self.redirect("/login")

class EditPost(BlogHandler):
	def get(self):
		postId = self.request.get('postId')
		p = Post.by_id(int(postId))
		if self.user and p:
			if(self.user.key().id() == p.userID):
				self.render("editPost.html", subject = p.subject, content = p.content)
			else:
				self.write("you are not allowed to edit.")
		else:
			self.redirect("/login")

	def post(self):
		if not self.user:
			self.redirect('/')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			postId = self.request.get('postId')
			p = Post.by_id(int(postId))
			p.subject = subject
			p.content = content
			db.put(p)
			self.redirect('/')
		else:
			error = "subject and content, please!"
			self.render("editPost.html", subject=subject, content=content, error=error)

class LikePost(BlogHandler):
	def get(self):
		postId = self.request.get('postId')
		p = Post.by_id(int(postId))
		if self.user and p:
			if(not (self.user.key().id() == p.userID)):
				if(self.user.key().id() in p.likeList):
					self.write("you are not allowed to like. you liked it before.")
				else:
					p.likeList.append(self.user.key().id())
					db.put(p)
					self.redirect("/")
			else:
				self.write("you are not allowed to like. your post")
		else:
			self.redirect("/login")

class UnLikePost(BlogHandler):
	def get(self):
		postId = self.request.get('postId')
		p = Post.by_id(int(postId))
		if self.user and p:
			if(not (self.user.key().id() == p.userID)):
				if(self.user.key().id() in p.likeList):
					p.likeList.remove(self.user.key().id())
					db.put(p)
					self.redirect("/")
				else:
					self.write("you are not allowed to like. you didn`t like it before.")
			else:
				self.write("you are not allowed to unlike. your post")
		else:
			self.redirect("/login")

class Comment(BlogHandler):
	
	def post(self, post_id):
		comment = self.request.get('comment')
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)
		post.commentList.append(comment)
		db.put(post)
		self.redirect('/')

app = webapp2.WSGIApplication([('/', BlogFront),
							   ('/([0-9]+)', PostPage),
							   ('/newpost', NewPost),
							   ('/signup', Register),
							   ('/login', Login),
							   ('/logout', Logout),
							   ('/welcome', Welcome),
							   ('/deletePost', DeletePost),
							   ('/editPost', EditPost),
							   ('/like', LikePost),
							   ('/unlike', UnLikePost),
							   ('/comment/([0-9]+)', Comment)
							   ],debug=True)
