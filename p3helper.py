import jinja2
import os
import hmac
import random
from string import letters
import hashlib
import re
import webapp2
from google.appengine.ext import ndb


"""
The helper functions, webapp RequestHandler,
and datastore classes are contained in this module
"""


template_dir = os.path.join(os.path.dirname(__file__), 'Templates')

JINJA_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

"""Helper Functions"""


class Utils:
    def render_to_template(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def make_secure_val(self, val):
        secret = 'this_is_a_secret'
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    def check_secure_val(self, secure_val):
        val = secure_val.split("|")[0]
        if secure_val == self.make_secure_val(val):
            return val

    def make_salt(self, length=6):
        return ''.join(random.choice(letters) for x in xrange(length))

    def make_pw_hash(self, name, pw, salt=None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s|%s' % (salt, h)

    def valid_pw(self, name, pw, h):
        salt = h.split('|')[0]
        return h == self.make_pw_hash(name, pw, salt)

    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{4,20}$")
        if username:
            return USER_RE.match(username)

    def valid_password(self, password):
        PASS_RE = re.compile(r"^.{4,20}$")
        if password:
            return PASS_RE.match(password)

    def valid_email(self, email):
        EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        if email:
            return EMAIL_RE.match(email)


"""RequestHandler functions"""


class SiteHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_to_template(self, template, **params):
        return Utils().render_to_template(template, **params)

    def render_page(self, template, **kw):
        self.write(self.render_to_template(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = Utils().make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and Utils().check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User._by_id(int(uid))

"""Datastore classes (User, Post, Comment)"""
# User class
DEFAULT_USERGROUP_NAME = 'default_usergroup'


def usergroup_key(usergroup_name=DEFAULT_USERGROUP_NAME):
    return ndb.Key('UserGroup', usergroup_name)


class User(ndb.Model):
    name = ndb.StringProperty()
    pw_hash = ndb.StringProperty()
    email = ndb.StringProperty()

    @classmethod
    def _by_id(cls, uid):
        u = cls.get_by_id(uid, parent=usergroup_key())
        return u

    @classmethod
    def _by_name(cls, name):
        u = cls.query(cls.name == name).get()
        return u

    @classmethod
    def _register(cls, name, pw, email=None):
        pw_hash = Utils().make_pw_hash(name, pw)
        return cls(parent=usergroup_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def _login(cls, name, pw):
        u = cls._by_name(name)
        if u and Utils().valid_pw(name, pw, u.pw_hash):
            return u

# Post class
DEFAULT_BLOG_NAME = 'default_blog'


def blog_key(blog_name=DEFAULT_BLOG_NAME):
    return ndb.Key('Blog_name', blog_name)


class Post(ndb.Model):
    subject = ndb.StringProperty(required=True)
    author = ndb.StringProperty()
    content = ndb.TextProperty(required=True)

    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

    likes = ndb.IntegerProperty(required=True)
    likers = ndb.StringProperty(repeated=True)

    def _render(self, username):
        self._render_text = self.content.replace('\n', '<br>')
        return Utils().render_to_template("post.html",
                                          p=self,
                                          username=username)

    @classmethod
    def _by_post_name(cls, name):
        u = cls.query(cls.subject == name).get()
        return u

# Comment class


class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    author = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    post_parent_id = ndb.StringProperty()

    def _render(self, username):
        self._render_text = self.content.replace('\n', '<br>')
        return Utils().render_to_template("comment.html",
                                          c=self,
                                          username=username)
