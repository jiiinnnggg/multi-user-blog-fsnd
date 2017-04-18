import os
import hmac
import random
from string import letters
import hashlib
import re
from google.appengine.ext import ndb
import jinja2
import webapp2

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

    def make_salt(self, length = 6):
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
        self.write(self.render_to_template(template,**kw))

    def set_secure_cookie(self, name, val):
        cookie_val = Utils().make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name,cookie_val))
    
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
                   name = name,
                   pw_hash = pw_hash,
                   email = email)
    
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
        # insert a line break when rendering to page
        self._render_text = self.content.replace('\n', '<br>')
        return Utils().render_to_template("post.html", p=self, username=username)

    @classmethod
    def _by_post_name(cls, name):
        # select * from User where name = name
        u = cls.query(cls.subject == name).get()
        return u

# Comment class
class Comment(ndb.Model):
    content = ndb.TextProperty(required=True)
    author = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    post_parent_id = ndb.StringProperty()
    
    # this is basically the same method as the _render method in Post
    def _render(self, username):
        # insert a line break when rendering to page
        self._render_text = self.content.replace('\n', '<br>')
        return Utils().render_to_template("comment.html", c=self, username=username)


"""SiteHandler sections"""
# Front page
class BlogFront(SiteHandler):
    def get(self):
        posts = Post.query()
        posts = posts.order(-Post.created)
        
        if self.user:
            self.render_page("blog-front.html", posts=posts, username = self.user.name)
        else:
            self.render_page("blog-front.html", posts=posts)

# Sign up and register new users
class SignUp(SiteHandler):
    def get(self):
        self.render_page("signup-form.html")
     
    def post(self):
        have_error = False

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        params = dict(username = self.username,
                      email = self.email)

        if not Utils().valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        
        if not Utils().valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not Utils().valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render_page("signup-form.html", **params)
        else:
            self.done()
    
    def done(self):
        raise NotImplementedError

class Register(SignUp):
    def done(self):
        u = User._by_name(self.username)
        
        if u:
            msg = 'That user already exists.'
            self.render_page('signup-form.html', error_username=msg)
        else:
            u = User._register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/')

# User log in and log out
class Login(SiteHandler):
    def get(self):
        self.render_page('login-page.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User._login(username, password)
        
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'That login is invalid, please try again.'
            self.render_page('login-page.html', error=msg)

class Logout(SiteHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(SiteHandler):
    def get(self):
        if self.user:
            self.render_page('welcome.html', username = self.user.name)
        else:
            self.redirect('/login')


# Create new post
class NewPost(SiteHandler):
    def get(self):
        if self.user:
            self.render_page("new-post.html", username=self.user.name)
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')
        
        subject = self.request.get('subject')
        content = self.request.get('content')

        blog_name = self.request.get('blog_name', DEFAULT_BLOG_NAME)
        
        if subject and content:
            new_post = Post(parent=blog_key(blog_name),
                     subject=subject,
                     content=content,
                     author=User._by_name(self.user.name).name,
                     likes=0,
                     likers=[]
                     )
            new_post.put()            
            self.redirect('/%s' % str(new_post.key.id()))
                      
        else:
            error = "Include subject and content please!"
            self.render_page("new-post.html", subject=subject, content=content,
                        error=error)

# Display single post
class PostPage(SiteHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        
        comments_query = Comment.query(
            ancestor=post.key).order(Comment.created)
        comments_for_post = comments_query.fetch()     

        if not post:
            self.error(404)
            return
        
        if self.user:
            self.render_page("permalink.html", post=post, comments=comments_for_post, username = self.user.name)
        else:
            self.render_page("permalink.html", post=post, comments=comments_for_post)

# Edit existing post
class EditPost(SiteHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()
                       
        self.render_page("edit-post.html", p=p, username=self.user.name)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
            
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()

        p.subject = self.request.get('subject')
        p.content = self.request.get('content')
    
        p.put()
        
        self.redirect('/%s' % str(p.key.id()))

# Delete existing post      
class DeletePost(SiteHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()
                       
        self.render_page("delete-post.html", p=p, username=self.user.name)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
            
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()
   
        p.key.delete()
        
        self.redirect('/')

# Like an existing post
class LikePost(SiteHandler):
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
            
        else:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            
            liker = self.user.name

            post.likes = post.likes + 1
            post.likers.append(liker)
            post.put()
            self.redirect('/')

# Undo a 'Like'
class UnlikePost(SiteHandler):
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
            
        else:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()

            liker = self.user.name

            if liker in post.likers:
                post.likes = post.likes - 1
                post.likers.remove(liker)
                post.put()
                self.redirect('/')

# Create new commment to a post
class NewComment(SiteHandler):              
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        
        post_id_str = str(post.key.id())
        
        c = Comment(parent=post.key)
        c.post_parent_id = post_id_str
        c.author = User._by_name(self.user.name).name
        c.content = self.request.get('comment_content')
        c.put()

        self.redirect('/' + post_id_str + '#comments')

# Display comment to post as single page        
class CommentPage(SiteHandler):
    def get(self, post_id, comment_id):
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())
                
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        if not c:
            self.redirect('/')
        
        if self.user:
            self.render_page("c_permalink.html", c=c, username=self.user.name)
        else:
            self.render_page("c_permalink.html", c=c)

# Edit existing comment                 
class EditComment(SiteHandler):
    def get(self, post_id, comment_id):
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = p_key.get()               
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        self.render_page("edit-comment.html", p=p, c=c, username=self.user.name)

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')
            
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())                
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        post_id_str = c.post_parent_id

        c.content = self.request.get('content')    
        c.put()
        
        self.redirect('/' + post_id_str + '#comments')

# Delete existing comment
class DeleteComment(SiteHandler):
    def get(self, post_id, comment_id):
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = p_key.get()               
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        self.render_page("delete-comment.html", p=p, c=c, username=self.user.name)
    
    def post(self, post_id, comment_id): 
        if not self.user:
            return self.redirect('/login')
                   
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())                
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        post_id_str = c.post_parent_id        
        c.key.delete()
        
        self.redirect('/' + post_id_str + '#comments')


"""WSGI app"""
app = webapp2.WSGIApplication(
    [('/', BlogFront),
     ('/blog', BlogFront),
     ('/signup', Register),
     ('/login', Login),
     ('/logout', Logout),
     ('/welcome', Welcome),
     ('/newpost', NewPost),
     ('/([0-9]+)', PostPage),
     ('/([0-9]+)/editpost', EditPost),
     ('/([0-9]+)/deletepost', DeletePost),
     ('/([0-9]+)/like', LikePost),
     ('/([0-9]+)/unlike', UnlikePost),
     ('/([0-9]+)/comment', NewComment),
     ('/([0-9]+)/comment/([0-9]+)', CommentPage),
     ('/([0-9]+)/comment/([0-9]+)/editcomment', EditComment),
     ('/([0-9]+)/comment/([0-9]+)/deletecomment', DeleteComment)
     ], debug=True)
