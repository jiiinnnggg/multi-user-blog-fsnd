# [START imports]
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
# [END imports]


def render_to_template(template, **params):
    t = JINJA_ENV.get_template(template)
    return t.render(params)

# [START create hash]
secret = 'this_is_a_secret'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split("|")[0]
    if secure_val == make_secure_val(val):
        return val
# [END create hash]


# [START SiteHandler]
class SiteHandler(webapp2.RequestHandler):
    # [start page render methods]
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_to_template(self, template, **params):
        return render_to_template(template, **params)

    def render_page(self, template, **kw):
        self.write(self.render_to_template(template,**kw))
    # [end page render methods]
    
    # [start cookie handling methods]
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name,cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # sets the user_id cookie to a hashed version of the user's db id
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))
    
    # sets the user_id to blank
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

         
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        #if the user_id hash exists, set the part before the "|" it to a variable named 'uid'
        uid = self.read_secure_cookie('user_id')
        #if uid is valid by using the User._by_id method, then set self.user to uid
        self.user = uid and User._by_id(int(uid))
    # [end cookie handling methods]
    
# [END SiteHandler]


# [START USER SECTION, Class User is of type ndb.Model]

# [some functions to make a password hash]
# returns a random 6-letter long salt
def make_salt(length = 6):
    return ''.join(random.choice(letters) for x in xrange(length))
    
# returns a string of format "salt|hash"
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

# pass in a name, a password and a string of format "salt|hash"
# if the string can be re-created with the make_pw_hash function, return True, else False
def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, pw, salt)

# [end, some functions to make a password hash]
   

#the key for the usergroup, allows for there to be multiple groups of Users
DEFAULT_USERGROUP_NAME = 'default_usergroup'

def usergroup_key(usergroup_name=DEFAULT_USERGROUP_NAME):
    """Constructs a Datastore key for a User entity, ie. for multiple groups of Users.
    We use usergroup_name as the key.
    """
    return ndb.Key('UserGroup', usergroup_name)

# [the User class]
class User(ndb.Model):
    name = ndb.StringProperty()
    pw_hash = ndb.StringProperty()
    email = ndb.StringProperty()
    
    # [start User class methods]
        
    # returns the User entity by its uid and parent
    @classmethod
    def _by_id(cls, uid):
        #the variable 'uid' is related to the initialize method from SiteHandler
        u = cls.get_by_id(uid, parent=usergroup_key())
        return u
    
    # returns the User entity by its name property
    @classmethod
    def _by_name(cls, name):
        u = cls.query(cls.name == name).get()
        return u
    
    # create a new User entity by taking in name, pw and email
    # the value stored in the pw_hash property uses the make_pw_hash function
    @classmethod
    def _register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=usergroup_key(),
                   name = name,
                   pw_hash = pw_hash,
                   email = email)
    
    #returns the User entity if the User.name and User.pw_hash is valid
    @classmethod
    def _login(cls, name, pw):
        u = cls._by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
    
# [END USER SECTION, Class User is of type ndb.Model]
        


# [START USER SIGNUP AND REGISTRATION SECTION]

# the user, passowrd and email are set as regex's
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{4,20}$")
PASS_RE = re.compile(r"^.{4,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# pass in a username, then if it matches the USER_RE regex object, return True
def valid_username(username):
    if username:
        return USER_RE.match(username)

# likewise for the password
def valid_password(password):
    if password:
        return PASS_RE.match(password)

# likewise for the email
def valid_email(email):
    if email:
        return EMAIL_RE.match(email)
    
# class SignUp inherits from the SiteHandler class
class SignUp(SiteHandler):
    # first, render the page
    def get(self):
        self.render_page("signup-form.html")
     
    # then, post
    def post(self):
        have_error = False
        
        # get these self properties from the form fields
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        
        params = dict(username = self.username,
                      email = self.email)
        
        # pass in the self.username from the get request, and if it doesn't match the regex,
        # assign the error msg to the 'error_username' in the params dictionary
        # and assign have_error to True
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        
        # likewise for the password
        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        
        # if the password in the verify field doesn't match the password in the password field,
        # return the error msg to 'error_verify'
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        
        # likewise for the email
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # if the have_error is True, render the form again with the error msg(s) in the params
        if have_error:
            self.render_page("signup-form.html", **params)
        else:
            self.done()
    
    # this done function is used below in the Register(SignUp) class  
    def done(self):
        raise NotImplementedError

# class Register inherits from SignUp
class Register(SignUp):

    # if done is not implemented, there is a NotImplementedError
    def done(self):
        
        # using the self.username from the get request, 
        # check if the name exists in the User ndb (by_name method)
        # if the name exists, the entity is assigned to variable u,
        # otherwise u is empty
        u = User._by_name(self.username)
        
        if u:
            msg = 'That user already exists.'
            self.render_page('signup-form.html', error_username=msg)
        else:
            # creates a new User object,
            # uses the register class method from User
            u = User._register(self.username, self.password, self.email)
            
            # store u in DB
            u.put()

            # set the cookie - from class SiteHandler,
            # then redirect to the blog page
            self.login(u)
            self.redirect('/')

# [END USER SIGNUP AND REGISTRATION SECTION]      


# [START LOGIN AND LOGOUT SECTION]

class Login(SiteHandler):
    
    # render the login page
    def get(self):
        self.render_page('login-page.html')

    # get the username and pw
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # from User @classmethod login,
        # returns the user entity if User.name and User.pw_hash are valid
        u = User._login(username, password)
        
        if u:
            # to clarify, self.login is from SiteHandler,
            # same as in the Register class
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'That login is invalid, please try again.'
            self.render_page('login-page.html', error=msg)


class Logout(SiteHandler):
    def get(self):
        # self.logout is from SiteHandler, set the cookie to empty
        self.logout()
        self.redirect('/')


class Welcome(SiteHandler):
    def get(self):
        if self.user:
            self.render_page('welcome.html', username = self.user.name)
        else:
            self.redirect('/login')

# [END LOGIN AND LOGOUT SECTION]



# [START BLOG SECTION]

DEFAULT_BLOG_NAME = 'default_blog'

def blog_key(blog_name=DEFAULT_BLOG_NAME):
    """Constructs a Datastore key for a Post entity, ie. if there are multiple blogs.
    We use blog_name as the key.
    """
    return ndb.Key('Blog_name', blog_name)


# [the Post class for blog entries]
 
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
        return render_to_template("post.html", p=self, username=username)

    @classmethod
    def _by_post_name(cls, name):
        # select * from User where name = name
        u = cls.query(cls.subject == name).get()
        return u


# [Comment class for comments on Post entities]

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
        return render_to_template("comment.html", c=self, username=username)


class NewComment(SiteHandler):    
    def post(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        post = key.get()
        
        post_id_str = str(post.key.id())
        
        c = Comment(parent=post.key)
        c.post_parent_id = post_id_str
        c.author = User._by_name(self.user.name).name
        c.content = self.request.get('comment_content')
        c.put()

        self.redirect('/' + post_id_str + '#comments')


class BlogFront(SiteHandler):
    def get(self):
        # for now, let's just show all the posts
        posts = Post.query()
        posts = posts.order(-Post.created)
        
        if self.user:
            self.render_page("blog-front.html", posts=posts, username = self.user.name)
        else:
            self.render_page("blog-front.html", posts=posts)


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
            

class NewPost(SiteHandler):
    def get(self):
        if self.user:
            self.render_page("new-post.html", username=self.user.name)
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            self.redirect('/')

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


class EditPost(SiteHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()
                       
        self.render_page("edit-post.html", p=p, username=self.user.name)

    def post(self, post_id):
        if not self.user:
            self.redirect('/')
            
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()

        p.subject = self.request.get('subject')
        p.content = self.request.get('content')
    
        p.put()
        
        self.redirect('/%s' % str(p.key.id()))

       
class DeletePost(SiteHandler):
    def get(self, post_id):
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()
                       
        self.render_page("delete-post.html", p=p, username=self.user.name)

    def post(self, post_id):
        if not self.user:
            self.redirect('/')
            
        key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = key.get()
   
        p.key.delete()
        
        self.redirect('/')

class EditComment(SiteHandler):
    def get(self, post_id, comment_id):
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = p_key.get()               
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        self.render_page("edit-comment.html", p=p, c=c, username=self.user.name)

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/')
            
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())                
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        post_id_str = c.post_parent_id

        c.content = self.request.get('content')    
        c.put()
        
        self.redirect('/' + post_id_str + '#comments')


class DeleteComment(SiteHandler):
    def get(self, post_id, comment_id):
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())
        p = p_key.get()               
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        self.render_page("delete-comment.html", p=p, c=c, username=self.user.name)
    
    def post(self, post_id, comment_id): 
        if not self.user:
            self.redirect('/')
                   
        p_key = ndb.Key('Post', int(post_id), parent=blog_key())                
        c_key = ndb.Key(Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        post_id_str = c.post_parent_id
        
        c.key.delete()
        
        self.redirect('/' + post_id_str + '#comments')


class LikePost(SiteHandler):
    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
            
        else:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()
            
            liker = self.user.name

            post.likes = post.likes + 1
            post.likers.append(liker)
            post.put()
            self.redirect('/')


class UnlikePost(SiteHandler):
    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
            
        else:
            key = ndb.Key('Post', int(post_id), parent=blog_key())
            post = key.get()

            liker = self.user.name

            if liker in post.likers:
                post.likes = post.likes - 1
                post.likers.remove(liker)
                post.put()
                self.redirect('/')


# [START app]
app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/([0-9]+)/editpost', EditPost),
                               ('/([0-9]+)/like', LikePost),
                               ('/([0-9]+)/unlike', UnlikePost),
                               ('/([0-9]+)/deletepost', DeletePost),
                               ('/([0-9]+)/comment', NewComment),
                               ('/([0-9]+)/comment/([0-9]+)', CommentPage),
                               ('/([0-9]+)/comment/([0-9]+)/editcomment', EditComment),
                               ('/([0-9]+)/comment/([0-9]+)/deletecomment', DeleteComment),
                               ('/([0-9]+)/like', LikePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/welcome', Welcome),
                               ('/logout', Logout)],
                              debug=True)
# [END app]