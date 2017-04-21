import p3helper as tools

"""SiteHandler sections"""
# Front page


class BlogFront(tools.SiteHandler):
    def get(self):
        posts = tools.Post.query()
        posts = posts.order(-tools.Post.created)

        if self.user:
            self.render_page("blog-front.html",
                             posts=posts,
                             username=self.user.name)
        else:
            self.render_page("blog-front.html", posts=posts)

# Sign up and register new users


class SignUp(tools.SiteHandler):
    def get(self):
        self.render_page("signup-form.html")

    def post(self):
        have_error = False

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not tools.Utils().valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not tools.Utils().valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not tools.Utils().valid_email(self.email):
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
        u = tools.User._by_name(self.username)

        if u:
            msg = 'That user already exists.'
            self.render_page('signup-form.html', error_username=msg)
        else:
            u = tools.User._register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/')

# User log in and log out


class Login(tools.SiteHandler):
    def get(self):
        self.render_page('login-page.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = tools.User._login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'That login is invalid, please try again.'
            self.render_page('login-page.html', error=msg)


class Logout(tools.SiteHandler):
    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(tools.SiteHandler):
    def get(self):
        if self.user:
            self.render_page('welcome.html', username=self.user.name)
        else:
            self.redirect('/login')


"""login decorator"""
def login_required(some_function):
    def login(self, *args, **kwargs):
        if not self.user:
            self.redirect('/login')
        else:
            some_function(self, *args, **kwargs)
    return login

# Create new post
class NewPost(tools.SiteHandler):
    @login_required
    def get(self):
            self.render_page("new-post.html", username=self.user.name)

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        blog_name = self.request.get('blog_name', tools.DEFAULT_BLOG_NAME)

        if subject and content:
            new_post = tools.Post(
                        parent=tools.blog_key(blog_name),
                        subject=subject,
                        content=content,
                        author=tools.User._by_name(self.user.name).key,
                        authname=tools.User._by_name(self.user.name).name,
                        likes=0,
                        likers=[]
                        )
            new_post.put()
            self.redirect('/%s' % str(new_post.key.id()))

        else:
            error = "Include subject and content please!"
            self.render_page("new-post.html",
                             subject=subject,
                             content=content,
                             error=error)

# Display single post


class PostPage(tools.SiteHandler):
    def get(self, post_id):
        key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        post = key.get()
        post_auth = post.author.get()

        comments_query = tools.Comment.query(
            ancestor=post.key).order(tools.Comment.created)
        comments_for_post = comments_query.fetch()

        if not post:
            self.error(404)
            return

        if self.user:
            self.render_page("permalink.html",
                             post=post,
                             auth=post_auth,
                             comments=comments_for_post,
                             username=self.user.name)
        else:
            self.render_page("permalink.html",
                             post=post,
                             auth=post_auth,
                             comments=comments_for_post)

# Edit existing post


class EditPost(tools.SiteHandler):
    def get(self, post_id):
        key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        p = key.get()
        
        if p is not None:
            self.render_page("edit-post.html", p=p, username=self.user.name)
        else:
            return self.redirect('/blog')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        p = key.get()

        if p is not None:
            if self.user.key == p.author:
                p.subject = self.request.get('subject')
                p.content = self.request.get('content')
                p.put()
                self.redirect('/%s' % str(p.key.id()))
        else:
            return self.redirect('/blog')

# Delete existing post


class DeletePost(tools.SiteHandler):
    def get(self, post_id):
        key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        p = key.get()
        
        if p is not None:
            self.render_page("delete-post.html", p=p, username=self.user.name)
        else:
            return self.redirect('/blog')

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        p = key.get()
        
        if p is not None:
            if self.user.key == p.author:
                p.key.delete()
                self.redirect('/')
        else:
            return self.redirect('/blog')

# Like an existing post


class LikePost(tools.SiteHandler):
    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
            post = key.get()

            # Can't like your own post
            author = post.author
            liker = self.user.name

            if (author == liker) or (liker in post.likers):
                self.redirect('/nolike')
            else:
                post.likes = post.likes + 1
                post.likers.append(liker)
                post.put()
                self.redirect('/')

# Undo a 'Like'


class UnlikePost(tools.SiteHandler):
    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
            post = key.get()

            liker = self.user.name

            if liker in post.likers:
                post.likes = post.likes - 1
                post.likers.remove(liker)
                post.put()
                self.redirect('/')


class NoLike(tools.SiteHandler):
    def get(self):
        if self.user:
            self.render_page("no-like.html",
                             username=self.user.name)
        else:
            self.render_page("no-like.html")

# Create new commment to a post


class NewComment(tools.SiteHandler):
    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        post = key.get()

        post_id_str = str(post.key.id())

        c = tools.Comment(parent=post.key)
        c.post_parent_id = post_id_str
        c.author = tools.User._by_name(self.user.name).key
        c.authname = tools.User._by_name(self.user.name).name
        c.content = self.request.get('comment_content')
        c.put()

        self.redirect('/' + post_id_str + '#comments')

# Display comment to post as single page


class CommentPage(tools.SiteHandler):
    def get(self, post_id, comment_id):
        p_key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        c_key = tools.ndb.Key(tools.Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        cauth = c.author.get()

        if not c:
            return self.redirect('/')

        if self.user:
            self.render_page("c_permalink.html",
                             c=c,
                             username=self.user.name)
        else:
            self.render_page("c_permalink.html",
                             c=c)

# Edit existing comment


class EditComment(tools.SiteHandler):
    def get(self, post_id, comment_id):
        p_key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        p = p_key.get()
        c_key = tools.ndb.Key(tools.Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        if c is not None:
            self.render_page("edit-comment.html",
                         p=p, c=c, username=self.user.name)
        else:
            self.redirect('/%s' % str(p.key.id()))

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        p_key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        c_key = tools.ndb.Key(tools.Comment, int(comment_id), parent=p_key)
        c = c_key.get()
        
        if c is not None:
            if self.user.key == c.author:
                post_id_str = c.post_parent_id
                c.content = self.request.get('comment_content')
                c.put()
                self.redirect('/' + post_id_str + '#comments')
        else:
            self.redirect('/' + post_id_str )

# Delete existing comment


class DeleteComment(tools.SiteHandler):
    def get(self, post_id, comment_id):
        p_key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        p = p_key.get()
        c_key = tools.ndb.Key(tools.Comment, int(comment_id), parent=p_key)
        c = c_key.get()

        self.render_page("delete-comment.html",
                         p=p, c=c, username=self.user.name)

    def post(self, post_id, comment_id):
        if not self.user:
            return self.redirect('/login')

        p_key = tools.ndb.Key('Post', int(post_id), parent=tools.blog_key())
        c_key = tools.ndb.Key(tools.Comment, int(comment_id), parent=p_key)
        c = c_key.get()

        if c is not None:
            if self.user.key == c.author:
                post_id_str = c.post_parent_id
                c.key.delete()
                self.redirect('/' + post_id_str + '#comments')
        else:
            self.redirect('/' + post_id_str )


"""WSGI app"""
app = tools.webapp2.WSGIApplication(
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
     ('/nolike', NoLike),
     ('/([0-9]+)/comment', NewComment),
     ('/([0-9]+)/comment/([0-9]+)', CommentPage),
     ('/([0-9]+)/comment/([0-9]+)/editcomment', EditComment),
     ('/([0-9]+)/comment/([0-9]+)/deletecomment', DeleteComment)
     ], debug=True)
