from flask import Flask, render_template, redirect, url_for, flash, abort, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, login_manager
from forms import CreatePostForm, NewUser, Login, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps


app = Flask(__name__)
ckeditor = CKEditor(app)
login_manager = LoginManager()
login_manager.init_app(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


db.session.commit()
##CONFIGURE TABLES
class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique = True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author_name")  ## This is the relationship field

    user_comments = relationship("CommentForm", back_populates="user_information")  ## This is the relationship field

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(Integer, ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_name = relationship("Users", back_populates="posts") ## This is the relationship field
    comment_thread = relationship("CommentForm", back_populates="related_blog")  ## This is the relationship field


class CommentForm(db.Model):
     __tablename__ = "comments"
     id = db.Column(db.Integer, primary_key=True)
     comment = db.Column(db.Text, nullable=False)
     author_id = db.Column(Integer, ForeignKey('users.id'))
     blog_id = db.Column(Integer, ForeignKey('blog_posts.id'))
     user_information = relationship("Users", back_populates="user_comments")  ## This is the relationship field
     related_blog = relationship("BlogPost", back_populates="comment_thread")  ## This is the relationship field


db.create_all()
db.session.commit()


@app.route('/', methods = ['POST', 'GET'])
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

@login_manager.user_loader
def load_user(user_id):
   return Users.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods = ['POST', 'GET'])
def register():
    form = NewUser()
    if form.validate_on_submit():
        e = form.email.data
        faln = form.name.data
        p = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        check_user = Users.query.filter_by(email=e).first()
        if check_user == None:
            db.session.add(Users(email = e, password = p, name = faln))
            db.session.commit()
            website_user = Users.query.filter_by(email=e).first()
            login_user(website_user)

            return redirect(url_for('get_all_posts'))
        else :
            flash('Account for this email already exists.')
            return redirect("/login")

    return render_template("register.html", form = form)



@app.route('/login', methods = ['POST', 'GET'])
def login():
    form = Login()
    if form.validate_on_submit():
        e = form.email.data
        website_user = Users.query.filter_by(email=e).first()
        if website_user != None:
            if check_password_hash(website_user.password, form.password.data):
                login_user(website_user)
                if current_user.is_authenticated:
                    return redirect(url_for('get_all_posts'))
            else :
                flash('Your password is incorrect. Please try again.')

        elif website_user == None:
            flash('Email does not exist in database. Please register.')

    return render_template("login.html", form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CreateCommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            db.session.add(CommentForm(comment=form.comment.data, author_id=current_user.id, blog_id = post_id))
            db.session.commit()
            redirect(f"/post/{post_id}")

        else :
            flash('Please login in order to post comments.')
            redirect("/login")

    return render_template("post.html", post=requested_post, form = form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods = ['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            author_id = current_user.id,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )


        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(debug = True, port=5000)


