from flask import Flask, request, make_response, redirect, render_template, session, url_for, flash, abort, jsonify
from flask.ext.security import LoginForm
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from datetime import datetime
from flask_wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_security import Security, current_user, logout_user, SQLAlchemyUserDatastore, UserMixin, RoleMixin, \
    login_required, auth_token_required
from sqlalchemy.exc import IntegrityError
# For CSRF protection in admin modelview forms
from flask_admin.form import SecureForm
from flask_admin.contrib.fileadmin import FileAdmin
import os.path as op
from flask_mail import Mail
from flask_security.utils import encrypt_password, verify_password, login_user
from flask_login import LoginManager
from oauth import OAuthSignIn
import os
import datetime

from urllib.parse import urlparse, urljoin
from flask import request, url_for
from flask_oauthlib.client import OAuth
from flask import Flask
from flask_compress import Compress
from passlib.apps import custom_app_context as pwd_context


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


class NameForm(Form):
    name = StringField('Username: ', validators=[DataRequired()])
    submit = SubmitField('Submit')


app = Flask(__name__)

oauth = OAuth(app)

# compress = Compress()
#
#
# def start_app():
#     app = Flask(__name__)
#     compress.init_app(app)
#     return app

gzip = Compress(app)

app.config["DEBUG"] = True

app.config["SECRET_KEY"] = os.urandom(30)

app.config["SECURITY_CONFIRMABLE"] = True

app.config["SECURITY_TRACKABLE"] = True

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://flask:flaskpassword@localhost/flasktest'

app.config['SECURITY_REGISTERABLE'] = True

app.config['SECURITY_REGISTER_URL'] = '/create_account'

app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'

app.config['SECURITY_PASSWORD_SALT'] = 'RgDUQTs4nzQAQRJf9kevRgDUQTs4nzQAQRJf9kev'

app.config['WTF_CSRF_ENABLED'] = False

app.config['SECURITY_TOKEN_MAX_AGE'] = 1800

app.config['SECURITY_POST_LOGIN_VIEW'] = '/'

app.config['SECURITY_RECOVERABLE'] = True

admin = Admin(app, name='flasktest', template_mode='bootstrap3')
path = op.join(op.dirname(__file__), 'static')
admin.add_view(FileAdmin(path, '/static/', name='Static Files'))

db = SQLAlchemy(app)
lm = LoginManager(app)

lm.login_view = "users.login"

lm.refresh_view = "apps.reauthenticate"
lm.needs_refresh_message = (
    u"To protect your account, please reauthenticate to access this page."
)
lm.needs_refresh_message_category = "info"

app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(minutes=40)

app.config['REMEMBER_COOKIE_SECURE'] = True

bootstrap = Bootstrap(app)

moment = Moment(app)

app.config['OAUTH_CREDENTIALS'] = {
    'facebook': {
        'id': '185436661892522',
        'secret': '82a09d542035ee5f10360846b706cb4a'
    },
    'twitter': {
        'id': 'sGHuFe9gdbcc9hzKYkENt3Je6',
        'secret': 'etGxvdXGegdyO1HFo2XfONEDYNK76QREMcPSHsH7n8l7j2umvJ'
    },
    'google': {
        'id': '552817426609-6rfk2dto43877j0rsa0bnh9d1o1m6esi.apps.googleusercontent.com',
        'secret': 'AwVHLZ6XFw9bMwp-diDJ1_wT'
    },
    'github': {
        'id': '51fe28c094d75307a61a',
        'secret': 'ce7689f6557178eacf9608599d984e0625f3c181'
    }
}

github = oauth.remote_app(
    'github',
    consumer_key='51fe28c094d75307a61a',
    consumer_secret='ce7689f6557178eacf9608599d984e0625f3c181',
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)

app.config['SECURITY_EMAIL_SENDER'] = 'no-reply@localhost'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'arlusishmael@gmail.com'
app.config['MAIL_PASSWORD'] = 'mago.mere'
mail = Mail(app)


@app.route('/login/github')
def github_login():
    return github.authorize(callback=url_for('authorized', _external=True))


@app.route('/callback/github')
def authorized():
    resp = github.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason=%s error=%s resp=%s' % (
            request.args['error'],
            request.args['error_description'],
            resp
        )
    session['github_token'] = (resp['access_token'], '')
    me = github.get('user')
    social_id = me.data['id']
    username = me.data['name']
    email = me.data['email']
    user = User.query.filter_by(social_id="github{0}".format(str(social_id))).first()
    role = Role.query.filter_by(name="client").first()
    if not user:
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            flash('Email already exists')
            return redirect(url_for('login'))
        user = User(social_id='github' + str(social_id), first_name=username, last_name='', email=email, password=None,
                    active=True, created=datetime.datetime.now(), roles=[role, ])
        db.session.add(user)
        db.session.commit()
    next_url = request.args.get('next')
    if social_id is None:
        flash('Authentication failed.')
        return redirect(url_for('login'))
    # Testing if user wants session remembered
    # if remember is None:
    login_user(user, True)
    import sys
    sys.stderr.write("*************")
    sys.stderr.write(str(login_user(user, True)))
    if not is_safe_url(next_url):
        return abort(400)
    return redirect(next_url or url_for('hello_world'))


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __repr__(self):
        return '<Role {0}>'.format(self.name)


roles_users = db.Table('users_roles',
                       db.Column('user_id', db.Integer(), db.ForeignKey('users.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('roles.id')))


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    social_id = db.Column(db.String(64), nullable=True, unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'), )
    last_login_at = db.Column(db.DateTime, nullable=True)
    current_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String, nullable=True)
    current_login_ip = db.Column(db.String, nullable=True)
    login_count = db.Column(db.Integer, nullable=True)

    def __init__(self, email, password, active, roles):
        self.password = password
        self.email = email
        #self.first_name = first_name
        #self.last_name = last_name
        self.active = active
        #self.created = created
        self.roles = roles
        #self.social_id = social_id

    def __repr__(self):
        return '<User {0} {1}>'.format(self.first_name, self.last_name)

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)


@lm.user_loader
def load_user(user_id):
    return User.get(user_id)


Security(app, SQLAlchemyUserDatastore(db, User, Role))
user_datastore = SQLAlchemyUserDatastore(db, User, Role)


#
# # Test user
# @app.before_first_request
# def create_user():
#     db.create_all()
#     try:
#         new_role = user_datastore.create_role(name="superuser", description="Superuser has access to all shit.")
#         new_user = user_datastore.create_user(email='superuser@paycast.com', password='testpassword',
#                                               first_name='Super',
#                                               last_name='User', active=True, confirmed_at=datetime.now())
#         new_user.roles.append(new_role)
#
#         # db.session.add_all([list, of, the, db, transaction])
#         db.session.commit()
#     except IntegrityError:
#         pass


class UserModelView(ModelView):
    form_columns = ('first_name', 'last_name')
    form_base_class = SecureForm

    column_searchable_list = (User.first_name, User.last_name)

    # def init_search(self):
    #     r = super(UserModelView, self).init_search()
    #     self._search_joins['roles'] = Role.name
    #     return r

    def __init__(self, session, **kwargs):
        super(UserModelView, self).__init__(User, session, name='Users', **kwargs)


admin.add_view(ModelView(Role, db.session))
admin.add_view(UserModelView(db.session))


@app.route("/login", methods=["GET", "POST"])
def login():
    """For GET requests, display the login form. For POSTS, login the current user
    by processing the form."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.get(form.email.data)
        if user:
            if pwd_context.encrypt(form.password.data) == user.password:
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                flash('Logged in successfully.')
                next_url = request.args.get('next')
                # next_is_valid should check if the user has valid
                # permission to access the `next` url
                if not is_safe_url(next):
                    return abort(400)
                return redirect(next_url or url_for('index'))
    return render_template("security/login_user.html", form=form)


def get_or_create(session, model, **kwargs):
    '''
    Creates an object or returns the object if exists
    credit to Kevin @ StackOverflow
    from: http://stackoverflow.com/questions/2546207/does-sqlalchemy-have-an-equivalent-of-djangos-get-or-create
    '''
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        instance = model(**kwargs)
        session.add(instance)
        return instance


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'email': user.email})


@app.route('/api/users', methods=['POST'])
def new_user():
    data = request.get_json(force=True)
    first_name = data['first_name']
    last_name = data['last_name']
    email = data['email']
    password = data['password']
    if first_name is None or last_name is None or email is None or password is None:
        abort(400)  # missing arguments
    if User.query.filter_by(email=email).first() is not None:
        abort(400)  # existing user
    new_role1 = get_or_create(db.session, Role,
                              name="client",
                              description="Client user(user who signed up using oauth or email + password)."
                              )
    user = user_datastore.create_user(first_name=first_name, last_name=last_name, password=password, social_id='',
                                      email=email, active=False,
                                      created=datetime.datetime.now(),
                                      roles=[new_role1])
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"email": user.email}), 201, {"Location": url_for('get_user', id=user.id, _external=True)}


@app.route("/")
@app.route("/hello")
@login_required
def hello_world():
    return render_template('index.html', content='Profile Page',
                           current_time=datetime.datetime.now())


@app.route("/test/<queryset>")
@auth_token_required
def search(queryset):
    # To get toke, post credentials to /login
    return queryset


@app.route("/integer/<int:value>")
def int_type(value):
    return "correct"


@app.route("/float/<float:value>")
def float_type(value):
    return "correct"


# Dynamic route that accepts slashes
@app.route("/path/<path:value>")
def path_type(value):
    return "correct"


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/name", methods=["GET", "POST"])
def index():
    form = NameForm()
    if form.validate_on_submit():
        old_name = session.get('name')
        if old_name is not None and old_name != form.name.data:
            flash("You changed your name!")
        session['name'] = form.name.data
        form.name.data = ""
        return redirect(url_for('index'))
    return render_template("name.html", name=session.get('name'), form=form, current_time=datetime.datetime.now())


@app.route("/browser")
def browser():
    user_agent = request.headers.get('User-Agent')
    return 'Your browser is {}'.format(user_agent), 200


@app.route("/response")
def response():
    output = make_response("This document carrie a cookie!")
    output.set_cookie('answer', '42')
    return output


@app.route("/direct")
def direct():
    return redirect("http://duckduckgo.com")


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    oauth = OAuthSignIn.get_provider(provider)
    if provider == 'google':
        social_id, given_name, family_name, email = oauth.callback()
        user = User.query.filter_by(social_id=social_id).first()
        role = Role.query.filter_by(name="client").first()
        if not user:
            user = User(social_id=social_id, first_name=given_name, last_name=family_name, email=email, password=None,
                        active=True, created=datetime.datetime.now(), roles=[role, ])
            db.session.add(user)
            db.session.commit()
    elif provider == 'twitter':
        social_id, username, email = oauth.callback()
        user = User.query.filter_by(social_id=social_id).first()
        role = Role.query.filter_by(name="client").first()
        if not user:
            user = User(social_id=social_id, first_name=username, last_name='', email=email, password=None,
                        active=True, created=datetime.datetime.now(), roles=[role, ])
            db.session.add(user)
            db.session.commit()
    elif provider == 'facebook':
        social_id, username, email = oauth.callback()
        user = User.query.filter_by(social_id="facebook{0}".format(social_id)).first()
        role = Role.query.filter_by(name="client").first()
        if not user:
            email_exists = User.query.filter_by(email=email).first()
            if email_exists:
                flash('Email already exists')
                return redirect(url_for('login'))
            user = User(social_id=social_id, first_name=username, last_name='', email=email, password=None,
                        active=True, created=datetime.datetime.now(), roles=[role, ])
            db.session.add(user)
            db.session.commit()
    # elif provider == 'github':
    #     social_id, username, email = oauth.callback()
    #     user = User.query.filter_by(social_id=social_id).first()
    #     role = Role.query.filter_by(name="client").first()
    #     if not user:
    #         user = User(social_id=social_id, first_name=username, last_name='', email=email, password=None,
    #                     active=True, created=datetime.datetime.now(), roles=[role, ])
    #         db.session.add(user)
    #         db.session.commit()
    if social_id is None:
        flash('Authentication failed.')
        return redirect(url_for('login'))
    login_user(user, True)
    return redirect(url_for('hello_world'))


# # Custom error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


# @login_manager.needs_refresh_handler
# To prevent remember_me sessions from doing sensitive stuff


if __name__ == "__main__":
    app.run(debug=True,
            ssl_context=('/home/arlus/Documents/nginx-selfsigned.crt', '/home/arlus/Documents/nginx-selfsigned.key'))
