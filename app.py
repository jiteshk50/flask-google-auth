from flask import Flask, redirect, url_for, session, render_template, request, flash
from flask_session import Session
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configurations
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Session(app)

# Database setup
db = SQLAlchemy(app)

# OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',  # Explicitly provide JWKS URI
    client_kwargs={'scope': 'openid email profile'}
)

# Token Serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)  # Nullable for Google users
    name = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)  # For Google users
    confirmed = db.Column(db.Boolean, default=False)

# Forms
class SignupForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

# Routes
@app.route('/')
def index():
    user = session.get('user')
    if user:
        return render_template('index.html', user=user)
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            email=form.email.data,
            password=hashed_password,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please confirm your email.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user'] = {'id': user.id, 'name': user.name, 'email': user.email}
            return redirect(url_for('index'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/login/google')
def login_with_google():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()

    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(
            email=user_info['email'],
            name=user_info['name'],
            profile_pic=user_info['picture']
        )
        db.session.add(user)
        db.session.commit()

    session['user'] = {'id': user.id, 'name': user.name, 'email': user.email}
    return redirect(url_for('index'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            flash(f'Reset link sent to {user.email}. Link: {reset_link}', 'info')
        else:
            flash('No account found with that email.', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPasswordForm()
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if form.validate_on_submit():
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('Password reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
    except Exception as e:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('reset_password.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
