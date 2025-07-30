from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import os
import datetime

app = Flask(__name__)
app.config.update(
    SECRET_KEY="devkey",
    SQLALCHEMY_DATABASE_URI="sqlite:///summaries.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    RATELIMIT_HEADERS_ENABLED=True
)

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = "login"  # This must match route function name
limiter = Limiter(get_remote_address, app=app, default_limits=["20 per hour"])

API_TOKEN = os.getenv("HF_API_TOKEN")  # Set your Hugging Face API token here or in environment

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    summaries = db.relationship("Summary", backref="user", lazy=True)

class Summary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    summary = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# Forms
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class SummarizeForm(FlaskForm):
    text = TextAreaField("Text to Summarize", validators=[DataRequired(), Length(min=20)])
    submit = SubmitField("Summarize")

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def hf_summarize(text):
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    payload = {"inputs": text}
    resp = requests.post("https://api-inference.huggingface.co/models/facebook/bart-large-cnn", json=payload, headers=headers)
    if resp.status_code == 503:
        raise RuntimeError("Model is currently unavailable. Please try again later.")
    if resp.status_code != 200:
        raise RuntimeError(f"Error from Hugging Face API: {resp.status_code}")
    return resp.json()[0]["summary_text"]

# Routes

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists. Please choose a different one.", "warning")
        else:
            # NOTE: For real apps, hash passwords before storing!
            user = User(username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registered successfully! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # NOTE: For real apps, use hashed password check here!
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("error.html", message="Rate limit exceeded, please wait and try again."), 429

@app.route("/", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def dashboard():
    form = SummarizeForm()
    if form.validate_on_submit():
        try:
            summary_text = hf_summarize(form.text.data)
            summary = Summary(text=form.text.data, summary=summary_text, user=current_user)
            db.session.add(summary)
            db.session.commit()
            flash("Text summarized successfully!", "success")
            return redirect(url_for("dashboard"))
        except RuntimeError as e:
            flash(str(e), "danger")
    history = Summary.query.filter_by(user_id=current_user.id).order_by(Summary.timestamp.desc()).all()
    return render_template("dashboard.html", form=form, history=history)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
