"""
This app is for SecureFuture Solutions LTD


"""

from flask import Flask, render_template, redirect, url_for, request,flash

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)

import bcrypt

# This section is the prerequisite for the app ---------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = ""
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_future.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
# End of Prerequisite Section ---------------------------------------------


# This section is for the database models ---------------------------------
class User(UserMixin, db.Model):

    """
    Passwords will never be stored in plain text. They will be hashed using bcrypt before being stored in the database.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def set_password(self,plaintext):
        #This both hashes and salts the password before storing it in the database
        self.password = bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self,plaintext):
        #This will return True if the password is correct, False otherwise
        return bcrypt.checkpw(plaintext.encode('utf-8'), self.password.encode('utf-8'))
    
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
# End of Database Models Section ---------------------------------------------