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

