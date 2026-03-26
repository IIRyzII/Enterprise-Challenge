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