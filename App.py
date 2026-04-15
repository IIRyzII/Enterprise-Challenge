"""
This app is for SecureFuture Solutions LTD


"""
import re,io,base64,logging,uuid,os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
load_dotenv()

import bleach,pyotp,qrcode
from flask import (Flask,render_template,redirect,url_for,request,flash,session,abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager,UserMixin,login_user,logout_user,current_user,login_required)

from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.crsf import CSRFProtect
import bcrypt

# This section is the prerequisite for the app ---------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY","change")
_db_url = os.environ.get("DATABASE_URL","sqlite:///secure_future.db")
if _db_url.startswith("postgres://","postgresql://"):
    _db_url = _db_url.replace("postgres://","postgresql://",1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "LoginPage"
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
    role = db.Column(db.String(20), nullable=False, default="employee")

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

# This section is for the routes ---------------------------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("Dashboard"))
    return redirect(url_for("LoginPage"))


#This route will handle the user registration process. It will validate the input and create a new user in the database if the input is valid.
@app.route("/SignUpPage", methods=["GET", "POST"])
def SignUpPage():
    if current_user.is_authenticated:
        return redirect(url_for("Dashboard"))
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        #basic validation to ensure all fields are filled out
        if not username or not email or not password:
            flash("Please fill out all fields.")
            return render_template("SignUpPage.html")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return render_template("SignUpPage.html")

        if role not in ["Employee", "Manager", "Admin"]:
            flash("Please select a valid role.")
            return render_template("SignUpPage.html")
        
        #check if the username or email already exists in the database
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one.")
            return render_template("SignUpPage.html")
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists. Please choose a different one.")
            return render_template("SignUpPage.html")
        
        #if the input is valid, create a new user and add it to the database
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.")
        return render_template("SignUpPage.html")
    return render_template("SignUpPage.html")
#Thus is the end of the SignUpPage route ---------------------------------



#This route will handle the user login process. It will validate the input and log the user in if the input is valid.
@app.route("/LoginPage", methods=["GET", "POST"])
def LoginPage():
    if current_user.is_authenticated:
        return redirect(url_for("Dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")

        user = User.query.filter_by(username=username).first()

        #This provides a generic error message to prevent user enumeration attacks, where an attacker could determine if a username exists based on the error message.
        if not user or not user.check_password(password):
            flash("Invalid username or password. Please try again.")
            return render_template("LoginPage.html")
        
        login_user(user)
        flash("Logged in successfully!")
        return redirect(url_for("Dashboard"))
    return render_template("LoginPage.html")
#Thus is the end of the LoginPage route ---------------------------------

#This will be the dashboard route, which will only be accessible to authenticated users. It will display a welcome message with the user's username as well as logging out functionality. The dashboard will also be the landing page after a successful login.
@app.route("/Dashboard")
@login_required
def Dashboard():
    if current_user.role == "Admin":
        return redirect(url_for("admin_dashboard"))
    elif current_user.role == "Manager":
        return redirect(url_for("manager_dashboard"))
    else:
        return redirect(url_for("employee_dashboard"))

@app.route("/employee")
@login_required
def employee_dashboard():
    return render_template("employee_dashboard.html", username=current_user.username)

@app.route("/manager")
@login_required
def manager_dashboard():
    return render_template("manager_dashboard.html", username=current_user.username)

@app.route("/admin")
@login_required
def admin_dashboard():
    return render_template("admin_dashboard.html", username=current_user.username)
    
@app.route("/Logout")
@login_required
def Logout():
    logout_user()
    flash("You have been logged out.")
    return render_template("LoginPage.html")
#This is the end of the dashboard route ---------------------------------


#This section is for running the app ---------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Database Ready:  securefuture.db")
    app.run(debug=True)
# End of App Running Section ---------------------------------------------
