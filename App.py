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

        #basic validation to ensure all fields are filled out
        if not username or not email or not password:
            flash("Please fill out all fields.")
            return render_template("SignUpPage.html")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return render_template("SignUpPage.html")
        
        #check if the username or email already exists in the database
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one.")
            return render_template("SignUpPage.html")
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists. Please choose a different one.")
            return render_template("SignUpPage.html")
        
        #if the input is valid, create a new user and add it to the database
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully! Please log in.")
        return redirect(url_for("LoginPage"))
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
@login_required # this line ensures that only authenticated users can access the dashboard
def Dashboard():
    return render_template("Dashboard.html", username=current_user.username)

@app.route("/Logout")
@login_required
def Logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("LoginPage"))
#This is the end of the dashboard route ---------------------------------


#This section is for running the app ---------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Database Ready:  seecurefuture.db")
    app.run(debug=True)
# End of App Running Section ---------------------------------------------