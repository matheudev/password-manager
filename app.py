import os
import hashlib
import base64
import re
import secrets
import string

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")


# Number of iterations for encryption
iterations = 100000


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Homepage"""

    # Get user's id
    user_id = session["user_id"]

    return render_template("index.html")


@app.route("/add-password", methods=["GET", "POST"])
@login_required
def add_password():
    """Add password to the database"""

    if request.method == "POST":

        user_id = session["user_id"]
        website = request.form.get("website")
        username = request.form.get("username")
        password = request.form.get("password")
        salt = os.urandom(16) # Generate a random salt value

        # check if website, username and password are submitted
        if not website:
            return apology("Must provide website", 400)
        elif not username:
            return apology("Must provide username", 400)
        elif not password:
            return apology("Must provide password", 400)

        # Get the password hash from the database
        password_hash_dict = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        password_hash = password_hash_dict[0]['hash']

        # Derive the encryption key from the hashed master password and salt
        key = hashlib.pbkdf2_hmac('sha256', password_hash.encode('utf-8'), salt, iterations)
        fernet = Fernet(base64.urlsafe_b64encode(key))


        # Encrypt the password using the Fernet object
        password_bytes = password.encode('utf-8')
        encrypted_password = fernet.encrypt(password_bytes)

        # Add data the user provided to the database
        db.execute("INSERT INTO passwords (website, username, password, salt, user_id) VALUES (?, ?, ?, ?, ?)",
           website, username, encrypted_password, salt, user_id)

        # redirect to the home page
        flash("Password Added!")
        return redirect("/")

    # if request method is GET, show the buy page
    else:
        return render_template("add-password.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        # Ensure password meets minimum requirements
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E])[\x21-\x7E]{8,}$'
        if not re.match(pattern, request.form.get("password")):
            return apology("Password must be at least 8 characters long, one uppercase letter, one lowercase letter, one digit, and one symbol", 400)

        # Save username and password hash in variables
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Ensure username doesn't already exists
        if len(rows) != 0:
            return apology("username is already taken", 400)

        # Insert data into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # Redirect user to login page
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/passwords-vault")
@login_required
def passwords_vault():
    """Vault with the passwords"""

    # Get the user's id
    user_id = session["user_id"]

    # Get user's new master password hash from database
    new_masterpassword_hash = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
    new_masterpassword = new_masterpassword_hash[0]['hash']

    # Get user's data from database
    passwords = db.execute("SELECT id, website, username, password, salt FROM passwords WHERE user_id = ?", user_id)

    # Decrypt the passwords using the new master password
    for password in passwords:
        encrypted_password = password["password"]
        salt = password["salt"]
        key = hashlib.pbkdf2_hmac('sha256', new_masterpassword.encode('utf-8'), salt, iterations)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        password_bytes = fernet.decrypt(encrypted_password)
        password_str = password_bytes.decode('utf-8')
        password["password"] = password_str

    return render_template("passwords-vault.html", passwords=passwords)




@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password of user"""

    if request.method == "POST":

        # Ensure all fields were submitted
        if not request.form.get("old-password") or not request.form.get("new-password") or not request.form.get("confirmation"):
            return apology("Please fill all fields.", 403)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("old-password")):
            return apology("Incorrect password.", 403)

        # Ensure new password matches confirmation
        if request.form.get("new-password") != request.form.get("confirmation"):
            return apology("Passwords must match.", 403)

        # Ensure password meets minimum requirements
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E])[\x21-\x7E]{8,}$'
        if not re.match(pattern, request.form.get("new-password")):
            return apology("Password must be at least 8 characters long, one uppercase letter, one lowercase letter, one digit, and one symbol", 400)

        # Get user's data from database
        user_id = session["user_id"]
        passwords = db.execute("SELECT id, website, username, password, salt FROM passwords WHERE user_id = ?", user_id)

        # Decrypt the passwords using the old master password and re-encrypt them with the new master password
        old_masterpassword1 = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        old_masterpassword = old_masterpassword1[0]['hash']

        new_masterpassword_hash = generate_password_hash(request.form.get("new-password"))
        new_masterpassword = new_masterpassword_hash

        for password in passwords:
            encrypted_password = password["password"]
            salt = password["salt"]
            old_key = hashlib.pbkdf2_hmac('sha256', old_masterpassword.encode('utf-8'), salt, iterations)
            fernet = Fernet(base64.urlsafe_b64encode(old_key))
            password_bytes = fernet.decrypt(encrypted_password)
            password_str = password_bytes.decode('utf-8')
            password["password"] = password_str
            newsalt = os.urandom(16) # Generate a random salt value
            new_key = hashlib.pbkdf2_hmac('sha256', new_masterpassword.encode('utf-8'), newsalt, iterations)
            newfernet = Fernet(base64.urlsafe_b64encode(new_key))
            password_bytes2 = password["password"].encode('utf-8')
            encrypted_password2 = newfernet.encrypt(password_bytes2)
             # Update the encrypted password and salt in the database
            db.execute("UPDATE passwords SET password = ?, salt = ? WHERE id = ?", encrypted_password2, newsalt, password["id"])



        # Update password hash in database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_masterpassword_hash, user_id)

        # Redirect to home page
        flash("Password changed!")
        return redirect("/")

    else:
        return render_template("password.html")



@app.route("/delete-password/<int:password_id>", methods=["POST"])
@login_required
def delete_password(password_id):
    """Delete a password from the database"""

    # Get user's id
    user_id = session["user_id"]

    # Delete the password with the given id and user_id from the database
    db.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", password_id, user_id)

    flash("Password deleted!")
    return redirect("/passwords-vault")


@app.route("/edit-password/<int:password_id>", methods=["POST"])
@login_required
def edit_password(password_id):
    """Edit password from the database"""

    # Get user's id
    user_id = session["user_id"]

    # Delete the password with the given id and user_id from the database
    newwebsite = request.form.get("new_website")
    newusername = request.form.get("new_username")
    newpassword = request.form.get("new_password")

    # Get the password hash from the database
    password_hash_dict = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
    password_hash = password_hash_dict[0]['hash']

    salt = os.urandom(16) # Generate a random salt value

    # Derive the encryption key from the hashed master password and salt
    key = hashlib.pbkdf2_hmac('sha256', password_hash.encode('utf-8'), salt, iterations)
    fernet = Fernet(base64.urlsafe_b64encode(key))

    # Encrypt the password using the Fernet object
    password_bytes = newpassword.encode('utf-8')
    encrypted_password = fernet.encrypt(password_bytes)

    db.execute("UPDATE passwords SET website = ?, username = ?, password = ?, salt = ? WHERE id = ? AND user_id = ?", newwebsite, newusername, encrypted_password, salt, password_id, user_id)

    flash("Password updated!")
    return redirect("/passwords-vault")

