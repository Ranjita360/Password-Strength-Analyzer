from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import bcrypt
import re

app = Flask(__name__)

# Change this to a long random secret in a real project
app.secret_key = "change-this-to-a-random-secret-key"

DATABASE = "users.db"


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    db.commit()
    db.close()


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

def valid_username(username):
    return re.match(r"^[A-Za-z0-9_]{3,20}$", username)


def valid_email(email):
    return re.match(
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
        email
    )


def valid_password(password):
    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    if not re.search(r"[^A-Za-z0-9]", password):
        return False

    return True


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Login System</title>
        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
                text-align: center;
                padding-top: 100px;
            }

            .container {
                background: white;
                padding: 30px;
                width: 350px;
                margin: auto;
                border-radius: 10px;
                box-shadow: 0 0 10px #ccc;
            }

            a {
                display: block;
                margin: 15px;
                text-decoration: none;
            }
        </style>
    </head>

    <body>

        <div class="container">

            <h1>Secure Login System</h1>

            <a href="/register">Create Account</a>

            <a href="/login">Login</a>

        </div>

    </body>
    </html>
    """)


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Validate username
        if not valid_username(username):
            message = "Username must contain 3-20 letters, numbers or underscores."

        # Validate email
        elif not valid_email(email):
            message = "Enter a valid email address."

        # Validate password
        elif not valid_password(password):
            message = (
                "Password must contain at least 8 characters, "
                "uppercase, lowercase, number and special character."
            )

        else:

            # Hash password using bcrypt
            hashed_password = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt()
            )

            try:

                db = get_db()

                # Parameterized query protects against SQL injection
                db.execute(
                    """
                    INSERT INTO users
                    (username, email, password)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        email,
                        hashed_password.decode("utf-8")
                    )
                )

                db.commit()
                db.close()

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:

                message = "Username or email already exists."

    return render_template_string("""
    <!DOCTYPE html>
    <html>

    <head>
        <title>Register</title>

        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
                padding-top: 50px;
            }

            .container {
                background: white;
                padding: 30px;
                width: 350px;
                margin: auto;
                border-radius: 10px;
                box-shadow: 0 0 10px #ccc;
            }

            input {
                width: 100%;
                padding: 10px;
                margin: 8px 0;
                box-sizing: border-box;
            }

            button {
                width: 100%;
                padding: 10px;
                background: #222;
                color: white;
                border: none;
                cursor: pointer;
            }

            .error {
                color: red;
            }
        </style>

    </head>

    <body>

    <div class="container">

        <h2>Create Account</h2>

        {% if message %}
            <p class="error">{{ message }}</p>
        {% endif %}

        <form method="POST">

            <input
                type="text"
                name="username"
                placeholder="Username"
                required
            >

            <input
                type="email"
                name="email"
                placeholder="Email"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            >

            <button type="submit">
                Register
            </button>

        </form>

        <p>
            Already have an account?
            <a href="/login">Login</a>
        </p>

    </div>

    </body>
    </html>
    """, message=message)


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        # Parameterized query
        user = db.execute(
            """
            SELECT * FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        db.close()

        if user:

            stored_password = user["password"].encode("utf-8")

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password
            ):

                session.clear()

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                return redirect(url_for("dashboard"))

        message = "Invalid username or password."

    return render_template_string("""
    <!DOCTYPE html>
    <html>

    <head>
        <title>Login</title>

        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
                padding-top: 80px;
            }

            .container {
                background: white;
                padding: 30px;
                width: 350px;
                margin: auto;
                border-radius: 10px;
                box-shadow: 0 0 10px #ccc;
            }

            input {
                width: 100%;
                padding: 10px;
                margin: 8px 0;
                box-sizing: border-box;
            }

            button {
                width: 100%;
                padding: 10px;
                background: #222;
                color: white;
                border: none;
            }

            .error {
                color: red;
            }
        </style>

    </head>

    <body>

    <div class="container">

        <h2>Login</h2>

        {% if message %}
            <p class="error">{{ message }}</p>
        {% endif %}

        <form method="POST">

            <input
                type="text"
                name="username"
                placeholder="Username"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            >

            <button type="submit">
                Login
            </button>

        </form>

        <p>
            Don't have an account?
            <a href="/register">Register</a>
        </p>

    </div>

    </body>
    </html>
    """, message=message)


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    username = session["username"]

    return render_template_string("""
    <!DOCTYPE html>
    <html>

    <head>
        <title>Dashboard</title>
    </head>

    <body>

        <h1>Welcome, {{ username }}!</h1>

        <p>You are successfully logged in.</p>

        <p>
            Your session is active.
        </p>

        <a href="/logout">
            Logout
        </a>

    </body>

    </html>
    """, username=username)


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    create_database()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )