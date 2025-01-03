import re  

# Define password validation function
def is_password_valid(password):

    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    return None

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import pymysql
from flask_bcrypt import Bcrypt
from utils import log_action
from db_config import get_db_connection
from db_config import initialize_database
from flask import flash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Set session lifetime
app.permanent_session_lifetime = timedelta(minutes=2)  

bcrypt = Bcrypt(app)
db = get_db_connection()
initialize_database()


@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        # Validate the password
        validation_error = is_password_valid(password)
        if validation_error:
            flash(validation_error, "danger")  # Feedback for invalid password
            return render_template("register.html")

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
                (username, hashed_password, email),
            )
            db.commit()
            new_user_id = cursor.lastrowid

            # Log the user registration action
            log_action(
                db,
                user_id=new_user_id,
                action="USER REGISTERED",
                table_name="users",
                record_id=new_user_id,
            )

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except pymysql.MySQLError as e:
            db.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        cursor = db.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT id, password, is_admin FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["is_admin"] = user["is_admin"]
            log_action(db, user_id=user["id"], action="USER LOGGED IN", table_name="users")
            return redirect(url_for("transactions"))

        log_action(db, user_id=None, action="FAILED LOGIN ATTEMPT", table_name="users")
        return "Invalid credentials. Try again."
    return render_template("login.html")


@app.route("/transactions", methods=["GET", "POST"])
def transactions():
    if "user_id" not in session:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))
    
    user_id = session["user_id"]

    # Check if the user is an admin
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    is_admin = user[0] if user else False

    if request.method == "POST":
        amount = request.form["amount"]

        cursor.execute("INSERT INTO transactions (user_id, amount) VALUES (%s, %s)", (user_id, amount))
        db.commit()
        transaction_id = cursor.lastrowid
        log_action(db, user_id=user_id, action="CREATE TRANSACTION", table_name="transactions", record_id=transaction_id)
        return "Transaction created successfully."

    return render_template("transactions.html", is_admin=is_admin)


@app.route("/audit_logs")
def audit_logs():
    if "user_id" not in session:
        return "session expired. Please log in.", 403

    cursor = db.cursor()
    if session.get("is_admin", False):
        # Admin sees all logs
        query = """
        SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.table_name,
               audit_logs.record_id, audit_logs.ip_address, audit_logs.timestamp
        FROM audit_logs
        LEFT JOIN users ON audit_logs.user_id = users.id
        ORDER BY audit_logs.timestamp DESC;
        """
        cursor.execute(query)
    else:
        # Normal user sees only their logs
        query = """
        SELECT audit_logs.id, users.username, audit_logs.action, audit_logs.table_name,
               audit_logs.record_id, audit_logs.ip_address, audit_logs.timestamp
        FROM audit_logs
        LEFT JOIN users ON audit_logs.user_id = users.id
        WHERE audit_logs.user_id = %s
        ORDER BY audit_logs.timestamp DESC;
        """
        cursor.execute(query, (session["user_id"],))

    logs = cursor.fetchall()
    return render_template("audit_logs.html", logs=logs)

@app.route("/view_database")
def view_database():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Check if the user is admin
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()

    if not user or not user[0]:  # Not admin or user not found
        return "You are not authorized to view this page."

    # Fetch all tables
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()

    database_data = {}
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        cursor.execute(f"SHOW COLUMNS FROM {table_name}")
        columns = [col[0] for col in cursor.fetchall()]
        database_data[table_name] = {"columns": columns, "rows": rows}

    return render_template("view_database.html", database_data=database_data)

@app.route("/delete_table/<table_name>", methods=["POST"])
def delete_table(table_name):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Check if the user is admin
    cursor = db.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()

    if not user or not user[0]:  
        return "You are not authorized to perform this action."

    try:
        # Delete the table
        cursor.execute(f"DROP TABLE `{table_name}`")
        db.commit()
        flash(f"Table '{table_name}' has been deleted successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"An error occurred while deleting the table: {str(e)}", "danger")

    return redirect(url_for("view_database"))




@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
