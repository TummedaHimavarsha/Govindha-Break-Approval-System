from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import threading
import time
import os
from functools import wraps


app = Flask(__name__)

# ==========================================================
# CONFIGURATION
# ==========================================================

# IMPORTANT:
# For production, change this to a strong random secret
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY"
)

# Database location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "break_approval.db")


# ----------------------------------------------------------
# TESTING:
# 60 seconds = 1 minute
#
# REAL LIFE:
# 1800 seconds = 30 minutes
# ----------------------------------------------------------

APPROVAL_TIMEOUT = 60

# For real life change to:
# APPROVAL_TIMEOUT = 1800


# ==========================================================
# APPROVAL FLOW
# ==========================================================

APPROVAL_FLOW = [
    "SME_HYD",
    "SME_KOL",
    "QA_HYD",
    "QA_KOL",
    "TEAM_LEAD"
]


ROLE_NAMES = {
    "SME_HYD": "SME - Hyderabad",
    "SME_KOL": "SME - Kolkata",
    "QA_HYD": "QA - Hyderabad",
    "QA_KOL": "QA - Kolkata",
    "TEAM_LEAD": "Team Lead"
}


# ==========================================================
# DATABASE
# ==========================================================

def get_db():

    connection = sqlite3.connect(
        DATABASE,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_database():

    connection = get_db()

    # ======================================================
    # USERS TABLE
    # ======================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            name TEXT NOT NULL,

            role TEXT NOT NULL

        )
    """)

    # ======================================================
    # BREAK REQUESTS TABLE
    # ======================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS break_requests (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            analyst_id INTEGER NOT NULL,

            break_duration TEXT NOT NULL,

            current_role TEXT NOT NULL,

            status TEXT NOT NULL,

            created_at REAL NOT NULL,

            updated_at REAL NOT NULL,

            approved_by TEXT,

            rejected_by TEXT,

            completed_at REAL

        )
    """)

    # ======================================================
    # APPROVAL HISTORY TABLE
    # ======================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS approval_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            break_id INTEGER NOT NULL,

            role TEXT NOT NULL,

            action TEXT NOT NULL,

            action_by TEXT NOT NULL,

            action_time REAL NOT NULL

        )
    """)

    connection.commit()

    # ======================================================
    # DEFAULT USERS
    # ======================================================

    default_users = [

        (
            "analyst1",
            "password123",
            "Analyst One",
            "ANALYST"
        ),

        (
            "smehyd",
            "password123",
            "SME Hyderabad",
            "SME_HYD"
        ),

        (
            "smekol",
            "password123",
            "SME Kolkata",
            "SME_KOL"
        ),

        (
            "qahyd",
            "password123",
            "QA Hyderabad",
            "QA_HYD"
        ),

        (
            "qakol",
            "password123",
            "QA Kolkata",
            "QA_KOL"
        ),

        (
            "teamlead",
            "password123",
            "Team Lead",
            "TEAM_LEAD"
        )

    ]

    for username, password, name, role in default_users:

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if not existing:

            connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    password,
                    name,
                    role
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    name,
                    role
                )
            )

    connection.commit()

    connection.close()

    print("Database initialized successfully.")


# ==========================================================
# LOGIN REQUIRED
# ==========================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return wrapper


# ==========================================================
# ROLE REQUIRED
# ==========================================================

def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "user_id" not in session:

                return redirect(
                    url_for("login")
                )

            if session.get("role") not in allowed_roles:

                flash(
                    "You are not authorized to access this page."
                )

                return redirect(
                    url_for("dashboard")
                )

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================================
# LOGIN
# ==========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["name"] = user["name"]
            session["role"] = user["role"]

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password."
        )

    return render_template(
        "login.html"
    )


# ==========================================================
# LOGOUT
# ==========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================================
# DASHBOARD ROUTER
# ==========================================================

@app.route("/")
@login_required
def dashboard():

    role = session["role"]

    if role == "ANALYST":

        return redirect(
            url_for("analyst_dashboard")
        )

    return redirect(
        url_for("approver_dashboard")
    )


# ==========================================================
# ANALYST DASHBOARD
# ==========================================================

@app.route("/analyst")
@role_required("ANALYST")
def analyst_dashboard():

    connection = get_db()

    requests = connection.execute(
        """
        SELECT *
        FROM break_requests
        WHERE analyst_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    connection.close()

    return render_template(
        "analyst.html",
        requests=requests,
        role_names=ROLE_NAMES
    )


# ==========================================================
# APPLY BREAK
# ==========================================================

@app.route(
    "/apply-break",
    methods=["POST"]
)
@role_required("ANALYST")
def apply_break():

    break_duration = request.form.get(
        "break_duration"
    )

    if break_duration not in [
        "15 Minutes",
        "30 Minutes"
    ]:

        flash(
            "Please select a valid break duration."
        )

        return redirect(
            url_for("analyst_dashboard")
        )

    connection = get_db()

    # ------------------------------------------------------
    # Prevent multiple pending requests
    # ------------------------------------------------------

    existing = connection.execute(
        """
        SELECT id
        FROM break_requests
        WHERE analyst_id = ?
        AND status = 'PENDING'
        """,
        (session["user_id"],)
    ).fetchone()

    if existing:

        connection.close()

        flash(
            "You already have a pending break request."
        )

        return redirect(
            url_for("analyst_dashboard")
        )

    current_time = time.time()

    # ------------------------------------------------------
    # Create break request
    # ------------------------------------------------------

    cursor = connection.execute(
        """
        INSERT INTO break_requests
        (
            analyst_id,
            break_duration,
            current_role,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            break_duration,
            APPROVAL_FLOW[0],
            "PENDING",
            current_time,
            current_time
        )
    )

    break_id = cursor.lastrowid

    # ------------------------------------------------------
    # Approval history
    # ------------------------------------------------------

    connection.execute(
        """
        INSERT INTO approval_history
        (
            break_id,
            role,
            action,
            action_by,
            action_time
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            break_id,
            APPROVAL_FLOW[0],
            "REQUEST_CREATED",
            session["name"],
            current_time
        )
    )

    connection.commit()

    connection.close()

    flash(
        "Break request submitted successfully."
    )

    return redirect(
        url_for("analyst_dashboard")
    )


# ==========================================================
# APPROVER DASHBOARD
# ==========================================================

@app.route("/approver")
@role_required(
    "SME_HYD",
    "SME_KOL",
    "QA_HYD",
    "QA_KOL",
    "TEAM_LEAD"
)
def approver_dashboard():

    role = session["role"]

    connection = get_db()

    requests = connection.execute(
        """
        SELECT
            break_requests.*,
            users.name AS analyst_name

        FROM break_requests

        JOIN users
        ON break_requests.analyst_id = users.id

        WHERE break_requests.current_role = ?

        AND break_requests.status = 'PENDING'

        ORDER BY break_requests.id DESC
        """,
        (role,)
    ).fetchall()

    connection.close()

    return render_template(
        "approver.html",
        requests=requests,
        current_role=role,
        current_role_name=ROLE_NAMES[role]
    )


# ==========================================================
# APPROVE BREAK
# ==========================================================

@app.route(
    "/approve/<int:break_id>",
    methods=["POST"]
)
@role_required(
    "SME_HYD",
    "SME_KOL",
    "QA_HYD",
    "QA_KOL",
    "TEAM_LEAD"
)
def approve_break(break_id):

    role = session["role"]

    connection = get_db()

    request_data = connection.execute(
        """
        SELECT *
        FROM break_requests

        WHERE id = ?

        AND current_role = ?

        AND status = 'PENDING'
        """,
        (
            break_id,
            role
        )
    ).fetchone()

    if not request_data:

        connection.close()

        flash(
            "This request is no longer available."
        )

        return redirect(
            url_for("approver_dashboard")
        )

    now = time.time()

    # ------------------------------------------------------
    # Approve request
    # ------------------------------------------------------

    connection.execute(
        """
        UPDATE break_requests

        SET
            status = 'APPROVED',
            approved_by = ?,
            completed_at = ?,
            updated_at = ?

        WHERE id = ?
        """,
        (
            session["name"],
            now,
            now,
            break_id
        )
    )

    # ------------------------------------------------------
    # Approval history
    # ------------------------------------------------------

    connection.execute(
        """
        INSERT INTO approval_history
        (
            break_id,
            role,
            action,
            action_by,
            action_time
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            break_id,
            role,
            "APPROVED",
            session["name"],
            now
        )
    )

    connection.commit()

    connection.close()

    flash(
        "Break approved successfully."
    )

    return redirect(
        url_for("approver_dashboard")
    )


# ==========================================================
# REJECT BREAK
# ==========================================================

@app.route(
    "/reject/<int:break_id>",
    methods=["POST"]
)
@role_required(
    "SME_HYD",
    "SME_KOL",
    "QA_HYD",
    "QA_KOL",
    "TEAM_LEAD"
)
def reject_break(break_id):

    role = session["role"]

    connection = get_db()

    request_data = connection.execute(
        """
        SELECT *
        FROM break_requests

        WHERE id = ?

        AND current_role = ?

        AND status = 'PENDING'
        """,
        (
            break_id,
            role
        )
    ).fetchone()

    if not request_data:

        connection.close()

        flash(
            "This request is no longer available."
        )

        return redirect(
            url_for("approver_dashboard")
        )

    now = time.time()

    # ------------------------------------------------------
    # Reject request
    # ------------------------------------------------------

    connection.execute(
        """
        UPDATE break_requests

        SET
            status = 'REJECTED',
            rejected_by = ?,
            completed_at = ?,
            updated_at = ?

        WHERE id = ?
        """,
        (
            session["name"],
            now,
            now,
            break_id
        )
    )

    # ------------------------------------------------------
    # Approval history
    # ------------------------------------------------------

    connection.execute(
        """
        INSERT INTO approval_history
        (
            break_id,
            role,
            action,
            action_by,
            action_time
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            break_id,
            role,
            "REJECTED",
            session["name"],
            now
        )
    )

    connection.commit()

    connection.close()

    flash(
        "Break rejected."
    )

    return redirect(
        url_for("approver_dashboard")
    )


# ==========================================================
# AUTOMATIC ESCALATION
# ==========================================================

def escalation_worker():

    print("Automatic escalation worker started.")

    while True:

        try:

            time.sleep(5)

            connection = get_db()

            current_time = time.time()

            pending_requests = connection.execute(
                """
                SELECT *
                FROM break_requests
                WHERE status = 'PENDING'
                """
            ).fetchall()

            for request_data in pending_requests:

                elapsed = (
                    current_time -
                    request_data["updated_at"]
                )

                if elapsed < APPROVAL_TIMEOUT:

                    continue

                current_role = request_data["current_role"]

                # --------------------------------------------------
                # Safety check
                # --------------------------------------------------

                if current_role not in APPROVAL_FLOW:

                    print(
                        f"Unknown role for break #{request_data['id']}: "
                        f"{current_role}"
                    )

                    continue

                current_index = APPROVAL_FLOW.index(
                    current_role
                )

                # --------------------------------------------------
                # THERE IS A NEXT APPROVER
                # --------------------------------------------------

                if current_index < len(
                    APPROVAL_FLOW
                ) - 1:

                    next_role = APPROVAL_FLOW[
                        current_index + 1
                    ]

                    connection.execute(
                        """
                        UPDATE break_requests

                        SET
                            current_role = ?,
                            updated_at = ?

                        WHERE id = ?

                        AND status = 'PENDING'
                        """,
                        (
                            next_role,
                            current_time,
                            request_data["id"]
                        )
                    )

                    connection.execute(
                        """
                        INSERT INTO approval_history
                        (
                            break_id,
                            role,
                            action,
                            action_by,
                            action_time
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            request_data["id"],
                            next_role,
                            "AUTO_ESCALATED",
                            "SYSTEM",
                            current_time
                        )
                    )

                    print(
                        f"Break #{request_data['id']} "
                        f"escalated from "
                        f"{current_role} to "
                        f"{next_role}"
                    )

                # --------------------------------------------------
                # TEAM LEAD TIMEOUT
                # --------------------------------------------------

                else:

                    connection.execute(
                        """
                        UPDATE break_requests

                        SET
                            status = 'ESCALATION_COMPLETED',
                            completed_at = ?,
                            updated_at = ?

                        WHERE id = ?

                        AND status = 'PENDING'
                        """,
                        (
                            current_time,
                            current_time,
                            request_data["id"]
                        )
                    )

                    connection.execute(
                        """
                        INSERT INTO approval_history
                        (
                            break_id,
                            role,
                            action,
                            action_by,
                            action_time
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            request_data["id"],
                            current_role,
                            "ESCALATION_COMPLETED",
                            "SYSTEM",
                            current_time
                        )
                    )

                    print(
                        f"Break #{request_data['id']} "
                        f"escalation completed."
                    )

            connection.commit()

            connection.close()

        except Exception as error:

            print(
                "Escalation error:",
                error
            )


# ==========================================================
# DATABASE INITIALIZATION
# ==========================================================

# IMPORTANT:
# This runs when Gunicorn imports this file on Render.
#
# This fixes:
# sqlite3.OperationalError:
# no such table: users
#
init_database()


# ==========================================================
# START AUTOMATIC ESCALATION WORKER
# ==========================================================

# Start the worker when the application is loaded.
#
# This is important because Render uses Gunicorn and therefore
# does not execute this file as __main__.

escalation_thread = threading.Thread(
    target=escalation_worker,
    daemon=True
)

escalation_thread.start()


# ==========================================================
# LOCAL DEVELOPMENT
# ==========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
