from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
import socket
import platform
import threading

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from monitor_service import start_services
from employee_monitor import log_login, log_activity, start_employee_monitor
from usb_monitor import start_usb_monitor
from file_monitor import start_file_monitor


# ==========================================
# APP CONFIGURATION
# ==========================================

app = Flask(__name__)
app.secret_key = "insider_threat_secret_key"

DATABASE = "threat.db"


# ==========================================
# DATABASE
# ==========================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================================
# COMMON FUNCTIONS
# ==========================================

def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unknown"


def get_device():
    return platform.node()


def login_required():
    return "username" in session


def start_thread(target, *args):
    threading.Thread(
        target=target,
        args=args,
        daemon=True
    ).start()


def write_login(cur, username, status):
    cur.execute("""
        INSERT INTO login_logs
        (username,login_time,ip_address,device_name,status)
        VALUES(?,?,?,?,?)
    """, (
        username,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        get_ip(),
        get_device(),
        status
    ))


def count(cur, table, where=None):
    sql = f"SELECT COUNT(*) FROM {table}"

    if where:
        sql += f" WHERE {where}"

    cur.execute(sql)
    return cur.fetchone()[0]


# ==========================================
# CREATE DEFAULT ADMIN
# ==========================================

def create_admin():

    conn = get_db()
    cur = conn.cursor()

    admin = cur.execute(
        "SELECT 1 FROM users WHERE username=?",
        ("admin",)
    ).fetchone()

    if not admin:

        cur.execute("""
            INSERT INTO users
            (username,password,fullname,email,department,role)
            VALUES(?,?,?,?,?,?)
        """, (
            "admin",
            generate_password_hash("admin123"),
            "System Administrator",
            "admin@gmail.com",
            "IT",
            "Admin"
        ))

        conn.commit()

    conn.close()


create_admin()
# ==========================================
# LOGIN
# ==========================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cur.fetchone()

        if user and check_password_hash(user["password"], password):

            session["username"] = user["username"]
            session["role"] = user["role"]

            write_login(cur, username, "Success")
            conn.commit()
            conn.close()

            start_thread(start_usb_monitor)
            start_thread(start_file_monitor, username)

            log_login(username)
            start_employee_monitor(username)

            if user["role"].strip().lower() == "admin":
                return redirect("/dashboard")

            return redirect("/employee_dashboard")

        write_login(cur, username, "Failed")
        conn.commit()
        conn.close()

        flash("Invalid Username or Password")

    return render_template("login.html")


# ==========================================
# FORGOT PASSWORD
# ==========================================

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=? AND email=?",
            (username, email)
        )

        if cur.fetchone():

            session["reset_user"] = username
            conn.close()

            return redirect("/reset_password")

        conn.close()

        flash("Invalid Username or Email")

    return render_template("forgot_password.html")


# ==========================================
# RESET PASSWORD
# ==========================================

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():

    if "reset_user" not in session:
        return redirect("/forgot_password")

    if request.method == "POST":

        password = generate_password_hash(
            request.form["password"]
        )

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "UPDATE users SET password=? WHERE username=?",
            (password, session["reset_user"])
        )

        conn.commit()
        conn.close()

        session.pop("reset_user")

        flash("Password changed successfully.")
        return redirect("/")

    return render_template("reset_password.html")


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    if "username" in session:

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE login_logs
            SET logout_time=?
            WHERE username=?
            AND logout_time IS NULL
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                session["username"]
            )
        )

        conn.commit()
        conn.close()

        log_activity(
            session["username"],
            "Logout",
            "Employee logged out from system",
            "Low"
        )

    session.clear()

    return redirect("/")
# ==========================================
# DASHBOARD DATA
# ==========================================

def dashboard_data():

    conn = get_db()
    cur = conn.cursor()

    data = {
        "users": count(cur, "users"),
        "logins": cur.execute(
            "SELECT COUNT(DISTINCT username) FROM login_logs"
        ).fetchone()[0],
        "alerts": count(cur, "alerts"),
        "files": count(cur, "activity_logs")
    }

    cur.execute("""
        SELECT username,
               activity,
               date,
               time,
               risk_level
        FROM activity_logs
        ORDER BY id DESC
        LIMIT 15
    """)

    data["activities"] = cur.fetchall()

    conn.close()

    return data


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    data = dashboard_data()

    cur.execute("""
        SELECT description
        FROM alerts
        ORDER BY id DESC
        LIMIT 5
    """)

    alerts = cur.fetchall()

    usb = count(cur, "usb_logs")
    files = count(cur, "file_logs")

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        data=data,
        alerts=alerts,
        usb=usb,
        files=files
    )


# ==========================================
# EMPLOYEE DASHBOARD
# ==========================================

@app.route("/employee_dashboard")
def employee_dashboard():

    if not login_required():
        return redirect("/")

    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    activities = count(
        cur,
        "activity_logs",
        f"username='{username}'"
    )

    alerts = count(
        cur,
        "alerts",
        f"username='{username}'"
    )

    cur.execute("""
        SELECT score
        FROM risk_scores
        WHERE username=?
        ORDER BY id DESC
        LIMIT 1
    """, (username,))

    risk = cur.fetchone()
    risk_score = risk["score"] if risk else 0

    cur.execute("""
        SELECT login_time
        FROM login_logs
        WHERE username=?
        ORDER BY id DESC
        LIMIT 1
    """, (username,))

    last = cur.fetchone()
    last_login = last["login_time"] if last else "No Login"

    cur.execute("""
        SELECT *
        FROM activity_logs
        WHERE username=?
        ORDER BY id DESC
        LIMIT 8
    """, (username,))

    recent = cur.fetchall()

    cur.execute("""
        SELECT *
        FROM alerts
        WHERE username=?
        ORDER BY id DESC
        LIMIT 5
    """, (username,))

    alerts_list = cur.fetchall()

    conn.close()

    return render_template(
        "employee_dashboard.html",
        username=username,
        role=session["role"],
        activities=activities,
        alerts=alerts,
        risk_score=risk_score,
        last_login=last_login,
        recent=recent,
        alerts_list=alerts_list
    )
# ==========================================
# REPORTS
# ==========================================

@app.route("/reports")
def reports():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    total_users = count(cur, "users")
    total_logs = count(cur, "activity_logs")
    total_alerts = count(cur, "alerts")
    high_risk = count(cur, "activity_logs", "risk_level='High'")

    cur.execute("""
        SELECT
            id,
            username,
            activity AS report_type,
            risk_level,
            date,
            'Completed' AS status
        FROM activity_logs
        ORDER BY id DESC
    """)

    reports = cur.fetchall()

    conn.close()

    return render_template(
        "reports.html",
        username=session["username"],
        role=session["role"],
        total_users=total_users,
        total_logs=total_logs,
        total_alerts=total_alerts,
        high_risk=high_risk,
        reports=reports
    )


# ==========================================
# ACTIVITY LOGS
# ==========================================

@app.route("/activity")
def activity():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM activity_logs
        ORDER BY id DESC
    """)

    activities = cur.fetchall()

    total_logs = count(cur, "activity_logs")
    high_risk = count(cur, "activity_logs", "risk_level='High'")
    medium_risk = count(cur, "activity_logs", "risk_level='Medium'")
    low_risk = count(cur, "activity_logs", "risk_level='Low'")

    conn.close()

    return render_template(
        "activity.html",
        username=session["username"],
        role=session["role"],
        activities=activities,
        total_logs=total_logs,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk
    )


# ==========================================
# ALERTS
# ==========================================

@app.route("/alerts")
def alerts():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 50
    """)

    alerts = cur.fetchall()

    total_alerts = count(cur, "alerts")
    high_alerts = count(cur, "alerts", "severity='High'")
    medium_alerts = count(cur, "alerts", "severity='Medium'")
    resolved_alerts = count(cur, "alerts", "status='Resolved'")

    conn.close()

    return render_template(
        "alerts.html",
        username=session["username"],
        role=session["role"],
        alerts=alerts,
        total_alerts=total_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        resolved_alerts=resolved_alerts
    )


# ==========================================
# RESOLVE ALERT
# ==========================================

@app.route("/resolve_alert/<int:id>")
def resolve_alert(id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "UPDATE alerts SET status='Resolved' WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect("/alerts")


# ==========================================
# DELETE ALERT
# ==========================================

@app.route("/delete_alert/<int:id>")
def delete_alert(id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM alerts WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect("/alerts")
# ==========================================
# ADD USER
# ==========================================

@app.route("/add_user", methods=["GET", "POST"])
def add_user():

    if request.method == "POST":

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO users
            (username,password,fullname,email,department,role)
            VALUES(?,?,?,?,?,?)
        """, (
            request.form["username"],
            generate_password_hash(request.form["password"]),
            request.form["fullname"],
            request.form["email"],
            request.form["department"],
            request.form["role"]
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("users"))

    return render_template("add_user.html")


# ==========================================
# USERS
# ==========================================

@app.route("/users")
def users():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users ORDER BY id")
    users = cur.fetchall()

    data = {
        "total_users": count(cur, "users"),
        "admins": count(cur, "users", "role='Admin'"),
        "employees": count(cur, "users", "role='Employee'")
    }

    cur.execute("""
        SELECT COUNT(DISTINCT username)
        FROM login_logs
        WHERE status='Success'
    """)

    data["active_users"] = cur.fetchone()[0]

    conn.close()

    return render_template(
        "users.html",
        username=session["username"],
        role=session["role"],
        users=users,
        **data
    )


# ==========================================
# DELETE USER
# ==========================================

@app.route("/delete_user/<int:id>")
def delete_user(id):

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM users WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect("/users")


# ==========================================
# EDIT USER
# ==========================================

@app.route("/edit_user/<int:id>")
def edit_user(id):
    return f"Edit User ID: {id}"


# ==========================================
# SETTINGS
# ==========================================

@app.route("/settings", methods=["GET", "POST"])
def settings():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM settings WHERE id=1")
    settings = cur.fetchone()

    if not settings:

        cur.execute("INSERT INTO settings(id) VALUES(1)")
        conn.commit()

        cur.execute("SELECT * FROM settings WHERE id=1")
        settings = cur.fetchone()

    if request.method == "POST":

        values = (
            1 if "usb_monitor" in request.form else 0,
            1 if "file_monitor" in request.form else 0,
            1 if "login_monitor" in request.form else 0,
            1 if "email_alert" in request.form else 0,
            1 if "backup" in request.form else 0,
            request.form["scan_interval"]
        )

        cur.execute("""
            UPDATE settings
            SET
                usb_monitor=?,
                file_monitor=?,
                login_monitor=?,
                email_alert=?,
                backup=?,
                scan_interval=?
            WHERE id=1
        """, values)

        conn.commit()

        return redirect("/settings")

    conn.close()

    return render_template(
        "settings.html",
        username=session["username"],
        role=session["role"],
        settings=settings
    )
# ==========================================
# EMPLOYEE ACTIVITY
# ==========================================

@app.route("/employee_activity")
def employee_activity():

    if not login_required():
        return redirect("/")

    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM activity_logs
        WHERE username=?
        ORDER BY id DESC
    """, (username,))

    activities = cur.fetchall()

    stats = {
        "total": count(cur, "activity_logs", f"username='{username}'"),
        "high": count(cur, "activity_logs", f"username='{username}' AND risk_level='High'"),
        "medium": count(cur, "activity_logs", f"username='{username}' AND risk_level='Medium'"),
        "low": count(cur, "activity_logs", f"username='{username}' AND risk_level='Low'")
    }

    conn.close()

    return render_template(
        "employee_activity.html",
        username=username,
        activities=activities,
        **stats
    )


# ==========================================
# EMPLOYEE ALERTS
# ==========================================

@app.route("/employee_alerts")
def employee_alerts():

    if not login_required():
        return redirect("/")

    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM alerts
        WHERE username=?
        ORDER BY id DESC
    """, (username,))

    alerts = cur.fetchall()

    stats = {
        "total": count(cur, "alerts", f"username='{username}'"),
        "high": count(cur, "alerts", f"username='{username}' AND severity='High'"),
        "medium": count(cur, "alerts", f"username='{username}' AND severity='Medium'"),
        "resolved": count(cur, "alerts", f"username='{username}' AND status='Resolved'")
    }

    conn.close()

    return render_template(
        "employee_alerts.html",
        username=username,
        alerts=alerts,
        **stats
    )


# ==========================================
# EMPLOYEE PROFILE
# ==========================================

@app.route("/employee_profile", methods=["GET", "POST"])
def employee_profile():

    if not login_required():
        return redirect("/")

    username = session["username"]

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":

        cur.execute("""
            UPDATE users
            SET fullname=?,
                email=?,
                department=?
            WHERE username=?
        """, (
            request.form["fullname"],
            request.form["email"],
            request.form["department"],
            username
        ))

        conn.commit()
        flash("Profile Updated Successfully")

    cur.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    )

    user = cur.fetchone()

    conn.close()

    return render_template(
        "employee_profile.html",
        user=user
    )


# ==========================================
# CHANGE PASSWORD
# ==========================================

@app.route("/change_password", methods=["GET", "POST"])
def change_password():

    if not login_required():
        return redirect("/")

    if request.method == "POST":

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT password FROM users WHERE username=?",
            (session["username"],)
        )

        user = cur.fetchone()

        if not check_password_hash(
                user["password"],
                request.form["current_password"]):
            flash("Current password is incorrect.")
            conn.close()
            return redirect("/change_password")

        if request.form["new_password"] != request.form["confirm_password"]:
            flash("New passwords do not match.")
            conn.close()
            return redirect("/change_password")

        cur.execute("""
            UPDATE users
            SET password=?
            WHERE username=?
        """, (
            generate_password_hash(request.form["new_password"]),
            session["username"]
        ))

        conn.commit()
        conn.close()

        flash("Password changed successfully.")
        return redirect("/employee_profile")

    return render_template("change_password.html")


# ==========================================
# USB HISTORY
# ==========================================

@app.route("/usb_history")
def usb_history():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM usb_logs ORDER BY id DESC")
    logs = cur.fetchall()

    inserted = count(cur, "usb_logs", "action='Inserted'")
    removed = count(cur, "usb_logs", "action='Removed'")
    total = count(cur, "usb_logs")
    active = max(inserted - removed, 0)

    conn.close()

    return render_template(
        "usb_history.html",
        username=session["username"],
        role=session["role"],
        logs=logs,
        total=total,
        inserted=inserted,
        removed=removed,
        active=active
    )


# ==========================================
# FILE HISTORY
# ==========================================

@app.route("/file_history")
def file_history():

    if not login_required():
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM file_logs ORDER BY id DESC")
    logs = cur.fetchall()

    total = count(cur, "file_logs")
    created = count(cur, "file_logs", "action='File Created'")
    modified = count(cur, "file_logs", "action='File Modified'")
    deleted = count(cur, "file_logs", "action='File Deleted'")

    conn.close()

    return render_template(
        "file_history.html",
        username=session["username"],
        role=session["role"],
        logs=logs,
        total=total,
        created=created,
        modified=modified,
        deleted=deleted
    )
# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    start_services()

    app.run(
        debug=True,
        use_reloader=False
    )