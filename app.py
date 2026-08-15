from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import socket
import platform
from monitor_service import start_services
from employee_monitor import log_login, start_employee_monitor
from usb_monitor import start_usb_monitor
from file_monitor import start_file_monitor
import threading

app = Flask(__name__)
app.secret_key = "insider_threat_secret_key"

DATABASE = "threat.db"


# ==========================
# DATABASE CONNECTION
# ==========================
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================
# GET IP ADDRESS
# ==========================
def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Unknown"


# ==========================
# GET DEVICE NAME
# ==========================
def get_device():
    return platform.node()


# ==========================
# CREATE DEFAULT ADMIN
# ==========================
def create_admin():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username=?", ("admin",))
    admin = cur.fetchone()

    if admin is None:

        password = generate_password_hash("admin123")

        cur.execute("""
        INSERT INTO users
        (username,password,fullname,email,department,role)

        VALUES(?,?,?,?,?,?)
        """,
        (
            "admin",
            password,
            "System Administrator",
            "admin@gmail.com",
            "IT",
            "Admin"
        ))

        conn.commit()

    conn.close()


create_admin()


# ==========================
# LOGIN
# ==========================
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user["password"], password):

            session["username"] = user["username"]
            session["role"] = user["role"]

            now = datetime.now()

            cur.execute("""
                INSERT INTO login_logs
                (username, login_time, ip_address, device_name, status)
                VALUES(?,?,?,?,?)
            """, (
                username,
                now.strftime("%Y-%m-%d %H:%M:%S"),
                get_ip(),
                get_device(),
                "Success"
            ))

            conn.commit()
            conn.close()

            # Save session
            session["username"] = user["username"]
            session["role"] = user["role"]

            # Start USB Monitor
            threading.Thread(
               target=start_usb_monitor,
               daemon=True
            ).start()

            # Start File Monitor in background
            threading.Thread(
                target=start_file_monitor,
                args=(username,),
                daemon=True
            ).start()

            # Record Login
            log_login(username)

            # Start Employee Monitor
            start_employee_monitor(username)

            print("Username:", user["username"])
            print("Role:", user["role"])

            if user["role"].strip().lower() == "admin":
                return redirect("/dashboard")
            else:
                return redirect("/employee_dashboard")

        # Invalid Login
        now = datetime.now()

        cur.execute("""
            INSERT INTO login_logs
            (username, login_time, ip_address, device_name, status)
            VALUES(?,?,?,?,?)
        """, (
            username,
            now.strftime("%Y-%m-%d %H:%M:%S"),
            get_ip(),
            get_device(),
            "Failed"
        ))

        conn.commit()
        conn.close()

        flash("Invalid Username or Password")

    return render_template("login.html")

#===========================
# EMPLOYEE DASHBOARD
#==========================

@app.route("/employee_dashboard")
def employee_dashboard():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    username = session["username"]

    # My Activities
    cur.execute(
        "SELECT COUNT(*) FROM activity_logs WHERE username=?",
        (username,)
    )
    activities = cur.fetchone()[0]

    # My Alerts
    cur.execute(
        "SELECT COUNT(*) FROM alerts WHERE username=?",
        (username,)
    )
    alerts = cur.fetchone()[0]

    # My Risk Score
    cur.execute(
        "SELECT score FROM risk_scores WHERE username=? ORDER BY id DESC LIMIT 1",
        (username,)
    )

    risk = cur.fetchone()
    risk_score = risk["score"] if risk else 0

    # Last Login
    cur.execute("""
        SELECT login_time
        FROM login_logs
        WHERE username=?
        ORDER BY id DESC
        LIMIT 1
    """, (username,))

    last = cur.fetchone()
    last_login = last["login_time"] if last else "No Login"

    # Recent Activities
    cur.execute("""
        SELECT *
        FROM activity_logs
        WHERE username=?
        ORDER BY id DESC
        LIMIT 8
    """, (username,))

    recent = cur.fetchall()

    # Latest Alerts
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

# ==========================
# FORGOT PASSWORD
# ==========================
@app.route("/forgot_password", methods=["GET","POST"])
def forgot_password():

    if request.method=="POST":

        username=request.form["username"]
        email=request.form["email"]

        conn=get_db()
        cur=conn.cursor()

        cur.execute("""

        SELECT *

        FROM users

        WHERE username=?

        AND email=?

        """,(username,email))

        user=cur.fetchone()

        conn.close()

        if user:

            session["reset_user"]=username

            return redirect("/reset_password")

        flash("Invalid Username or Email")

    return render_template("forgot_password.html")

# ==========================
# RESET PASSWORD
# ==========================

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():

    if "reset_user" not in session:
        return redirect("/forgot_password")

    if request.method == "POST":

        password = request.form["password"]

        hashed = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""

        UPDATE users

        SET password=?

        WHERE username=?

        """,(hashed, session["reset_user"]))

        conn.commit()
        conn.close()

        session.pop("reset_user", None)

        flash("Password changed successfully.")

        return redirect("/")

    return render_template("reset_password.html")

# ==========================
# DASHBOARD
# ==========================
@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/")

    data = dashboard_data()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT description
        FROM alerts
        ORDER BY id DESC
        LIMIT 5
    """)

    alerts = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM usb_logs")
    usb = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM file_logs")
    files = cur.fetchone()[0]


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
# ==========================
# DASHBOARD DATA
# ==========================

def dashboard_data():

    conn = get_db()
    cur = conn.cursor()

    # Total Users
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    # Successful Logins (Active Users)
    cur.execute("SELECT COUNT(DISTINCT username) FROM login_logs")
    active_users = cur.fetchone()[0]
    

    # Threat Alerts
    cur.execute("SELECT COUNT(*) FROM alerts")
    threats = cur.fetchone()[0]

    # Activity Logs
    cur.execute("SELECT COUNT(*) FROM activity_logs")
    activities = cur.fetchone()[0]

    # Recent Activities
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

    recent = cur.fetchall()

    conn.close()

    return {

        "users": total_users,

        "logins": active_users,

        "alerts": threats,

        "files": activities,

        "activities": recent

    }

#==========================
# REPORTS
#==========================
@app.route("/reports")
def reports():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM activity_logs")
    total_logs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE risk_level='High'
    """)
    high_risk = cur.fetchone()[0]

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

# ==========================
# LOGOUT
# ==========================
@app.route("/logout")
def logout():

    if "username" in session:

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""

        UPDATE login_logs

        SET logout_time=?

        WHERE username=?

        AND logout_time IS NULL

        """,

        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            session["username"]
        ))

        conn.commit()
        conn.close()
        from employee_monitor import log_activity

        log_activity(
    session["username"],
    "Logout",
    "Employee logged out from system",
    "Low"
)

    session.clear()

    return redirect("/")

# ==========================
# ACTIVITY LOGS
# ==========================

@app.route("/activity")
def activity():

    if "username" not in session:
        return redirect("/")

    conn=get_db()
    cur=conn.cursor()

    cur.execute("SELECT * FROM activity_logs ORDER BY id DESC")
    activities=cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM activity_logs")
    total_logs=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM activity_logs WHERE risk_level='High'")
    high_risk=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM activity_logs WHERE risk_level='Medium'")
    medium_risk=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM activity_logs WHERE risk_level='Low'")
    low_risk=cur.fetchone()[0]

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

# ==========================
# ALERTS
# ==========================
@app.route("/alerts")
def alerts():

    if "username" not in session:
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

    cur.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='High'")
    high_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='Medium'")
    medium_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE status='Resolved'")
    resolved_alerts = cur.fetchone()[0]

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


@app.route("/resolve_alert/<int:id>")
def resolve_alert(id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE alerts
        SET status='Resolved'
        WHERE id=?
    """,(id,))

    conn.commit()
    conn.close()

    return redirect("/alerts")


@app.route("/delete_alert/<int:id>")
def delete_alert(id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM alerts WHERE id=?",(id,))

    conn.commit()
    conn.close()

    return redirect("/alerts")

#===========================
# ADD USERS
#==========================
@app.route("/add_user", methods=["GET", "POST"])
def add_user():

    if request.method == "POST":

        username = request.form["username"]
        password = generate_password_hash(request.form["password"])
        fullname = request.form["fullname"]
        email = request.form["email"]
        department = request.form["department"]
        role = request.form["role"]

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # INSERT QUERY GOES HERE
        cursor.execute("""
        INSERT INTO users
        (
            username,
            password,
            fullname,
            email,
            department,
            role
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username,
            password,
            fullname,
            email,
            department,
            role
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("users"))

    return render_template("add_user.html")
# ==========================
# USERS
# ==========================

@app.route("/users")
def users():

    if "username" not in session:
        return redirect("/")

    conn=get_db()
    cur=conn.cursor()

    cur.execute("SELECT * FROM users ORDER BY id")
    users=cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM users")
    total_users=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users WHERE role='Admin'")
    admins=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users WHERE role='Employee'")
    employees=cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(DISTINCT username)
        FROM login_logs
        WHERE status='Success'
    """)
    active_users=cur.fetchone()[0]

    conn.close()

    return render_template(

        "users.html",

        username=session["username"],

        role=session["role"],

        users=users,

        total_users=total_users,

        admins=admins,

        employees=employees,

        active_users=active_users

    )
@app.route("/delete_user/<int:id>")
def delete_user(id):

    if "username" not in session:
        return redirect("/")

    conn=get_db()
    cur=conn.cursor()

    cur.execute("DELETE FROM users WHERE id=?", (id,))

    conn.commit()
    conn.close()

    return redirect("/users")
@app.route("/edit_user/<int:id>")
def edit_user(id):

    return f"Edit User ID: {id}"

# ==========================
# SETTINGS
# ==========================

@app.route("/settings", methods=["GET","POST"])
def settings():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM settings WHERE id=1")
    settings = cur.fetchone()

    if settings is None:

        cur.execute("""

        INSERT INTO settings

        (id)

        VALUES(1)

        """)

        conn.commit()

        cur.execute("SELECT * FROM settings WHERE id=1")
        settings = cur.fetchone()

    if request.method == "POST":

        usb = 1 if "usb_monitor" in request.form else 0
        file = 1 if "file_monitor" in request.form else 0
        login = 1 if "login_monitor" in request.form else 0
        email = 1 if "email_alert" in request.form else 0
        backup = 1 if "backup" in request.form else 0

        interval = request.form["scan_interval"]

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

        """,

        (

        usb,

        file,

        login,

        email,

        backup,

        interval

        ))

        conn.commit()

        return redirect("/settings")

    conn.close()

    return render_template(

        "settings.html",

        username=session["username"],

        role=session["role"],

        settings=settings

    )

# ==========================
# EMPLOYEE MY ACTIVITIES
# ==========================

@app.route("/employee_activity")
def employee_activity():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    username = session["username"]

    cur.execute("""
        SELECT *
        FROM activity_logs
        WHERE username=?
        ORDER BY id DESC
    """, (username,))

    activities = cur.fetchall()

    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE username=?
    """, (username,))
    total = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE username=?
        AND risk_level='High'
    """, (username,))
    high = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE username=?
        AND risk_level='Medium'
    """, (username,))
    medium = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE username=?
        AND risk_level='Low'
    """, (username,))
    low = cur.fetchone()[0]

    conn.close()

    return render_template(
        "employee_activity.html",
        username=username,
        activities=activities,
        total=total,
        high=high,
        medium=medium,
        low=low
    )

# ==========================
# EMPLOYEE MY ALERTS
# ==========================

@app.route("/employee_alerts")
def employee_alerts():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    username = session["username"]

    # Employee's Alerts
    cur.execute("""
        SELECT *
        FROM alerts
        WHERE username=?
        ORDER BY id DESC
    """, (username,))

    alerts = cur.fetchall()

    # Total Alerts
    cur.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE username=?
    """, (username,))
    total = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE username=?
        AND severity='High'
    """, (username,))
    high = cur.fetchone()[0]

    # Medium Alerts
    cur.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE username=?
        AND severity='Medium'
    """, (username,))
    medium = cur.fetchone()[0]

    # Resolved Alerts
    cur.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE username=?
        AND status='Resolved'
    """, (username,))
    resolved = cur.fetchone()[0]

    conn.close()

    return render_template(
        "employee_alerts.html",
        username=username,
        alerts=alerts,
        total=total,
        high=high,
        medium=medium,
        resolved=resolved
    )
# ==========================
# EMPLOYEE PROFILE
# ==========================

@app.route("/employee_profile", methods=["GET", "POST"])
def employee_profile():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    username = session["username"]

    if request.method == "POST":

        fullname = request.form["fullname"]
        email = request.form["email"]
        department = request.form["department"]

        cur.execute("""
            UPDATE users
            SET fullname=?,
                email=?,
                department=?
            WHERE username=?
        """, (fullname, email, department, username))

        conn.commit()

        flash("Profile Updated Successfully")

    cur.execute("""
        SELECT *
        FROM users
        WHERE username=?
    """, (username,))

    user = cur.fetchone()

    conn.close()

    return render_template(
        "employee_profile.html",
        user=user
    )
# ==========================
# CHANGE PASSWORD
# ==========================

@app.route("/change_password", methods=["GET", "POST"])
def change_password():

    if "username" not in session:
        return redirect("/")

    if request.method == "POST":

        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT password FROM users WHERE username=?",
            (session["username"],)
        )

        user = cur.fetchone()

        if not check_password_hash(user["password"], current_password):
            flash("Current password is incorrect.")
            conn.close()
            return redirect("/change_password")

        if new_password != confirm_password:
            flash("New passwords do not match.")
            conn.close()
            return redirect("/change_password")

        hashed_password = generate_password_hash(new_password)

        cur.execute("""
            UPDATE users
            SET password=?
            WHERE username=?
        """, (hashed_password, session["username"]))

        conn.commit()
        conn.close()

        flash("Password changed successfully.")
        return redirect("/employee_profile")

    return render_template("change_password.html")

#================================
# USB HISTORY
#================================
@app.route("/usb_history")
def usb_history():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM usb_logs ORDER BY id DESC")
    logs = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM usb_logs")
    total = cur.fetchone()[0]
    print("Total:", total)

    cur.execute("SELECT COUNT(*) FROM usb_logs WHERE action='Inserted'")
    inserted = cur.fetchone()[0]
    print("Inserted:", inserted)

    cur.execute("SELECT COUNT(*) FROM usb_logs WHERE action='Removed'")
    removed = cur.fetchone()[0]
    print("Removed:", removed)

    active = inserted- removed
    if active < 0:
        active = 0

    conn.close()

    print("Inserted =", inserted)
    print("Removed =", removed)
    print("Total =", total)
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

#=========================
# FILE HISTORY
#=========================
@app.route("/file_history")
def file_history():

    if "username" not in session:
        return redirect("/")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM file_logs ORDER BY id DESC")
    logs = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM file_logs")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM file_logs WHERE action='File Created'")
    created = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM file_logs WHERE action='File Modified'")
    modified = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM file_logs WHERE action='File Deleted'")
    deleted = cur.fetchone()[0]

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

# ==========================
# START SERVER
# ==========================
if __name__ == "__main__":

    start_services()

    app.run(
        debug=True,
        use_reloader=False
    )