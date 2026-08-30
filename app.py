from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db, init_db
from monitor import start_services, set_current_user, log_login, log_activity
from datetime import datetime
import sqlite3
import socket
import platform

app = Flask(__name__)
app.secret_key = "insider_threat_secret_key"


def login_required():
    return "username" in session


def system_info():
    """Return simple computer information for login logs."""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "Unknown"
    return ip, platform.node()


def page(name, **data):
    """Send common username/role values to every template."""
    data["username"] = session.get("username")
    data["role"] = session.get("role")
    return render_template(name, **data)


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            set_current_user(username)

            log_login(username, "Success")
            conn.close()

            if user["role"].lower() == "admin":
                return redirect("/dashboard")
            return redirect("/employee_dashboard")

        conn.close()
        log_login(username, "Failed")
        flash("Invalid Username or Password")

    return render_template("login.html")


# ---------------- EMPLOYEE DASHBOARD ----------------
@app.route("/employee_dashboard")
def employee_dashboard():
    if not login_required():
        return redirect("/")

    username = session["username"]
    conn = get_db()

    activities = conn.execute(
        "SELECT COUNT(*) FROM activity_logs WHERE username=?", (username,)
    ).fetchone()[0]

    alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE username=?", (username,)
    ).fetchone()[0]

    risk = conn.execute("""
        SELECT score FROM risk_scores
        WHERE username=? ORDER BY id DESC LIMIT 1
    """, (username,)).fetchone()

    last = conn.execute("""
        SELECT login_time FROM login_logs
        WHERE username=? ORDER BY id DESC LIMIT 1
    """, (username,)).fetchone()

    recent = conn.execute("""
        SELECT * FROM activity_logs
        WHERE username=? ORDER BY id DESC LIMIT 8
    """, (username,)).fetchall()

    alerts_list = conn.execute("""
        SELECT * FROM alerts
        WHERE username=? ORDER BY id DESC LIMIT 5
    """, (username,)).fetchall()

    conn.close()

    return page(
        "employee_dashboard.html",
        activities=activities,
        alerts=alerts,
        risk_score=risk["score"] if risk else 0,
        last_login=last["login_time"] if last else "No Login",
        recent=recent,
        alerts_list=alerts_list
    )




# ---------------- ADMIN DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect("/")

    conn = get_db()

    data = {
        "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "logins": conn.execute(
            "SELECT COUNT(DISTINCT username) FROM login_logs WHERE status='Success'"
        ).fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "files": conn.execute("SELECT COUNT(*) FROM file_logs").fetchone()[0],
        "activities": conn.execute("""
            SELECT username,activity,date,time,risk_level
            FROM activity_logs ORDER BY id DESC LIMIT 15
        """).fetchall()
    }

    alerts = conn.execute("""
        SELECT description FROM alerts ORDER BY id DESC LIMIT 5
    """).fetchall()

    usb = conn.execute("SELECT COUNT(*) FROM usb_logs").fetchone()[0]
    files = conn.execute("SELECT COUNT(*) FROM file_logs").fetchone()[0]
    conn.close()

    return page("dashboard.html", data=data, alerts=alerts, usb=usb, files=files)


# ---------------- REPORTS ----------------
@app.route("/reports")
def reports():
    if not login_required():
        return redirect("/")

    conn = get_db()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_logs = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    high_risk = conn.execute(
        "SELECT COUNT(*) FROM activity_logs WHERE risk_level='High'"
    ).fetchone()[0]

    rows = conn.execute("""
        SELECT id,username,activity AS report_type,
               risk_level,date,'Completed' AS status
        FROM activity_logs ORDER BY id DESC
    """).fetchall()
    conn.close()

    return page(
        "reports.html",
        total_users=total_users,
        total_logs=total_logs,
        total_alerts=total_alerts,
        high_risk=high_risk,
        reports=rows
    )


# ---------------- ACTIVITY ----------------
@app.route("/activity")
def activity():
    if not login_required():
        return redirect("/")

    conn = get_db()
    activities = conn.execute(
        "SELECT * FROM activity_logs ORDER BY id DESC"
    ).fetchall()

    total = len(activities)
    high = sum(1 for x in activities if x["risk_level"] == "High")
    medium = sum(1 for x in activities if x["risk_level"] == "Medium")
    low = sum(1 for x in activities if x["risk_level"] == "Low")
    conn.close()

    return page(
        "activity.html",
        activities=activities,
        total_logs=total,
        high_risk=high,
        medium_risk=medium,
        low_risk=low
    )


# ---------------- ALERTS ----------------
@app.route("/alerts")
def alerts():
    if not login_required():
        return redirect("/")

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 50"
    ).fetchall()

    total = len(rows)
    high = sum(1 for x in rows if x["severity"] == "High")
    medium = sum(1 for x in rows if x["severity"] == "Medium")
    resolved = sum(1 for x in rows if x["status"] == "Resolved")
    conn.close()

    return page(
        "alerts.html",
        alerts=rows,
        total_alerts=total,
        high_alerts=high,
        medium_alerts=medium,
        resolved_alerts=resolved
    )


@app.route("/resolve_alert/<int:id>")
def resolve_alert(id):
    if not login_required():
        return redirect("/")
    conn = get_db()
    conn.execute("UPDATE alerts SET status='Resolved' WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect("/alerts")


@app.route("/delete_alert/<int:id>")
def delete_alert(id):
    if not login_required():
        return redirect("/")
    conn = get_db()
    conn.execute("DELETE FROM alerts WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect("/alerts")


# ---------------- USERS ----------------
@app.route("/users")
def users():
    if not login_required():
        return redirect("/")

    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()

    total = len(rows)
    admins = sum(1 for x in rows if x["role"] == "Admin")
    employees = sum(1 for x in rows if x["role"] == "Employee")
    active = conn.execute("""
        SELECT COUNT(DISTINCT username)
        FROM login_logs WHERE status='Success'
    """).fetchone()[0]
    conn.close()

    return page(
        "users.html",
        users=rows,
        total_users=total,
        admins=admins,
        employees=employees,
        active_users=active
    )


@app.route("/add_user", methods=["GET", "POST"])
def add_user():
    if not login_required():
        return redirect("/")

    if request.method == "POST":
        try:
            conn = get_db()
            conn.execute("""
                INSERT INTO users
                (username,password,fullname,email,department,role)
                VALUES (?,?,?,?,?,?)
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
            return redirect("/users")
        except sqlite3.IntegrityError:
            flash("Username already exists.")

    return render_template("add_user.html")


@app.route("/delete_user/<int:id>")
def delete_user(id):
    if not login_required():
        return redirect("/")

    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect("/users")


@app.route("/edit_user/<int:id>")
def edit_user(id):
    # Kept because the original UI has this button.
    return f"Edit User ID: {id}"



# ---------------- EMPLOYEE PAGES ----------------
@app.route("/employee_activity")
def employee_activity():
    if not login_required():
        return redirect("/")

    username = session["username"]
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM activity_logs
        WHERE username=? ORDER BY id DESC
    """, (username,)).fetchall()
    conn.close()

    return render_template(
        "employee_activity.html",
        username=username,
        activities=rows,
        total=len(rows),
        high=sum(x["risk_level"] == "High" for x in rows),
        medium=sum(x["risk_level"] == "Medium" for x in rows),
        low=sum(x["risk_level"] == "Low" for x in rows)
    )


@app.route("/employee_alerts")
def employee_alerts():
    if not login_required():
        return redirect("/")

    username = session["username"]
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM alerts
        WHERE username=? ORDER BY id DESC
    """, (username,)).fetchall()
    conn.close()

    return render_template(
        "employee_alerts.html",
        username=username,
        alerts=rows,
        total=len(rows),
        high=sum(x["severity"] == "High" for x in rows),
        medium=sum(x["severity"] == "Medium" for x in rows),
        resolved=sum(x["status"] == "Resolved" for x in rows)
    )


@app.route("/employee_profile", methods=["GET", "POST"])
def employee_profile():
    if not login_required():
        return redirect("/")

    username = session["username"]
    conn = get_db()

    if request.method == "POST":
        conn.execute("""
            UPDATE users
            SET fullname=?,email=?,department=?
            WHERE username=?
        """, (
            request.form["fullname"],
            request.form["email"],
            request.form["department"],
            username
        ))
        conn.commit()
        flash("Profile Updated Successfully")

    user = conn.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    return render_template("employee_profile.html", user=user)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not login_required():
        return redirect("/")

    if request.method == "POST":
        conn = get_db()
        user = conn.execute(
            "SELECT password FROM users WHERE username=?",
            (session["username"],)
        ).fetchone()

        if not check_password_hash(user["password"], request.form["current_password"]):
            conn.close()
            flash("Current password is incorrect.")
            return redirect("/change_password")

        if request.form["new_password"] != request.form["confirm_password"]:
            conn.close()
            flash("New passwords do not match.")
            return redirect("/change_password")

        conn.execute(
            "UPDATE users SET password=? WHERE username=?",
            (generate_password_hash(request.form["new_password"]),
             session["username"])
        )
        conn.commit()
        conn.close()
        flash("Password changed successfully.")
        return redirect("/employee_profile")

    return render_template("change_password.html")


# ---------------- HISTORY PAGES ----------------
@app.route("/usb_history")
def usb_history():
    if not login_required():
        return redirect("/")

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM usb_logs ORDER BY id DESC"
    ).fetchall()
    conn.close()

    inserted = sum(x["action"] == "Inserted" for x in rows)
    removed = sum(x["action"] == "Removed" for x in rows)

    return page(
        "usb_history.html",
        logs=rows,
        total=len(rows),
        inserted=inserted,
        removed=removed,
        active=max(0, inserted - removed)
    )


@app.route("/file_history")
def file_history():
    if not login_required():
        return redirect("/")

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM file_logs ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return page(
        "file_history.html",
        logs=rows,
        total=len(rows),
        created=sum(x["action"] == "File Created" for x in rows),
        modified=sum(x["action"] == "File Modified" for x in rows),
        deleted=sum(x["action"] == "File Deleted" for x in rows)
    )


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    username = session.get("username")

    if username:
        conn = get_db()
        conn.execute("""
            UPDATE login_logs
            SET logout_time=?
            WHERE username=? AND logout_time IS NULL
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username))
        conn.commit()
        conn.close()
        log_activity(username, "Logout", "User logged out", "Low")

    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    start_services()
    app.run(debug=True, use_reloader=False)
