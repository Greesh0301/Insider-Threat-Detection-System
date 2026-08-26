import os
import time
import socket
import platform
import sqlite3
import threading
from datetime import datetime

DATABASE = "threat.db"
WATCH_FOLDER = "monitored_folder"

try:
    import psutil
except ImportError:
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object


SENSITIVE_FILES = {
    "salary.xlsx", "payroll.xlsx", "employees.db",
    "confidential.docx", "finance.xlsx", "secret.pdf"
}

_current_user = "Unknown"
_services_started = False
_file_observer = None
_previous_usb = set()


def set_current_user(username):
    """Tell the monitors which logged-in employee is being monitored."""
    global _current_user
    _current_user = username


def _db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def _now():
    now = datetime.now()
    return now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")


def log_activity(username, activity, details, risk="Low"):
    date, clock = _now()
    conn = _db()
    conn.execute("""
        INSERT INTO activity_logs
        (username,activity,details,risk_level,date,time)
        VALUES (?,?,?,?,?,?)
    """, (username, activity, details, risk, date, clock))
    conn.commit()
    conn.close()


def add_alert(username, alert_type, description, severity):
    date, clock = _now()
    conn = _db()
    conn.execute("""
        INSERT INTO alerts
        (username,alert_type,description,severity,status,date,time)
        VALUES (?,?,?,?,?,?,?)
    """, (username, alert_type, description, severity, "Pending", date, clock))
    conn.commit()
    conn.close()


def update_risk(username):
    """Calculate one simple risk score from the user's recent activity."""
    conn = _db()
    score = 0

    score += conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE username=? AND status='Failed'",
        (username,)
    ).fetchone()[0] * 10

    score += conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE username=? AND severity='Medium'",
        (username,)
    ).fetchone()[0] * 5

    score += conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE username=? AND severity='High'",
        (username,)
    ).fetchone()[0] * 15

    score = min(score, 100)
    level = "High" if score >= 80 else "Medium" if score >= 40 else "Low"

    conn.execute("""
        INSERT INTO risk_scores(username,score,level,updated_on)
        VALUES (?,?,?,?)
    """, (username, score, level, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def log_login(username, status):
    """Save a login attempt and detect a late successful login."""
    now = datetime.now()
    ip = socket.gethostbyname(socket.gethostname())
    device = platform.node()

    conn = _db()
    conn.execute("""
        INSERT INTO login_logs
        (username,login_time,ip_address,device_name,status)
        VALUES (?,?,?,?,?)
    """, (username, now.strftime("%Y-%m-%d %H:%M:%S"), ip, device, status))
    conn.commit()
    conn.close()

    if status == "Success":
        log_activity(username, "Login", "User logged into the system", "Low")

        if now.hour < 6 or now.hour > 22:
            add_alert(username, "Late Login",
                      "Login outside office hours", "Medium")
    else:
        # Alert only when the third failed attempt is reached.
        conn = _db()
        count = conn.execute("""
            SELECT COUNT(*) FROM login_logs
            WHERE username=? AND status='Failed'
        """, (username,)).fetchone()[0]
        conn.close()

        if count == 3:
            add_alert(username, "Failed Login",
                      "Three failed login attempts detected", "High")

    update_risk(username)


def save_file_event(username, action, path):
    """Save a file-system event, activity entry and optional threat alert."""
    filename = os.path.basename(path)
    date, clock = _now()

    conn = _db()
    conn.execute("""
        INSERT INTO file_logs
        (username,file_name,file_path,action,date,time)
        VALUES (?,?,?,?,?,?)
    """, (username, filename, path, action, date, clock))

    conn.execute("""
        INSERT INTO activity_logs
        (username,activity,details,risk_level,date,time)
        VALUES (?,?,?,?,?,?)
    """, (username, action, filename, "Medium", date, clock))
    conn.commit()

    if filename.lower() in {x.lower() for x in SENSITIVE_FILES}:
        conn.execute("""
            INSERT INTO alerts
            (username,alert_type,description,severity,status,date,time)
            VALUES (?,?,?,?,?,?,?)
        """, (username, "Sensitive File",
              f"{filename} accessed", "High", "Pending", date, clock))

    conn.commit()
    conn.close()
    update_risk(username)


def save_usb_event(username, device, action):
    """Save USB insertion/removal and create a medium alert."""
    date, clock = _now()
    conn = _db()

    conn.execute("""
        INSERT INTO usb_logs
        (username,device_name,action,date,time)
        VALUES (?,?,?,?,?)
    """, (username, device, action, date, clock))

    conn.execute("""
        INSERT INTO activity_logs
        (username,activity,details,risk_level,date,time)
        VALUES (?,?,?,?,?,?)
    """, (username, "USB " + action, device, "Medium", date, clock))

    conn.execute("""
        INSERT INTO alerts
        (username,alert_type,description,severity,status,date,time)
        VALUES (?,?,?,?,?,?,?)
    """, (username, "USB", f"USB Device {action}: {device}",
          "Medium", "Pending", date, clock))

    conn.commit()
    conn.close()
    update_risk(username)


def _usb_loop():
    """Check removable drives every two seconds."""
    global _previous_usb

    if psutil is None:
        return

    while True:
        current = {
            part.device for part in psutil.disk_partitions(all=False)
            if "removable" in part.opts.lower()
        }

        for device in current - _previous_usb:
            save_usb_event(_current_user, device, "Inserted")

        for device in _previous_usb - current:
            save_usb_event(_current_user, device, "Removed")

        _previous_usb = current
        time.sleep(2)


if Observer is not None:
    class FileHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                save_file_event(_current_user, "File Created", event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                save_file_event(_current_user, "File Modified", event.src_path)

        def on_deleted(self, event):
            if not event.is_directory:
                save_file_event(_current_user, "File Deleted", event.src_path)

        def on_moved(self, event):
            if not event.is_directory:
                save_file_event(_current_user, "File Renamed", event.dest_path)


def _file_loop():
    """Watch the local monitored_folder for file changes."""
    global _file_observer

    if Observer is None:
        return

    os.makedirs(WATCH_FOLDER, exist_ok=True)
    _file_observer = Observer()
    _file_observer.schedule(FileHandler(), WATCH_FOLDER, recursive=True)
    _file_observer.start()

    while True:
        time.sleep(1)


def start_services():
    """Start USB and file monitoring once when Flask starts."""
    global _services_started
    if _services_started:
        return

    _services_started = True
    threading.Thread(target=_usb_loop, daemon=True).start()
    threading.Thread(target=_file_loop, daemon=True).start()


def stop_services():
    """Stop the file observer when the application is closed."""
    global _file_observer
    if _file_observer:
        _file_observer.stop()
        _file_observer.join(timeout=2)
