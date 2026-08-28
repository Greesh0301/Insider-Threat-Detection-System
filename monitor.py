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
    "salary.xlsx",
    "payroll.xlsx",
    "employees.db",
    "confidential.docx",
    "finance.xlsx",
    "secret.pdf"
}


_current_user = "Unknown"
_services_started = False
_file_observer = None
_previous_usb = set()



# ================= DATABASE =================

def _db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



def _now():
    now = datetime.now()
    return (
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S")
    )



# ================= USER =================

def set_current_user(username):
    global _current_user
    _current_user = username



# ================= ACTIVITY =================

def log_activity(username, activity, description, risk):

    conn = _db()

    date, clock = _now()

    conn.execute("""
    INSERT INTO activity_logs
    (
        username,
        activity,
        details,
        risk_level,
        date,
        time
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """,
    (
        username,
        activity,
        description,
        risk,
        date,
        clock
    ))

    conn.commit()
    conn.close()



# ================= ALERT =================

def add_alert(username, alert_type, description, severity):

    date, clock = _now()

    conn = _db()

    conn.execute("""
    INSERT INTO alerts
    (
        username,
        alert_type,
        description,
        severity,
        status,
        date,
        time
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
    (
        username,
        alert_type,
        description,
        severity,
        "Pending",
        date,
        clock
    ))

    conn.commit()
    conn.close()



# ================= RISK =================

def update_risk(username):

    conn = _db()

    score = 0


    score += conn.execute("""
    SELECT COUNT(*)
    FROM login_logs
    WHERE username=?
    AND status='Failed'
    """,
    (username,)
    ).fetchone()[0] * 10


    score += conn.execute("""
    SELECT COUNT(*)
    FROM alerts
    WHERE username=?
    AND severity='Medium'
    """,
    (username,)
    ).fetchone()[0] * 5


    score += conn.execute("""
    SELECT COUNT(*)
    FROM alerts
    WHERE username=?
    AND severity='High'
    """,
    (username,)
    ).fetchone()[0] * 15


    score = min(score,100)


    if score >= 80:
        level = "High"

    elif score >= 40:
        level = "Medium"

    else:
        level = "Low"



    conn.execute("""
    INSERT INTO risk_scores
    (
        username,
        score,
        level,
        updated_on
    )
    VALUES (?, ?, ?, ?)
    """,
    (
        username,
        score,
        level,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))


    conn.commit()
    conn.close()



# ================= LOGIN =================

def log_login(username,status):

    now = datetime.now()

    ip = socket.gethostbyname(socket.gethostname())

    device = platform.node()


    conn = _db()


    conn.execute("""
    INSERT INTO login_logs
    (
        username,
        login_time,
        ip_address,
        device_name,
        status,
        risk
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """,
    (
        username,
        now.strftime("%Y-%m-%d %H:%M:%S"),
        ip,
        device,
        status,
        "Low"
    ))


    conn.commit()



    if status == "Success":


        failed = conn.execute("""
        SELECT COUNT(*)
        FROM login_logs
        WHERE username=?
        AND status='Failed'
        """,
        (username,)
        ).fetchone()[0]


        if now.hour >= 21:

            log_activity(
                username,
                "Late Login",
                "Login after 9 PM",
                "High"
            )

            add_alert(
                username,
                "Late Login",
                "User logged in after office hours",
                "High"
            )


        elif failed >= 3:

            log_activity(
                username,
                "Suspicious Login",
                "Successful login after multiple failures",
                "High"
            )


            add_alert(
                username,
                "Suspicious Login",
                "3 or more failed attempts",
                "High"
            )


        elif failed == 2:

            log_activity(
                username,
                "Suspicious Login",
                "Login after two failures",
                "Medium"
            )


            add_alert(
                username,
                "Suspicious Login",
                "Two failed attempts",
                "Medium"
            )


        else:

            log_activity(
                username,
                "Login",
                "User logged into system",
                "Low"
            )



    conn.close()

    update_risk(username)



# ================= FILE MONITOR =================

def save_file_event(username,action,path):

    filename=os.path.basename(path)

    date,clock=_now()


    conn=_db()


    conn.execute("""
    INSERT INTO file_logs
    (
        username,
        file_name,
        file_path,
        action,
        date,
        time
    )
    VALUES (?,?,?,?,?,?)
    """,
    (
        username,
        filename,
        path,
        action,
        date,
        clock
    ))



    conn.execute("""
    INSERT INTO activity_logs
    (
        username,
        activity,
        details,
        risk_level,
        date,
        time
    )
    VALUES (?,?,?,?,?,?)
    """,
    (
        username,
        action,
        filename,
        "Medium",
        date,
        clock
    ))


    conn.commit()


    if filename.lower() in {x.lower() for x in SENSITIVE_FILES}:

        conn.execute("""
        INSERT INTO alerts
        (
            username,
            alert_type,
            description,
            severity,
            status,
            date,
            time
        )
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            username,
            "Sensitive File",
            filename+" accessed",
            "High",
            "Pending",
            date,
            clock
        ))


    conn.commit()
    conn.close()

    update_risk(username)



# ================= USB MONITOR =================

def save_usb_event(username,device,action):

    date,clock=_now()

    conn=_db()


    conn.execute("""
    INSERT INTO usb_logs
    (
        username,
        device_name,
        action,
        date,
        time
    )
    VALUES (?,?,?,?,?)
    """,
    (
        username,
        device,
        action,
        date,
        clock
    ))


    conn.execute("""
    INSERT INTO activity_logs
    (
        username,
        activity,
        details,
        risk_level,
        date,
        time
    )
    VALUES (?,?,?,?,?,?)
    """,
    (
        username,
        "USB "+action,
        device,
        "Medium",
        date,
        clock
    ))


    conn.commit()
    conn.close()

    update_risk(username)

    
    # ================= USB MONITOR LOOP =================

def _usb_loop():

    global _previous_usb

    if psutil is None:
        return

    while True:

        current = {
            part.device
            for part in psutil.disk_partitions(all=False)
            if "removable" in part.opts.lower()
        }


        for device in current - _previous_usb:
            save_usb_event(
                _current_user,
                device,
                "Inserted"
            )


        for device in _previous_usb - current:
            save_usb_event(
                _current_user,
                device,
                "Removed"
            )


        _previous_usb = current

        time.sleep(2)



# ================= FILE MONITOR =================

if Observer is not None:

    class FileHandler(FileSystemEventHandler):

        def on_created(self,event):

            if not event.is_directory:
                save_file_event(
                    _current_user,
                    "File Created",
                    event.src_path
                )


        def on_modified(self,event):

            if not event.is_directory:
                save_file_event(
                    _current_user,
                    "File Modified",
                    event.src_path
                )


        def on_deleted(self,event):

            if not event.is_directory:
                save_file_event(
                    _current_user,
                    "File Deleted",
                    event.src_path
                )


        def on_moved(self,event):

            if not event.is_directory:
                save_file_event(
                    _current_user,
                    "File Renamed",
                    event.dest_path
                )



_file_observer = None


def _file_loop():

    global _file_observer


    if Observer is None:
        return


    os.makedirs(
        WATCH_FOLDER,
        exist_ok=True
    )


    _file_observer = Observer()

    _file_observer.schedule(
        FileHandler(),
        WATCH_FOLDER,
        recursive=True
    )


    _file_observer.start()


    while True:
        time.sleep(1)




# ================= START SERVICES =================

def start_services():

    global _services_started


    if _services_started:
        return


    _services_started = True


    threading.Thread(
        target=_usb_loop,
        daemon=True
    ).start()


    threading.Thread(
        target=_file_loop,
        daemon=True
    ).start()



# ================= STOP SERVICES =================

def stop_services():

    global _file_observer


    if _file_observer:

        _file_observer.stop()

        _file_observer.join(timeout=2)