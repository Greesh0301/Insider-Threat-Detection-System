import sqlite3
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

DATABASE = "threat.db"
WATCH_FOLDER = "monitored_folder"


# ==========================
# SAVE FILE EVENT
# ==========================

def save_event(username, action, file_path):

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    filename = os.path.basename(file_path)

    date = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().strftime("%H:%M:%S")

    # File Logs
    cur.execute("""
        INSERT INTO file_logs
        (username,file_name,file_path,action,date,time)
        VALUES(?,?,?,?,?,?)
    """, (
        username,
        filename,
        file_path,
        action,
        date,
        current_time
    ))

    # Activity Logs
    cur.execute("""
        INSERT INTO activity_logs
        (username,activity,details,risk_level,date,time)
        VALUES(?,?,?,?,?,?)
    """, (
        username,
        action,
        filename,
        "Medium",
        date,
        current_time
    ))

    # Alerts
    cur.execute("""
        INSERT INTO alerts
        (username,alert_type,description,severity,date,time)
        VALUES(?,?,?,?,?,?)
    """, (
        username,
        "File Activity",
        f"{action}: {filename}",
        "Medium",
        date,
        current_time
    ))

    conn.commit()
    conn.close()

    print(f"{action}: {filename}")


# ==========================
# FILE MONITOR CLASS
# ==========================

class FileMonitor(FileSystemEventHandler):

    def __init__(self, username):
        super().__init__()
        self.username = username

    def on_created(self, event):
        if not event.is_directory:
            save_event(
                self.username,
                "File Created",
                event.src_path
            )

    def on_deleted(self, event):
        if not event.is_directory:
            save_event(
                self.username,
                "File Deleted",
                event.src_path
            )

    def on_modified(self, event):
        if not event.is_directory:
            save_event(
                self.username,
                "File Modified",
                event.src_path
            )

    def on_moved(self, event):
        if not event.is_directory:
            save_event(
                self.username,
                "File Renamed",
                event.dest_path
            )


# ==========================
# START FILE MONITOR
# ==========================

def start_file_monitor(username):

    if not os.path.exists(WATCH_FOLDER):
        os.makedirs(WATCH_FOLDER)

    observer = Observer()

    event_handler = FileMonitor(username)

    observer.schedule(
        event_handler,
        WATCH_FOLDER,
        recursive=True
    )

    observer.start()

    print(f"File Monitor Started for {username}")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()