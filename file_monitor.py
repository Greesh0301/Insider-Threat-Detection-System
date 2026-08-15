import sqlite3
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

DATABASE = "threat.db"
WATCH_FOLDER = "monitored_folder"

# Ignore duplicate Windows events within 3 seconds
EVENT_COOLDOWN = 3


# =========================================================
# SAVE FILE EVENT
# =========================================================

def save_event(username, action, file_path):

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    # Get only the file name
    filename = os.path.basename(file_path)

    # =====================================================
    # IMPORTANT:
    # Store only monitored_folder + file name
    # NOT the complete Windows path
    # =====================================================

    display_path = os.path.join(
        WATCH_FOLDER,
        filename
    )

    # Convert / to \ for Windows display
    display_path = display_path.replace("/", "\\")

    date = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().strftime("%H:%M:%S")

    # =====================================================
    # FILE LOGS
    # =====================================================

    cur.execute("""
        INSERT INTO file_logs
        (username, file_name, file_path, action, date, time)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        username,
        filename,
        display_path,
        action,
        date,
        current_time
    ))

    # =====================================================
    # ACTIVITY LOGS
    # =====================================================

    cur.execute("""
        INSERT INTO activity_logs
        (username, activity, details, risk_level, date, time)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        username,
        action,
        filename,
        "Medium",
        date,
        current_time
    ))

    # =====================================================
    # ALERTS
    # =====================================================

    cur.execute("""
        INSERT INTO alerts
        (username, alert_type, description, severity, date, time)
        VALUES (?, ?, ?, ?, ?, ?)
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

    print(
        f"[FILE MONITOR] {action}: "
        f"{display_path}"
    )


# =========================================================
# FILE MONITOR
# =========================================================

class FileMonitor(FileSystemEventHandler):

    def __init__(self, username):

        super().__init__()

        self.username = username

        # Store recent events
        self.recent_events = {}

        # Recently created files
        self.recently_created = {}

        # Recently renamed files
        self.recently_renamed = {}

        self.cooldown = EVENT_COOLDOWN


    # =====================================================
    # DUPLICATE CHECK
    # =====================================================

    def is_duplicate(self, action, path):

        path = os.path.abspath(path)

        key = (action, path)

        now = time.time()

        if key in self.recent_events:

            previous_time = self.recent_events[key]

            if now - previous_time < self.cooldown:
                return True

        self.recent_events[key] = now

        return False


    # =====================================================
    # FILE CREATED
    # =====================================================

    def on_created(self, event):

        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)

        if self.is_duplicate("created", path):
            return

        # Remember creation time
        self.recently_created[path] = time.time()

        save_event(
            self.username,
            "File Created",
            path
        )


    # =====================================================
    # FILE MODIFIED
    # =====================================================

    def on_modified(self, event):

        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)

        now = time.time()

        # -------------------------------------------------
        # Ignore modification immediately after creation
        # -------------------------------------------------

        if path in self.recently_created:

            created_time = self.recently_created[path]

            if now - created_time < self.cooldown:

                print(
                    "[IGNORED] Modification after creation:",
                    os.path.basename(path)
                )

                return

            else:

                del self.recently_created[path]


        # -------------------------------------------------
        # Ignore modification immediately after rename
        # -------------------------------------------------

        if path in self.recently_renamed:

            renamed_time = self.recently_renamed[path]

            if now - renamed_time < self.cooldown:

                print(
                    "[IGNORED] Modification after rename:",
                    os.path.basename(path)
                )

                return

            else:

                del self.recently_renamed[path]


        # -------------------------------------------------
        # Ignore duplicate modification
        # -------------------------------------------------

        if self.is_duplicate("modified", path):

            print(
                "[IGNORED] Duplicate modification:",
                os.path.basename(path)
            )

            return


        # -------------------------------------------------
        # Save modification
        # -------------------------------------------------

        save_event(
            self.username,
            "File Modified",
            path
        )


    # =====================================================
    # FILE DELETED
    # =====================================================

    def on_deleted(self, event):

        if event.is_directory:
            return

        path = os.path.abspath(event.src_path)

        if self.is_duplicate("deleted", path):
            return

        save_event(
            self.username,
            "File Deleted",
            path
        )


    # =====================================================
    # FILE RENAMED
    # =====================================================

    def on_moved(self, event):

        if event.is_directory:
            return

        old_path = os.path.abspath(event.src_path)
        new_path = os.path.abspath(event.dest_path)

        now = time.time()

        # -------------------------------------------------
        # Ignore automatic rename immediately after create
        # -------------------------------------------------

        if old_path in self.recently_created:

            created_time = self.recently_created[old_path]

            if now - created_time < self.cooldown:

                print(
                    "[IGNORED] Automatic rename:",
                    os.path.basename(new_path)
                )

                return


        # -------------------------------------------------
        # Ignore duplicate rename
        # -------------------------------------------------

        if self.is_duplicate("renamed", new_path):
            return


        # -------------------------------------------------
        # Remove old path from created list
        # -------------------------------------------------

        if old_path in self.recently_created:
            del self.recently_created[old_path]


        # -------------------------------------------------
        # Remember renamed file
        # -------------------------------------------------

        self.recently_renamed[new_path] = now


        # -------------------------------------------------
        # Save rename
        # -------------------------------------------------

        save_event(
            self.username,
            "File Renamed",
            new_path
        )


# =========================================================
# START FILE MONITOR
# =========================================================

def start_file_monitor(username):

    # Create monitored folder
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

    print("=" * 50)
    print("          FILE MONITOR STARTED")
    print("=" * 50)
    print(f"Username   : {username}")
    print(f"Monitoring : {os.path.abspath(WATCH_FOLDER)}")
    print(f"Display    : {WATCH_FOLDER}\\filename")
    print(f"Cooldown   : {EVENT_COOLDOWN} seconds")
    print("=" * 50)

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("\nStopping File Monitor...")

        observer.stop()

    observer.join()