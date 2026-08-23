import psutil
import sqlite3
import time
import getpass
import threading

from datetime import datetime

DATABASE = "threat.db"

previous_devices = set()


def log_usb(username,device, action):

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    

    now = datetime.now()

    date = now.strftime("%Y-%m-%d")
    current_time = now.strftime("%H:%M:%S")

    # USB Log
    cur.execute("""
        INSERT INTO usb_logs
        (
            username,
            device_name,
            action,
            date,
            time
        )
        VALUES (?,?,?,?,?)
    """, (
        username,
        device,
        action,
        date,
        current_time
    ))

    # Activity Log
    cur.execute("""
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
    """, (
        username,
        "USB " + action,
        device,
        "Medium",
        date,
        current_time
    ))

    # Alert
    cur.execute("""
        INSERT INTO alerts
        (
            username,
            alert_type,
            description,
            severity,
            date,
            time
        )
        VALUES (?,?,?,?,?,?)
    """, (
        username,
        "USB",
        f"USB Device {action}: {device}",
        "Medium",
        date,
        current_time
    ))

    conn.commit()
    conn.close()

    print(f"{action}: {device}")

def get_current_user():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("""
        SELECT username
        FROM login_logs
        WHERE logout_time IS NULL
        ORDER BY id DESC
        LIMIT 1
    """)

    user = cur.fetchone()

    conn.close()

    if user:
        return user["username"]

    return "Unknown"

def monitor_usb():

    global previous_devices

    while True:

        current_devices = set()

        # Detect removable drives
        for part in psutil.disk_partitions(all=False):

            if "removable" in part.opts.lower():
                current_devices.add(part.device)

        inserted = current_devices - previous_devices
        removed = previous_devices - current_devices

        username = get_current_user()

        for device in inserted:
          log_usb(username, device, "Inserted")

        for device in removed:
          log_usb(username, device, "Removed")
        previous_devices = current_devices

        time.sleep(2)


usb_thread = None

def start_usb_monitor():

    global usb_thread

    if usb_thread is None or not usb_thread.is_alive():

        usb_thread = threading.Thread(
            target=monitor_usb,
            daemon=True
        )

        usb_thread.start()

        print("USB Monitor Started")
