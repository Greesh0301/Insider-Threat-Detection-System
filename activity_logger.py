import sqlite3

DATABASE = "threat.db"


def log_activity(username, activity, category, risk):

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO activity_logs
        (username, activity, category, risk_score)
        VALUES (?,?,?,?)
    """, (username, activity, category, risk))

    conn.commit()
    conn.close()


def log_usb(device, event):

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO usb_logs
        (drive_name,event)
        VALUES (?,?)
    """, (device, event))

    conn.commit()
    conn.close()


def log_file(file_name, event):

    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO file_logs
        (file_name,event)
        VALUES (?,?)
    """, (file_name, event))

    conn.commit()
    conn.close()