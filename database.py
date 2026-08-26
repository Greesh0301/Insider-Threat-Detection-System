import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = "threat.db"


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



# ==========================================
# INITIALIZE DATABASE
# ==========================================

def init_db():

    conn = get_db()
    cur = conn.cursor()


    # ---------------- USERS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        fullname TEXT,
        email TEXT,
        department TEXT,
        role TEXT DEFAULT 'Employee'
    )
    """)



    # ---------------- LOGIN LOGS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_time TEXT,
        logout_time TEXT,
        ip_address TEXT,
        device_name TEXT,
        status TEXT,
        risk TEXT
    )
    """)



    # ---------------- ACTIVITY LOGS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        activity TEXT,
        details TEXT,
        risk_level TEXT,
        date TEXT,
        time TEXT
    )
    """)



    # ---------------- USB LOGS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usb_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        device_name TEXT,
        action TEXT,
        date TEXT,
        time TEXT
    )
    """)



    # ---------------- FILE LOGS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS file_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        file_name TEXT,
        file_path TEXT,
        action TEXT,
        date TEXT,
        time TEXT
    )
    """)



    # ---------------- ALERTS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        alert_type TEXT,
        description TEXT,
        severity TEXT,
        status TEXT DEFAULT 'Pending',
        date TEXT,
        time TEXT
    )
    """)



    # ---------------- RISK SCORES ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS risk_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        score INTEGER,
        level TEXT,
        updated_on TEXT
    )
    """)



    # ---------------- SETTINGS ----------------

    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        usb_monitor INTEGER DEFAULT 1,
        file_monitor INTEGER DEFAULT 1,
        login_monitor INTEGER DEFAULT 1,
        email_alert INTEGER DEFAULT 1,
        backup INTEGER DEFAULT 1,
        scan_interval INTEGER DEFAULT 5
    )
    """)



    # ---------------- DEFAULT ADMIN ----------------

    cur.execute(
        "SELECT id FROM users WHERE username=?",
        ("admin",)
    )

    if cur.fetchone() is None:

        cur.execute("""
        INSERT INTO users
        (username,password,fullname,email,department,role)
        VALUES (?,?,?,?,?,?)
        """,
        (
            "admin",
            generate_password_hash("admin123"),
            "System Administrator",
            "admin@gmail.com",
            "IT",
            "Admin"
        ))



    # ---------------- DEFAULT SETTINGS ----------------

    cur.execute(
        "SELECT id FROM settings WHERE id=1"
    )

    if cur.fetchone() is None:

        cur.execute("""
        INSERT INTO settings(id)
        VALUES(1)
        """)



    conn.commit()
    conn.close()



# ==========================================
# RUN DATABASE CREATION
# ==========================================

if __name__ == "__main__":

    init_db()
    print("Database ready.")