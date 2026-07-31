import sqlite3

DB_NAME = "threat.db"

def create_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # ===========================
    # USERS TABLE
    # ===========================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    fullname TEXT,
    email TEXT,
    department TEXT,
    role TEXT DEFAULT 'Employee'
)
""")
    # ===========================
    # LOGIN LOGS
    # ===========================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        login_time TEXT,
        logout_time TEXT,
        ip_address TEXT,
        device_name TEXT,
        status TEXT 
    )
    """)
   # ===========================
    # ACTIVITY LOGS
    # ===========================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        activity TEXT,
        details TEXT,
        risk_level TEXT,
        date TEXT,
        time TEXT
    )
    """)

    # ===========================
    # USB LOGS
    # ===========================
    cursor.execute("""
CREATE TABLE IF NOT EXISTS usb_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    device_name TEXT,
    action TEXT,
    date TEXT,
    time TEXT
)
""")
    # ===========================
    # FILE MONITOR LOGS
    # ===========================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        file_name TEXT,
        file_path TEXT,
        action TEXT,
        date TEXT,
        time TEXT
    )
    """)

    # ===========================
    # ALERTS
    # ===========================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
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

    # ===========================
    # RISK SCORE
    # ===========================
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_scores(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        score INTEGER,
        level TEXT,
        updated_on TEXT
    )
    """)
    # ===========================
    # SETTINGS
    # ===========================

    cursor.execute("""

     CREATE TABLE IF NOT EXISTS settings(
         id INTEGER PRIMARY KEY,
         usb_monitor INTEGER DEFAULT 1,
         file_monitor INTEGER DEFAULT 1,
         login_monitor INTEGER DEFAULT 1,
         email_alert INTEGER DEFAULT 1,
         backup INTEGER DEFAULT 1,
         scan_interval INTEGER DEFAULT 5
    )
    """)

    conn.commit()
    conn.close()

    print("Database Created Successfully!")
    

if __name__ == "__main__":
    create_database()