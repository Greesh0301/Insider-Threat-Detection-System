import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = "threat.db"


def get_db():
    """Open the SQLite database and return rows like dictionaries."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all tables and the default admin account."""
    conn = get_db()
    cur = conn.cursor()

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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, login_time TEXT, logout_time TEXT,
            ip_address TEXT, device_name TEXT, status TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, activity TEXT, details TEXT,
            risk_level TEXT, date TEXT, time TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usb_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, device_name TEXT, action TEXT,
            date TEXT, time TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, file_name TEXT, file_path TEXT,
            action TEXT, date TEXT, time TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, alert_type TEXT, description TEXT,
            severity TEXT, status TEXT DEFAULT 'Pending',
            date TEXT, time TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, score INTEGER, level TEXT, updated_on TEXT
        )
    """)

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

    # Demo/admin account. Password: admin123
    cur.execute("SELECT id FROM users WHERE username=?", ("admin",))
    if cur.fetchone() is None:
        cur.execute("""
            INSERT INTO users
            (username,password,fullname,email,department,role)
            VALUES (?,?,?,?,?,?)
        """, (
            "admin",
            generate_password_hash("admin123"),
            "System Administrator",
            "admin@gmail.com",
            "IT",
            "Admin"
        ))

    cur.execute("SELECT id FROM settings WHERE id=1")
    if cur.fetchone() is None:
        cur.execute("INSERT INTO settings (id) VALUES (1)")

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database ready.")
