import sqlite3

conn = sqlite3.connect("database/threat.db")
cursor = conn.cursor()

try:
    cursor.execute("""
    INSERT INTO users(username, password, role)
    VALUES (?, ?, ?)
    """, ("admin", "admin123", "Admin"))

    conn.commit()
    print("Admin user created successfully.")

except sqlite3.IntegrityError:
    print("Admin user already exists.")

conn.close()