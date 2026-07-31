import sqlite3

conn = sqlite3.connect("threat.db")   # Use the same path as your app
cur = conn.cursor()

cur.execute("PRAGMA table_info(usb_logs)")

for row in cur.fetchall():
    print(row)

conn.close()