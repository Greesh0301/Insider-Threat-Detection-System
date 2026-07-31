import sqlite3
from datetime import datetime

DATABASE = "threat.db"

# Sensitive files to monitor
SENSITIVE_FILES = [
    "salary.xlsx",
    "payroll.xlsx",
    "employees.db",
    "confidential.docx",
    "finance.xlsx",
    "secret.pdf"
]


def get_db():
    return sqlite3.connect(DATABASE)


# ---------------------------------
# Create Alert
# ---------------------------------
def create_alert(username, alert_type, description, severity):

    conn = get_db()
    cur = conn.cursor()

    now = datetime.now()

    cur.execute("""
    INSERT INTO alerts
    (username,alert_type,description,severity,date,time)

    VALUES(?,?,?,?,?,?)
    """,(

        username,
        alert_type,
        description,
        severity,
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S")

    ))

    conn.commit()
    conn.close()


# ---------------------------------
# Risk Score
# ---------------------------------
def update_risk(username, score):

    if score >= 80:
        level = "High"

    elif score >= 40:
        level = "Medium"

    else:
        level = "Low"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""

    INSERT INTO risk_scores

    (username,score,level,updated_on)

    VALUES(?,?,?,?)

    """,

    (
        username,
        score,
        level,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# ---------------------------------
# Failed Login Detection
# ---------------------------------
def detect_failed_login():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""

    SELECT username,COUNT(*)

    FROM login_logs

    WHERE status='Failed'

    GROUP BY username

    """)

    rows = cur.fetchall()

    conn.close()

    for username,count in rows:

        if count >= 3:

            create_alert(

                username,

                "Failed Login",

                "More than 3 failed login attempts",

                "High"

            )

            update_risk(username,60)


# ---------------------------------
# Late Night Login
# ---------------------------------
def detect_late_login():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""

    SELECT username,login_time

    FROM login_logs

    WHERE status='Success'

    """)

    rows = cur.fetchall()

    conn.close()

    for username,login in rows:

        hour = int(login.split(" ")[1].split(":")[0])

        if hour < 6 or hour > 22:

            create_alert(

                username,

                "Late Login",

                "Login outside office hours",

                "Medium"

            )

            update_risk(username,30)


# ---------------------------------
# Sensitive File Detection
# ---------------------------------
def detect_sensitive_files():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""

    SELECT username,file_name

    FROM file_logs

    """)

    rows = cur.fetchall()

    conn.close()

    for username,file in rows:

        if file.lower() in [x.lower() for x in SENSITIVE_FILES]:

            create_alert(

                username,

                "Sensitive File",

                file + " accessed",

                "High"

            )

            update_risk(username,80)


# ---------------------------------
# USB Detection
# ---------------------------------
def detect_usb_usage():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""

    SELECT username,COUNT(*)

    FROM usb_logs

    GROUP BY username

    """)

    rows = cur.fetchall()

    conn.close()

    for username,count in rows:

        if count >= 5:

            create_alert(

                username,

                "USB Usage",

                "Frequent USB device usage detected",

                "Medium"

            )

            update_risk(username,40)


# ---------------------------------
# File Modification Detection
# ---------------------------------
def detect_mass_modification():

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""

    SELECT username,COUNT(*)

    FROM file_logs

    WHERE action='File Modified'

    GROUP BY username

    """)

    rows = cur.fetchall()

    conn.close()

    for username,count in rows:

        if count >= 20:

            create_alert(

                username,

                "Mass File Modification",

                "Large number of files modified",

                "High"

            )

            update_risk(username,90)


# ---------------------------------
# Run All Detection Rules
# ---------------------------------
def run_detector():

    print("Running Threat Detection...")

    detect_failed_login()

    detect_late_login()

    detect_sensitive_files()

    detect_usb_usage()

    detect_mass_modification()

    print("Threat Detection Completed.")


if __name__ == "__main__":

    run_detector()