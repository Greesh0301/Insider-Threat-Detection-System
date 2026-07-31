import sqlite3
import os
import time
import socket
import platform
import threading
from datetime import datetime


DATABASE = "threat.db"


# ==========================
# DATABASE CONNECTION
# ==========================

def get_db():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    return conn



# ==========================
# SYSTEM DETAILS
# ==========================

def get_ip():

    try:
        return socket.gethostbyname(socket.gethostname())

    except:
        return "Unknown"



def get_device():

    return platform.node()



# ==========================
# SAVE ACTIVITY LOG
# ==========================

def log_activity(username, activity, details, risk="Low"):

    try:

        conn = get_db()
        cur = conn.cursor()

        now = datetime.now()


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

        VALUES(?,?,?,?,?,?)

        """,
        (
        username,
        activity,
        details,
        risk,
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S")
        ))


        conn.commit()
        conn.close()


    except Exception as e:

        print("Activity Log Error:",e)




# ==========================
# CREATE ALERT
# ==========================

def create_alert(username, alert_type, description, severity):

    try:

        conn=get_db()

        cur=conn.cursor()

        now=datetime.now()


        cur.execute("""
        INSERT INTO alerts
        (
        username,
        alert_type,
        description,
        severity,
        status,
        date,
        time
        )

        VALUES(?,?,?,?,?,?,?)

        """,
        (
        username,
        alert_type,
        description,
        severity,
        "Pending",
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S")
        ))


        conn.commit()
        conn.close()


    except Exception as e:

        print("Alert Error:",e)




# ==========================
# LOGIN LOGGER
# ==========================

def log_login(username,status="Success"):


    try:

        conn=get_db()

        cur=conn.cursor()

        now=datetime.now()


        cur.execute("""
        INSERT INTO login_logs
        (
        username,
        login_time,
        ip_address,
        device_name,
        status
        )

        VALUES(?,?,?,?,?)

        """,
        (
        username,
        now.strftime("%Y-%m-%d %H:%M:%S"),
        get_ip(),
        get_device(),
        status
        ))


        conn.commit()
        conn.close()



        log_activity(
            username,
            "Login",
            "Employee logged into system",
            "Low"
        )


    except Exception as e:

        print("Login Log Error:",e)




# ==========================
# FILE MONITOR
# ==========================

def monitor_files(username):


    folder=os.path.expanduser("~/Downloads")


    old_files=set(os.listdir(folder))


    while True:


        time.sleep(5)


        try:

            new_files=set(os.listdir(folder))


            added=new_files-old_files


            for file in added:


                now=datetime.now()


                conn=get_db()

                cur=conn.cursor()



                cur.execute("""
                INSERT INTO file_logs
                (
                username,
                file_name,
                access_time
                )

                VALUES(?,?,?)

                """,
                (
                username,
                file,
                now.strftime("%Y-%m-%d %H:%M:%S")
                ))



                conn.commit()

                conn.close()



                log_activity(
                    username,
                    "File Access",
                    "Accessed file : "+file,
                    "Medium"
                )


                create_alert(
                    username,
                    "File Access",
                    "Employee accessed file : "+file,
                    "Medium"
                )


            old_files=new_files



        except Exception as e:

            print("File Monitor Error:",e)






# ==========================
# START EMPLOYEE MONITOR
# ==========================

def start_employee_monitor(username):


    file_thread=threading.Thread(
        target=monitor_files,
        args=(username,),
        daemon=True
    )


    file_thread.start()



    print("------------------------------")
    print("Employee Monitoring Started")
    print("User:",username)
    print("------------------------------")