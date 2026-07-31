import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("threat.db")
cur = conn.cursor()

employees = [

("rahul",
generate_password_hash("rahul123"),
"Rahul Sharma",
"rahul@gmail.com",
"IT",
"Employee"),

("priya",
generate_password_hash("priya123"),
"Priya Patel",
"priya@gmail.com",
"HR",
"Employee"),

("rohit",
generate_password_hash("rohit123"),
"Rohit Verma",
"rohit@gmail.com",
"Operations",
"Employee"),

("neha",
generate_password_hash("neha123"),
"Neha Joshi",
"neha@gmail.com",
"Finance",
"Employee"),

("karan",
generate_password_hash("karan123"),
"Karan Mehta",
"karan@gmail.com",
"IT",
"Employee"),

("pooja",
generate_password_hash("pooja123"),
"Pooja Deshmukh",
"pooja@gmail.com",
"HR",
"Employee"),

("vikas",
generate_password_hash("vikas123"),
"Vikas Singh",
"vikas@gmail.com",
"Cyber Security",
"Employee"),

("sneha",
generate_password_hash("sneha123"),
"Sneha Kulkarni",
"sneha@gmail.com",
"Marketing",
"Employee"),

("arjun",
generate_password_hash("arjun123"),
"Arjun Nair",
"arjun@gmail.com",
"Operations",
"Employee"),

("meera",
generate_password_hash("meera123"),
"Meera Shah",
"meera@gmail.com",
"Finance",
"Employee"),

("aditya",
generate_password_hash("aditya123"),
"Aditya Rao",
"aditya@gmail.com",
"IT",
"Employee"),

("kavya",
generate_password_hash("kavya123"),
"Kavya More",
"kavya@gmail.com",
"Cyber Security",
"Employee")



]

for employee in employees:
    cur.execute("SELECT * FROM users WHERE username=?", (employee[0],))
    if cur.fetchone() is None:
        cur.execute("""
        INSERT INTO users
        (username,password,fullname,email,department,role)
        VALUES(?,?,?,?,?,?)
        """, employee)

conn.commit()
conn.close()

print("Employees Added Successfully")