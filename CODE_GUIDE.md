# Easy Code Guide

## `app.py`

Think of `app.py` as the **controller**. A browser asks for a URL, Flask runs the matching function, the function reads/writes SQLite, and then sends an HTML template back.

### Imports
- `Flask` -> creates the web application.
- `render_template` -> opens an HTML file from `templates`.
- `request` -> reads form data.
- `redirect` -> sends the browser to another page.
- `session` -> remembers the logged-in user.
- `flash` -> shows small messages.
- `Werkzeug` -> safely hashes and checks passwords.
- `database.get_db` -> opens SQLite.
- `monitor` -> records security events and starts monitoring.

### `login_required()`
Checks whether `session["username"]` exists. If it does not, the user is sent back to the login page.

### `system_info()`
Uses `socket` to get the IP address and `platform` to get the computer name.

### `page()`
A small helper. It automatically sends the current `username` and `role` to templates so we do not repeat that code in every route.

### `login()`
1. Gets username/password from the form.
2. Searches the `users` table.
3. Uses `check_password_hash()` to compare the password.
4. Creates a session when correct.
5. Calls `log_login()`.
6. Opens the admin dashboard for Admin or employee dashboard for Employee.
7. If incorrect, it records a failed login and shows an error.

### `employee_dashboard()`
Gets counts and recent records only for the logged-in employee and sends them to `employee_dashboard.html`.

### `forgot_password()`
Checks username and email. If both match, it stores the username temporarily in the session.

### `reset_password()`
Creates a new password hash and updates the user record.

### `dashboard()`
Counts users, logins, alerts and files. It also gets recent activities and sends them to the admin dashboard.

### `reports()`
Reads activity information and creates a simple report table.

### `activity()`
Reads all activity logs and calculates High/Medium/Low counts.

### `alerts()`
Reads the latest alerts and calculates total, High, Medium and Resolved counts.

### `resolve_alert(id)`
Uses the alert ID to change `status` to `Resolved`.

### `delete_alert(id)`
Uses the alert ID to delete an alert.

### `users()`
Reads all users and calculates the number of admins, employees and active users.

### `add_user()`
Reads the form, hashes the password and inserts the new user into SQLite.

### `delete_user(id)`
Deletes one user using its database ID.

### `edit_user(id)`
Kept for compatibility with the existing UI. It currently displays the selected ID instead of editing it.

### `settings()`
Reads checkbox values and scan interval from the settings form and stores them in the `settings` table.

### `employee_activity()`
Shows only activities belonging to the current employee.

### `employee_alerts()`
Shows only alerts belonging to the current employee.

### `employee_profile()`
Reads profile data and updates fullname, email and department when the form is submitted.

### `change_password()`
Checks the old password, checks that the new passwords match, hashes the new password and saves it.

### `usb_history()`
Reads USB logs and calculates inserted, removed and active counts.

### `file_history()`
Reads file logs and calculates created, modified and deleted counts.

### `logout()`
Stores logout time, creates a logout activity, clears the session and returns to login.

### `if __name__ == "__main__"`
This is the starting point. It creates the database, starts monitoring and starts Flask.

---

## `database.py`

### `get_db()`
Opens `threat.db` and uses `sqlite3.Row`, so database columns can be accessed like `user["username"]`.

### `init_db()`
Runs `CREATE TABLE IF NOT EXISTS` for every required table. It also creates:
- default admin username: `admin`
- default admin password: `admin123`
- default monitoring settings

SQLite is useful here because it stores everything in one local `.db` file and does not need a separate database server.

---

## `monitor.py`

This file is the **security engine**.

### `set_current_user(username)`
Stores the employee currently being monitored.

### `_db()`
Small helper for opening SQLite.

### `_now()`
Returns the current date and time in the format used by the database.

### `log_activity()`
Inserts a normal activity into `activity_logs`.

### `add_alert()`
Inserts a security alert into `alerts`.

### `update_risk()`
Creates a simple 0-100 score:
- failed logins add risk
- Medium alerts add risk
- High alerts add more risk
- score is limited to 100

Levels:
- 0-39 = Low
- 40-79 = Medium
- 80-100 = High

### `log_login(username, status)`
Stores login information. It also detects:
- three failed attempts -> High alert
- login before 6 AM or after 10 PM -> Medium alert

### `save_file_event()`
Stores file events. If the filename is one of the sensitive filenames, a High alert is created.

Example sensitive files:
`salary.xlsx`, `payroll.xlsx`, `finance.xlsx`, `secret.pdf`.

### `save_usb_event()`
Stores USB insertion/removal and creates a Medium alert.

### `FileHandler`
`watchdog` calls these methods automatically:
- `on_created()` -> new file
- `on_modified()` -> changed file
- `on_deleted()` -> deleted file
- `on_moved()` -> renamed/moved file

### `_usb_loop()`
Uses `psutil.disk_partitions()` every two seconds and compares the current removable drives with the previous list.

### `_file_loop()`
Creates a watchdog observer for `monitored_folder`.

### `start_services()`
Starts USB and file monitoring using background threads.

### `stop_services()`
Stops the watchdog observer when needed.

---

# How the code connects

## Login flow

`login.html`
-> POST request
-> `app.py /`
-> `database.py get_db()`
-> password verification
-> `monitor.py log_login()`
-> SQLite
-> redirect to dashboard

## File monitoring flow

File changes in `monitored_folder`
-> `watchdog`
-> `FileHandler`
-> `save_file_event()`
-> `file_logs`
-> `activity_logs`
-> sensitive-file check
-> `alerts`
-> `risk_scores`

## USB monitoring flow

USB inserted/removed
-> `psutil`
-> `_usb_loop()`
-> `save_usb_event()`
-> `usb_logs`
-> `activity_logs`
-> `alerts`
-> `risk_scores`

## Dashboard flow

Browser requests `/dashboard`
-> `dashboard()`
-> SQL `COUNT` queries
-> recent records
-> `render_template("dashboard.html")`
-> HTML page displays the values.

---

# HTML template explanation

The HTML files are intentionally kept from the original project so the **CSS, colors, layout and theme remain the same**.

- `login.html`: login form and Show Password JavaScript.
- `dashboard.html`: admin cards, recent activity and threat information.
- `employee_dashboard.html`: employee-specific statistics.
- `activity.html`: complete activity table.
- `alerts.html`: alert table and resolve/delete actions.
- `users.html`: user cards, search and user table.
- `add_user.html`: new employee/admin form.
- `reports.html`: report statistics and records.
- `settings.html`: monitoring checkboxes and scan interval.
- `usb_history.html`: USB statistics and event table.
- `file_history.html`: file statistics and event table.
- `employee_activity.html`: employee-only activity table.
- `employee_alerts.html`: employee-only alert table.
- `employee_profile.html`: profile update form.
- `change_password.html`: password change form.
- `forgot_password.html`: identity check before reset.
- `reset_password.html`: new password form.

## Jinja syntax used in the HTML

`{{ value }}` means "display a Python value".

Example:

```html
<h1>{{ username }}</h1>
```

Flask sends `username` to the template, and Jinja prints it.

A loop such as:

```html
{% for row in activities %}
    {{ row.activity }}
{% endfor %}
```

means Flask/Jinja repeats the HTML for every database record.

A condition such as:

```html
{% if user.role == "Admin" %}
```

shows different HTML depending on the user's role.

---

# Easy viva explanation

**Frontend:** HTML, CSS and JavaScript create the cyber-security dashboard.

**Backend:** Flask receives browser requests and runs Python functions.

**Database:** SQLite stores users, login logs, activities, alerts, USB logs, file logs and risk scores.

**Monitoring:** `watchdog` watches files and `psutil` checks removable USB drives.

**Detection:** simple rules identify suspicious behavior.

**Risk:** events increase a 0-100 risk score.

**Output:** alerts and risk scores are displayed on the dashboard.

