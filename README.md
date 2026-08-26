# Insider Threat Detection System - Simplified Version

This version keeps the **same dark blue cyber-security theme, page names and main functions** from the original project, but the backend is much easier to understand.

## What was simplified?

The original project had several Python monitoring files. This version combines the monitoring work into one easy file:

- `app.py` -> Flask routes, login, pages and user actions.
- `database.py` -> creates the SQLite tables and default admin.
- `monitor.py` -> login logging, risk score, alerts, file monitoring and USB monitoring.
- `templates/` -> the original HTML/CSS pages are kept so the UI/theme stays the same.
- `monitored_folder/` -> put test files here to see file events.
- `requirements.txt` -> libraries needed.

The old `.git`, `venv`, `__pycache__` and duplicate helper files are intentionally removed.

## Default login

Username: `admin`  
Password: `admin123`

## Run the project

1. Open this folder in VS Code.
2. Open a terminal.
3. Create a virtual environment:

```bash
python -m venv venv
```

4. Activate it on Windows:

```powershell
venv\Scripts\activate
```

5. Install libraries:

```bash
pip install -r requirements.txt
```

6. Run:

```bash
python app.py
```

7. Open:

`http://127.0.0.1:5000`

## Important

The database is created automatically when the project starts. If you want a fresh database, delete `threat.db` and run `python app.py` again.

The USB monitor needs `psutil`. The file monitor uses `watchdog`. If a machine does not allow removable-drive detection, the rest of the application still works.

## File-by-file explanation

### 1. app.py

This is the **main Flask file**.

Important functions/routes:

- `login()` checks username/password, creates a session and records the login.
- `employee_dashboard()` shows the logged-in employee's own activities, alerts and risk score.
- `forgot_password()` checks username + email before password reset.
- `reset_password()` stores a new hashed password.
- `dashboard()` collects administrator dashboard counts.
- `reports()` creates report data from activity logs.
- `activity()` displays all activity logs.
- `alerts()` displays threat alerts.
- `resolve_alert()` changes an alert to Resolved.
- `delete_alert()` removes an alert.
- `users()` displays users and counts.
- `add_user()` creates a new user with a hashed password.
- `delete_user()` removes a user.
- `settings()` saves monitoring settings.
- `employee_activity()` shows only the current employee's activities.
- `employee_alerts()` shows only the current employee's alerts.
- `employee_profile()` updates the employee profile.
- `change_password()` verifies the old password and saves the new one.
- `usb_history()` displays USB events.
- `file_history()` displays file events.
- `logout()` closes the session and records logout time.

### 2. database.py

This file creates the SQLite database.

Tables:

- `users` -> account information
- `login_logs` -> successful/failed logins
- `activity_logs` -> normal user activities
- `usb_logs` -> USB insertion/removal
- `file_logs` -> file changes
- `alerts` -> suspicious events
- `risk_scores` -> calculated risk
- `settings` -> monitoring preferences

`get_db()` opens the database.

`init_db()` creates tables and the default admin account.

### 3. monitor.py

This file contains the security monitoring logic.

`set_current_user()` tells the monitor which employee is logged in.

`log_login()` saves successful/failed logins and detects late logins or repeated failed attempts.

`save_file_event()` stores file creation, modification, deletion and rename events. It also checks sensitive filenames.

`save_usb_event()` stores USB insertion/removal events.

`update_risk()` calculates a simple score from failed logins and alert severity.

`start_services()` starts the USB and file monitoring threads.

The monitor uses:
- `watchdog` for file-system changes.
- `psutil` for removable-drive detection.
- `threading` so monitoring can run in the background while Flask serves pages.

### 4. templates/

These are the frontend pages. Their CSS/theme is kept from the original project.

Main pages:

- `login.html` -> login screen
- `dashboard.html` -> admin dashboard
- `employee_dashboard.html` -> employee dashboard
- `activity.html` -> activity logs
- `alerts.html` -> threat alerts
- `users.html` -> user management
- `reports.html` -> reports
- `settings.html` -> monitoring settings
- `usb_history.html` -> USB history
- `file_history.html` -> file history
- `employee_activity.html` -> employee activities
- `employee_alerts.html` -> employee alerts
- `employee_profile.html` -> employee profile
- `change_password.html` -> password change
- `forgot_password.html` -> forgot password
- `reset_password.html` -> reset password
- `add_user.html` -> add user form

### How the system works

Login -> Flask checks the user in SQLite -> password is verified -> session is created -> login is logged -> monitoring runs in background.

When suspicious activity occurs:

`Activity -> Database -> Detection rule -> Alert -> Risk score -> Dashboard`

Examples:

- 3 failed logins -> High alert.
- Login before 6 AM or after 10 PM -> Medium alert.
- Sensitive file such as `salary.xlsx` -> High alert.
- USB inserted/removed -> Medium alert.
- File created/modified/deleted -> activity log + alert.

### Libraries used

- **Flask**: web server and URL routes.
- **SQLite3**: database.
- **Werkzeug**: password hashing.
- **psutil**: detects removable drives.
- **watchdog**: detects file-system changes.
- **threading**: runs monitoring in the background.
- **socket**: gets IP address.
- **platform**: gets computer/device name.
- **datetime**: records date and time.

## Viva one-line explanation

If asked "How does your project work?"

Say:

"Our Flask application provides the web interface, SQLite stores users and security logs, watchdog monitors file changes, psutil checks removable USB devices, and simple detection rules convert suspicious activities into alerts and risk scores."
