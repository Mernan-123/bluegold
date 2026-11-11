BlueGold SecureAccess
=====================

Windows setup
-------------
Extract all five files to a new folder. Double-click START_HERE.bat.
It installs Flask and prompts for a new admin password (12+ characters).
The setup prompt shows the password as you type. Enter it once.
Interactive setup takes precedence over ADMIN_PASSWORD. On later launches, you may enter the
same password or choose a new one. Open http://127.0.0.1:5000 and sign in as
admin. Keep the terminal open while using the app. Stop it with Ctrl+C.

Manual setup
------------
Install the requirements with: python -m pip install -r requirements.txt
Set ADMIN_PASSWORD in your process environment, then run: python app.py
You can also run python app.py --setup to use the visible password prompt.
After initial setup, python app.py reuses the existing admin hash when
ADMIN_PASSWORD is unset. Setting ADMIN_PASSWORD at startup rotates the
password. Werkzeug stores only a salted password hash.

Monitoring
----------
Security overview shows live counts, recent events, source IPs, the hourly
trend, and a map that updates with the feed. All attempts has search,
outcome filters, paginated history, and expandable network details.
Five failed sign-ins from an IP within 15 minutes trigger a 15-minute
lockout. A successful sign-in before lockout resets the failure count.

The audit log records the time, source IP, outcome, and the verified account
name on successful sign-in. Passwords, failed username submissions and raw
browser headers are excluded. Simulation activity is available from the
admin sidebar. Starting it replaces the admin session with a demo session.
Sign out of the simulation and sign back in to return to administration.
The simulation uses a fixed demo identifier and logs event labels without
storing form values, searches, arbitrary URLs, or action targets.

The launcher enables approximate public-IP location and ISP lookups through
ipwho.is. For manual startup set IP_GEOLOCATION=1 to enable these lookups. This sends public source IPs to that service.
Local IPs have no coordinates. The map requires access to Leaflet and
OpenStreetMap. The rest of the monitoring page works if Leaflet is offline.
The default server listens on localhost and is intended for local lab use.

Clean database
--------------
The bundled auth.db was created from the schema. It contains zero accounts,
sign-in attempts, or simulation events. The uploaded database contained 1 account(s), 20 attempts,
and 0 simulation events. No old hashes or record data were
copied. The original upload and any other existing copies remain separate.
When switching to this release, use the bundled database in a new folder.
If AUTH_DB is set, unset it or point it at the new database before launch.

MAC addresses are unavailable in HTTP requests. Loopback and private IPs
have no public location or ISP. Location and ISP are saved when returned
by the provider. This update does not backfill previous attempts.

New attempts record a browser and OS label when detectable. The raw browser
header is excluded. These labels are client-reported and may be inaccurate.
