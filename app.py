from flask import Flask, render_template, redirect, url_for, request, send_file

from database.database import (
    get_connection,
    reset_evaluation_data,
)

from detection.device_detection import detect_devices

from datetime import datetime

from reports.forensic_report import generate_forensic_report


app = Flask(__name__)


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def get_devices():
    """
    Get all known devices from the devices table.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            ip_address,
            mac_address,
            hostname,
            status,
            first_seen,
            last_seen
        FROM devices
        ORDER BY last_seen DESC
    """)

    devices = cursor.fetchall()

    connection.close()

    return devices


def get_security_events():
    """
    Get all recorded security events including
    investigation and resolution information.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            event_type,
            ip_address,
            mac_address,
            timestamp,
            severity,
            description,
            status,
            classification,
            investigation_notes,
            resolution_notes,
            investigated_at,
            resolved_at
        FROM security_events
        ORDER BY timestamp DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events


def get_security_event(event_id):
    """
    Get one specific security event.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            event_type,
            ip_address,
            mac_address,
            timestamp,
            severity,
            description,
            status,
            classification,
            investigation_notes,
            resolution_notes,
            investigated_at,
            resolved_at
        FROM security_events
        WHERE id = ?
    """, (event_id,))

    event = cursor.fetchone()

    connection.close()

    return event


def get_device_by_mac(mac_address):
    """
    Find a device using its MAC address.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            ip_address,
            mac_address,
            hostname,
            status,
            first_seen,
            last_seen
        FROM devices
        WHERE UPPER(TRIM(mac_address))
              = UPPER(TRIM(?))
    """, (mac_address,))

    device = cursor.fetchone()

    connection.close()

    return device


def get_device_observations(mac_address):
    """
    Get the observation history of a specific device.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            ip_address,
            mac_address,
            hostname,
            observed_at
        FROM device_observations
        WHERE UPPER(TRIM(mac_address))
              = UPPER(TRIM(?))
        ORDER BY observed_at DESC
    """, (mac_address,))

    observations = cursor.fetchall()

    connection.close()

    return observations


def get_observations():
    """
    Get all forensic device observations.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            o.id,
            o.ip_address,
            o.mac_address,
            o.hostname,
            o.observed_at,
            COALESCE(d.status, 'Unknown')
        FROM device_observations o
        LEFT JOIN devices d
            ON UPPER(TRIM(o.mac_address))
             = UPPER(TRIM(d.mac_address))
        ORDER BY o.observed_at DESC
    """)

    observations = cursor.fetchall()

    connection.close()

    return observations


def get_last_observation_time():
    """
    Get the timestamp of the most recent network observation.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT MAX(observed_at)
        FROM device_observations
    """)

    result = cursor.fetchone()

    connection.close()

    if result and result[0]:
        return result[0]

    return None


def get_current_devices():
    """
    Get devices detected during the most recent network scan.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT MAX(observed_at)
        FROM device_observations
    """)

    result = cursor.fetchone()

    latest_scan = result[0] if result else None

    if not latest_scan:
        connection.close()
        return []

    cursor.execute("""
        SELECT
            o.ip_address,
            o.mac_address,
            o.hostname,
            d.status,
            o.observed_at
        FROM device_observations o
        LEFT JOIN devices d
            ON UPPER(TRIM(o.mac_address))
             = UPPER(TRIM(d.mac_address))
        WHERE o.observed_at = ?
        ORDER BY o.ip_address
    """, (latest_scan,))

    current_devices = cursor.fetchall()

    connection.close()

    return current_devices

# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_statistics():
    connection = get_connection()
    cursor = connection.cursor()

    # Total known devices
    cursor.execute("""
        SELECT COUNT(*)
        FROM devices
    """)
    total_known_devices = cursor.fetchone()[0]

    # Authorized devices
    cursor.execute("""
        SELECT COUNT(*)
        FROM authorized_devices
        WHERE status = 'Authorized'
    """)
    total_authorized_devices = cursor.fetchone()[0]

    # Potentially unauthorized devices
    cursor.execute("""
        SELECT COUNT(*)
        FROM devices
        WHERE status = 'Potentially Unauthorized'
    """)
    total_potentially_unauthorized = cursor.fetchone()[0]

    # Total security events
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
    """)
    total_security_events = cursor.fetchone()[0]

    # Event status statistics
    cursor.execute("""
        SELECT status, COUNT(*)
        FROM security_events
        GROUP BY status
    """)
    status_rows = cursor.fetchall()

    status_statistics = {
        "Open": 0,
        "Under Investigation": 0,
        "Resolved": 0
    }

    for status, count in status_rows:
        if status in status_statistics:
            status_statistics[status] = count

    # Event classification statistics
    cursor.execute("""
        SELECT classification, COUNT(*)
        FROM security_events
        GROUP BY classification
    """)
    classification_rows = cursor.fetchall()

    classification_statistics = {
        "Unclassified": 0,
        "Confirmed Unauthorized": 0,
        "False Positive": 0,
        "Controlled Test": 0
    }

    for classification, count in classification_rows:
        if classification in classification_statistics:
            classification_statistics[classification] = count

    # Event severity statistics
    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM security_events
        GROUP BY severity
    """)
    severity_rows = cursor.fetchall()

    severity_statistics = {
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }

    for severity, count in severity_rows:
        if severity in severity_statistics:
            severity_statistics[severity] = count

    connection.close()

    return {
        "total_known_devices": total_known_devices,
        "total_authorized_devices": total_authorized_devices,
        "total_potentially_unauthorized": total_potentially_unauthorized,
        "total_security_events": total_security_events,

        "open_events": status_statistics["Open"],
        "investigating_events": status_statistics["Under Investigation"],
        "resolved_events": status_statistics["Resolved"],

        "classification_statistics": classification_statistics,
        "severity_statistics": severity_statistics
    }
# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    devices = get_devices()

    current_devices = get_current_devices()

    events = get_security_events()

    # --------------------------------------------------------
    # Dashboard statistics
    # --------------------------------------------------------

    statistics = get_dashboard_statistics()

    # --------------------------------------------------------
    # Current device statistics
    # --------------------------------------------------------

    total_known_devices = len(devices)

    current_detected = len(current_devices)

    current_authorized = sum(
        1
        for device in current_devices
        if device[3] == "Authorized"
    )

    current_unauthorized = sum(
        1
        for device in current_devices
        if device[3] == "Potentially Unauthorized"
    )

    # --------------------------------------------------------
    # Last scan
    # --------------------------------------------------------

    last_scan = get_last_observation_time()

    scan_count = request.args.get("scan_count")

    # --------------------------------------------------------
    # Render dashboard
    # --------------------------------------------------------

    return render_template(
        "dashboard.html",

        devices=devices,

        current_devices=current_devices,

        events=events,

        statistics=statistics,

        # Existing dashboard values
        total_known_devices=total_known_devices,

        current_detected=current_detected,

        current_authorized=current_authorized,

        current_unauthorized=current_unauthorized,

        total_events=len(events),

        last_scan=last_scan,

        scan_count=scan_count,

        # New event statistics
        total_security_events=statistics[
            "total_security_events"
        ],

        open_events=statistics[
            "open_events"
        ],

        investigating_events=statistics[
            "investigating_events"
        ],

        resolved_events=statistics[
            "resolved_events"
        ],

        classification_statistics=statistics[
            "classification_statistics"
        ],
        severity_statistics=statistics["severity_statistics"]
    )

# ============================================================
# NETWORK SCANNING
# ============================================================

@app.route("/scan")
def scan_network():

    print()
    print("=" * 60)
    print("STARTING NETWORK SCAN")
    print("=" * 60)

    try:

        detected_devices = detect_devices()

        device_count = len(detected_devices)

        print()

        print(
            f"SCAN COMPLETED: "
            f"{device_count} device(s) detected."
        )

    except Exception as error:

        print()

        print("NETWORK SCAN ERROR")

        print(error)

        device_count = 0

    print("=" * 60)
    print()

    return redirect(
        url_for(
            "dashboard",
            scan_count=device_count
        )
    )


# ============================================================
# FORENSIC TIMELINE
# ============================================================

@app.route("/timeline")
def forensic_timeline():

    observations = get_observations()

    return render_template(
        "timeline.html",

        observations=observations,

        total_observations=len(observations)
    )

# ============================================================
# FORENSIC REPORT GENERATION
# ============================================================

@app.route("/event/<int:event_id>/report")
def generate_event_report(event_id):

    event = get_security_event(event_id)

    if event is None:
        return "Security event not found.", 404

    mac_address = event[3]

    device = get_device_by_mac(mac_address)

    observations = get_device_observations(mac_address)

    report_path = generate_forensic_report(
        event,
        device,
        observations
    )

    return send_file(
        report_path,
        as_attachment=True,
        download_name=report_path.name,
        mimetype="application/pdf"
    )

# ============================================================
# SECURITY EVENT INVESTIGATION
# ============================================================

@app.route("/event/<int:event_id>")
def event_investigation(event_id):

    event = get_security_event(event_id)

    if event is None:

        return "Security event not found.", 404

    mac_address = event[3]

    device = get_device_by_mac(mac_address)

    observations = get_device_observations(mac_address)

    return render_template(
        "event_investigation.html",

        event=event,

        device=device,

        observations=observations,

        observation_count=len(observations)
    )


# ============================================================
# SECURITY EVENT MANAGEMENT
# ============================================================

@app.route("/event/<int:event_id>/update", methods=["POST"])
def update_security_event(event_id):

    # --------------------------------------------------------
    # Allowed values
    # --------------------------------------------------------

    allowed_statuses = {
        "Open",
        "Under Investigation",
        "Resolved"
    }

    allowed_classifications = {
        "Unclassified",
        "Confirmed Unauthorized",
        "False Positive",
        "Controlled Test"
    }

    # --------------------------------------------------------
    # Get submitted values
    # --------------------------------------------------------

    status = request.form.get(
        "status",
        "Open"
    ).strip()

    classification = request.form.get(
        "classification",
        "Unclassified"
    ).strip()

    investigation_notes = request.form.get(
        "investigation_notes",
        ""
    ).strip()

    resolution_notes = request.form.get(
        "resolution_notes",
        ""
    ).strip()

    # --------------------------------------------------------
    # Validate status
    # --------------------------------------------------------

    if status not in allowed_statuses:
        return "Invalid event status.", 400

    # --------------------------------------------------------
    # Validate classification
    # --------------------------------------------------------

    if classification not in allowed_classifications:
        return "Invalid event classification.", 400

    # --------------------------------------------------------
    # Open database
    # --------------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

    # --------------------------------------------------------
    # Confirm event exists
    # --------------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            investigated_at,
            resolved_at
        FROM security_events
        WHERE id = ?
    """, (event_id,))

    existing_event = cursor.fetchone()

    if existing_event is None:

        connection.close()

        return "Security event not found.", 404

    current_investigated_at = existing_event[1]
    current_resolved_at = existing_event[2]

    # --------------------------------------------------------
    # Current timestamp
    # --------------------------------------------------------

    current_time = datetime.now().isoformat(
        timespec="seconds"
    )

    investigated_at = current_investigated_at
    resolved_at = current_resolved_at

    # --------------------------------------------------------
    # Under Investigation
    # --------------------------------------------------------

    if status == "Under Investigation":

        if not investigated_at:
            investigated_at = current_time

        resolved_at = None

    # --------------------------------------------------------
    # Resolved
    # --------------------------------------------------------

    elif status == "Resolved":

        if not investigated_at:
            investigated_at = current_time

        if not resolved_at:
            resolved_at = current_time

    # --------------------------------------------------------
    # Open
    # --------------------------------------------------------

    elif status == "Open":

        resolved_at = None

    # --------------------------------------------------------
    # Update security event
    # --------------------------------------------------------

    cursor.execute("""
        UPDATE security_events
        SET
            status = ?,
            classification = ?,
            investigation_notes = ?,
            resolution_notes = ?,
            investigated_at = ?,
            resolved_at = ?
        WHERE id = ?
    """, (
        status,
        classification,
        investigation_notes,
        resolution_notes,
        investigated_at,
        resolved_at,
        event_id
    ))

    connection.commit()
    connection.close()

    # --------------------------------------------------------
    # Return to event page with success message
    # --------------------------------------------------------

    return redirect(
        url_for(
            "event_investigation",
            event_id=event_id,
            updated="success"
        )
    )

# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 60)

    print("WI-FI SECURITY MONITORING SYSTEM")

    print("=" * 60)

    print()

    print("Dashboard:")
    print("http://127.0.0.1:5000")

    print()

    print("Network Scan:")
    print("http://127.0.0.1:5000/scan")

    print()

    print("Forensic Timeline:")
    print("http://127.0.0.1:5000/timeline")

    print()

    print("Security Event Investigation:")
    print("http://127.0.0.1:5000/event/<event_id>")

    print()

    print("Security Event Update:")
    print("POST /event/<event_id>/update")

    print()

    print("REGISTERED FLASK ROUTES:")

    for rule in app.url_map.iter_rules():

        print(
            f"{rule.methods} "
            f"{rule}"
        )

    print("=" * 60)

    print()

    app.run(debug=True)