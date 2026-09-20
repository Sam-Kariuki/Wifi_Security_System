import sqlite3
from pathlib import Path
from datetime import datetime


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATABASE_FILE = BASE_DIR / "wifi_security.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Create a connection to the SQLite database.
    """
    return sqlite3.connect(DATABASE_FILE)


# ============================================================
# DATABASE CREATION
# ============================================================

def create_database():
    """
    Create the required database tables.

    Existing tables and records are preserved.
    """

    connection = get_connection()
    cursor = connection.cursor()


    # ========================================================
    # DEVICES TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            mac_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            status TEXT NOT NULL DEFAULT 'Unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)


    # ========================================================
    # AUTHORIZED DEVICES TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS authorized_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL UNIQUE,
            device_name TEXT NOT NULL,
            owner_type TEXT,
            status TEXT NOT NULL DEFAULT 'Authorized'
        )
    """)


    # ========================================================
    # SECURITY EVENTS TABLE
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            mac_address TEXT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,

            status TEXT NOT NULL DEFAULT 'Open',

            classification TEXT NOT NULL
                DEFAULT 'Unclassified',

            investigation_notes TEXT,

            resolution_notes TEXT,

            investigated_at TEXT,

            resolved_at TEXT
        )
    """)


    # ========================================================
    # DEVICE OBSERVATION HISTORY
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            mac_address TEXT NOT NULL,
            hostname TEXT,
            observed_at TEXT NOT NULL
        )
    """)


    connection.commit()

    connection.close()


# ============================================================
# SECURITY EVENT DATABASE MIGRATION
# ============================================================

def migrate_security_events():
    """
    Add event-management fields to an existing
    security_events table.

    This function is safe to run against the existing
    project database because it only adds missing columns.
    Existing security events are preserved.
    """

    connection = get_connection()
    cursor = connection.cursor()


    # Get the existing columns
    cursor.execute("""
        PRAGMA table_info(security_events)
    """)

    existing_columns = {
        column[1]
        for column in cursor.fetchall()
    }


    # --------------------------------------------------------
    # Add status
    # --------------------------------------------------------

    if "status" not in existing_columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN status TEXT
            NOT NULL
            DEFAULT 'Open'
        """)

        print(
            "Added security event field: status"
        )


    # --------------------------------------------------------
    # Add classification
    # --------------------------------------------------------

    if "classification" not in existing_columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN classification TEXT
            NOT NULL
            DEFAULT 'Unclassified'
        """)

        print(
            "Added security event field: classification"
        )


    # --------------------------------------------------------
    # Add investigation notes
    # --------------------------------------------------------

    if "investigation_notes" not in existing_columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN investigation_notes TEXT
        """)

        print(
            "Added security event field: investigation_notes"
        )


    # --------------------------------------------------------
    # Add resolution notes
    # --------------------------------------------------------

    if "resolution_notes" not in existing_columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN resolution_notes TEXT
        """)

        print(
            "Added security event field: resolution_notes"
        )


    # --------------------------------------------------------
    # Add investigation timestamp
    # --------------------------------------------------------

    if "investigated_at" not in existing_columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN investigated_at TEXT
        """)

        print(
            "Added security event field: investigated_at"
        )


    # --------------------------------------------------------
    # Add resolution timestamp
    # --------------------------------------------------------

    if "resolved_at" not in existing_columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN resolved_at TEXT
        """)

        print(
            "Added security event field: resolved_at"
        )


    connection.commit()

    connection.close()


# ============================================================
# DEVICE STATUS UPDATE
# ============================================================

def update_device_status(mac_address, status):
    """
    Update the current authorization/security status
    of a discovered device.
    """

    connection = get_connection()
    cursor = connection.cursor()

    mac_address = mac_address.upper().strip()

    cursor.execute("""
        UPDATE devices
        SET status = ?
        WHERE mac_address = ?
    """, (
        status,
        mac_address
    ))

    connection.commit()

    connection.close()


# ============================================================
# SAVE DEVICE
# ============================================================

def save_device(ip_address, mac_address, hostname=None):
    """
    Save a discovered device or update an existing device.

    Every discovery is also recorded in the
    device observation history.
    """

    connection = get_connection()
    cursor = connection.cursor()

    current_time = datetime.now().isoformat(
        timespec="seconds"
    )


    # Normalize MAC address
    mac_address = mac_address.upper().strip()


    # --------------------------------------------------------
    # Check whether device already exists
    # --------------------------------------------------------

    cursor.execute(
        "SELECT id FROM devices WHERE mac_address = ?",
        (mac_address,)
    )

    existing_device = cursor.fetchone()


    if existing_device:

        # Update existing device
        cursor.execute("""
            UPDATE devices
            SET ip_address = ?,
                hostname = ?,
                last_seen = ?
            WHERE mac_address = ?
        """, (
            ip_address,
            hostname,
            current_time,
            mac_address
        ))

        action = "updated"


    else:

        # Insert new device
        cursor.execute("""
            INSERT INTO devices (
                ip_address,
                mac_address,
                hostname,
                status,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ip_address,
            mac_address,
            hostname,
            "Unknown",
            current_time,
            current_time
        ))

        action = "added"


    # --------------------------------------------------------
    # Record device observation
    # --------------------------------------------------------

    cursor.execute("""
        INSERT INTO device_observations (
            ip_address,
            mac_address,
            hostname,
            observed_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        ip_address,
        mac_address,
        hostname,
        current_time
    ))


    connection.commit()

    connection.close()

    return action


# ============================================================
# MAIN DATABASE INITIALIZATION
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("WI-FI SECURITY DATABASE")
    print("=" * 60)
    print()

    # Create missing tables
    create_database()

    print(
        "Database tables verified."
    )

    print()

    # Upgrade existing security_events table
    migrate_security_events()

    print()

    print(
        "Database migration completed successfully."
    )

    print()

    print(
        f"Database location:"
    )

    print(
        DATABASE_FILE
    )

    print()

    print("=" * 60)


def reset_evaluation_data():
    """
    Reset data used for controlled evaluation/testing.

    Authorized devices are intentionally preserved.
    Individual forensic records cannot be deleted through
    the application.
    """
    connection = get_connection()
    cursor = connection.cursor()

    # Remove historical observation records
    cursor.execute("DELETE FROM device_observations")

    # Remove security events and investigation records
    cursor.execute("DELETE FROM security_events")

    # Remove discovered device records
    cursor.execute("DELETE FROM devices")

    # Reset AUTOINCREMENT counters for the cleared tables
    cursor.execute("""
        DELETE FROM sqlite_sequence
        WHERE name IN (
            'device_observations',
            'security_events',
            'devices'
        )
    """)

    connection.commit()
    connection.close()

    return True