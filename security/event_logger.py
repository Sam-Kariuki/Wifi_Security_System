from database.database import get_connection
from datetime import datetime


def log_security_event(
    event_type,
    ip_address,
    mac_address,
    severity,
    description
):
    """
    Record a security event in the database.
    """

    connection = get_connection()
    cursor = connection.cursor()

    timestamp = datetime.now().isoformat(timespec="seconds")

    cursor.execute("""
        INSERT INTO security_events (
            event_type,
            ip_address,
            mac_address,
            timestamp,
            severity,
            description
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        ip_address,
        mac_address,
        timestamp,
        severity,
        description
    ))

    connection.commit()
    connection.close()

    print("Security event recorded successfully.")

def security_event_exists(mac_address, event_type="Unauthorized Device"):
    """
    Check whether an event of the specified type has already
    been recorded for a MAC address.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM security_events
        WHERE mac_address = ?
        AND event_type = ?
        LIMIT 1
    """, (
        mac_address.upper(),
        event_type
    ))

    result = cursor.fetchone()

    connection.close()

    return result is not None

def get_security_events():
    """
    Retrieve recorded security events.
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
            description
        FROM security_events
        ORDER BY timestamp DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events


if __name__ == "__main__":

    print("\nSecurity Events")
    print("=" * 80)

    events = get_security_events()

    if not events:
        print("No security events recorded.")

    else:
        for event in events:
            print(
                f"ID: {event[0]} | "
                f"Type: {event[1]} | "
                f"IP: {event[2]} | "
                f"MAC: {event[3]} | "
                f"Time: {event[4]} | "
                f"Severity: {event[5]}"
            )

            print(f"Description: {event[6]}")
            print("-" * 80)