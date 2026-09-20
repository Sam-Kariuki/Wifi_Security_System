from database.database import get_connection


def add_authorized_device(mac_address, device_name, owner_type="School"):
    """
    Add a device to the authorized device list.

    If the MAC address already exists, no duplicate record
    is created.
    """

    connection = get_connection()
    cursor = connection.cursor()

    mac_address = mac_address.upper()

    cursor.execute("""
        SELECT id
        FROM authorized_devices
        WHERE mac_address = ?
    """, (mac_address,))

    existing_device = cursor.fetchone()

    if existing_device:
        print(
            f"Device already authorized: "
            f"{device_name} ({mac_address})"
        )
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO authorized_devices (
            mac_address,
            device_name,
            owner_type,
            status
        )
        VALUES (?, ?, ?, ?)
    """, (
        mac_address,
        device_name,
        owner_type,
        "Authorized"
    ))

    connection.commit()
    connection.close()

    print(
        f"Authorized device added: "
        f"{device_name} ({mac_address})"
    )

    return True

def get_authorized_devices():
    """
    Return all authorized devices.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT mac_address, device_name, owner_type, status
        FROM authorized_devices
    """)

    devices = cursor.fetchall()

    connection.close()

    return devices


def is_authorized(mac_address):
    """
    Check whether a MAC address belongs to an authorized device.
    """

    connection = get_connection()
    cursor = connection.cursor()

    mac_address = mac_address.upper().strip()

    cursor.execute("""
        SELECT id
        FROM authorized_devices
        WHERE UPPER(TRIM(mac_address)) = ?
        AND status = 'Authorized'
    """, (mac_address,))

    result = cursor.fetchone()

    connection.close()

    return result is not None


if __name__ == "__main__":

    # Researcher-approved test devices
    add_authorized_device(
        "48-A9-8A-4B-9A-BC",
        "Research Test Device 01",
        "Researcher"
    )

    add_authorized_device(
        "B4-B6-76-27-83-73",
        "Research Test Device 02",
        "Researcher"
    )

    add_authorized_device(
        "F0-6E-0B-C0-D3-E6",
        "Research Test Device 03",
        "Researcher"
    )

    print("\nAuthorized Devices")
    print("-" * 70)

    devices = get_authorized_devices()

    for device in devices:
        print(
            f"MAC: {device[0]} | "
            f"Name: {device[1]} | "
            f"Type: {device[2]} | "
            f"Status: {device[3]}"
        )