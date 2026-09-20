from monitor.device_discovery import discover_devices
from database.database import (
    save_device,
    update_device_status
)
from detection.authorized_devices import is_authorized
from security.event_logger import (
    log_security_event,
    security_event_exists
)


def detect_devices():
    """
    Discover network devices and determine their authorization status.

    Each device is classified as either Authorized or
    Potentially Unauthorized.

    The current status is saved in the devices table.
    Unauthorized devices generate a security event.
    """

    devices = discover_devices()

    results = []

    for device in devices:

        ip_address = device["ip"]
        mac_address = device["mac"]

        # Check whether the device is authorized
        if is_authorized(mac_address):

            status = "Authorized"

        else:

            status = "Potentially Unauthorized"

            # Prevent duplicate security events
            if not security_event_exists(
                mac_address,
                "Unauthorized Device"
            ):

                log_security_event(
                    event_type="Unauthorized Device",
                    ip_address=ip_address,
                    mac_address=mac_address,
                    severity="Medium",
                    description=(
                        "A network device was detected but its "
                        "MAC address is not registered as authorized."
                    )
                )

            else:

                print(
                    f"Existing security event found for "
                    f"{mac_address}. No duplicate event created."
                )

        # Update the current status in the devices table
        save_device(
            ip_address,
            mac_address
        )

        update_device_status(
            mac_address,
            status
        )

        results.append({
            "ip": ip_address,
            "mac": mac_address,
            "status": status
        })

    return results


def test_unauthorized_device():
    """
    Controlled test of the unauthorized-device detection
    and security-event logging mechanism.

    This uses a fictional MAC address and does not
    interact with a real network device.

    The test also verifies duplicate-event prevention.
    """

    test_ip = "192.168.10.99"
    test_mac = "02-00-00-00-00-99"

    print("\nControlled Unauthorized Device Test")
    print("-" * 60)

    if is_authorized(test_mac):

        print(
            "TEST FAILED: Device is incorrectly authorized."
        )

    else:

        print(f"Test IP: {test_ip}")
        print(f"Test MAC: {test_mac}")
        print("Status: Potentially Unauthorized")

        # Check whether an event already exists
        if not security_event_exists(
            test_mac,
            "Unauthorized Device"
        ):

            log_security_event(
                event_type="Unauthorized Device",
                ip_address=test_ip,
                mac_address=test_mac,
                severity="Medium",
                description=(
                    "Controlled test event: a device was detected "
                    "whose MAC address is not registered as authorized."
                )
            )

            print("Test security event recorded successfully.")

        else:

            print(
                "Existing security event found for "
                f"{test_mac}. No duplicate event created."
            )


if __name__ == "__main__":

    print("\nWi-Fi Security Device Detection")
    print("=" * 60)

    detected_devices = detect_devices()

    if not detected_devices:

        print("No network devices detected.")

    else:

        for number, device in enumerate(
            detected_devices,
            start=1
        ):

            print(
                f"{number}. "
                f"IP: {device['ip']} | "
                f"MAC: {device['mac']} | "
                f"Status: {device['status']}"
            )

    print("=" * 60)

    print(
        f"Total devices detected: "
        f"{len(detected_devices)}"
    )