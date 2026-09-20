import subprocess
import re
import ipaddress

from database.database import save_device, create_database

def discover_devices():
    """
    Discover potential network devices from the Windows ARP table.

    Broadcast and multicast addresses are excluded because they
    do not represent individual network devices.
    """

    result = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True,
        shell=True
    )

    devices = []

    for line in result.stdout.splitlines():

        match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})",
            line
        )

        if not match:
            continue

        ip_address = match.group(1)
        mac_address = match.group(2).upper()

        try:
            ip = ipaddress.ip_address(ip_address)

            # Ignore multicast and broadcast addresses
            if ip.is_multicast:
                continue

            if ip_address == "255.255.255.255":
                continue

            if mac_address == "FF-FF-FF-FF-FF-FF":
                continue

        except ValueError:
            continue

        device = {
            "ip": ip_address,
            "mac": mac_address
        }

        # Avoid duplicate entries
        if device not in devices:
            devices.append(device)

    return devices


if __name__ == "__main__":


    # Make sure the database exists
    create_database()

    devices = discover_devices()

    print("\nDiscovered Network Devices")
    print("-" * 50)

    if not devices:
        print("No network devices found.")

    else:
        for number, device in enumerate(devices, start=1):

            action = save_device(
                device["ip"],
                device["mac"]
            )

            print(
                f"{number}. "
                f"IP: {device['ip']}   "
                f"MAC: {device['mac']}   "
                f"[{action}]"
            )

    print("-" * 50)
    print(f"Total potential devices: {len(devices)}")