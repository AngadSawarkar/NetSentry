from datetime import datetime, timezone
from collections import defaultdict
import time
from email.utils import parsedate_to_datetime
from config import DEVICE_UPDATE_INTERVAL
from backend_client import (
    send_device_to_backend,
    get_devices_from_backend
)

# Stores information about discovered devices
devices = {}
last_backend_update = {}


def normalize_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    val_str = str(value).strip()
    try:
        clean_val = val_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_val)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        pass

    try:
        parsed_date = parsedate_to_datetime(val_str)
        return parsed_date.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return val_str


def load_saved_devices():
    saved_devices = get_devices_from_backend()

    for saved_device in saved_devices:
        ip_address = saved_device["ip_address"]

        devices[ip_address] = {
            "ip_address": ip_address,
            "mac_address": saved_device.get("mac_address"),
            "first_seen": normalize_datetime(saved_device.get("first_seen")),
            "last_seen": normalize_datetime(saved_device.get("last_seen")),
            "packet_count": int(saved_device.get("packet_count", 0)),
            "total_bytes": int(saved_device.get("total_bytes", 0))
        }

        last_backend_update[ip_address] = time.time()

        print(
            f"[RESTORED DEVICE] {ip_address} | "
            f"Packets: {devices[ip_address]['packet_count']} | "
            f"Bytes: {devices[ip_address]['total_bytes']}"
        )

    print(f"[RESTORE COMPLETE] {len(devices)} devices loaded")


def update_device(ip_address, mac_address=None, packet_size=0):
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Register new device
    if ip_address not in devices:
        devices[ip_address] = {
            "ip_address": ip_address,
            "mac_address": mac_address,
            "first_seen": current_time,
            "last_seen": current_time,
            "packet_count": 0,
            "total_bytes": 0
        }
        print(f"[NEW DEVICE] {ip_address}")

    # Update existing device
    device = devices[ip_address]

    if mac_address:
        device["mac_address"] = mac_address

    if not device.get("first_seen"):
        device["first_seen"] = current_time

    device["last_seen"] = current_time
    device["packet_count"] += 1
    device["total_bytes"] += packet_size

    # Send updated device information periodically
    current_timestamp = time.time()

    if (
        ip_address not in last_backend_update
        or current_timestamp - last_backend_update[ip_address]
        >= DEVICE_UPDATE_INTERVAL
    ):
        send_device_to_backend(device)
        last_backend_update[ip_address] = current_timestamp


def display_devices():
    print("\n========== DEVICE INVENTORY ==========")
    for ip, device in devices.items():
        print(f"\nIP Address: {device['ip_address']}")
        print(f"MAC Address: {device['mac_address']}")
        print(f"First Seen: {device['first_seen']}")
        print(f"Last Seen: {device['last_seen']}")
        print(f"Packets: {device['packet_count']}")
        print(f"Total Bytes: {device['total_bytes']}")
    print("\n======================================")


def flush_devices_to_backend():
    print("\n[SHUTDOWN] Saving final device statistics...")
    for ip_address, device in devices.items():
        print(f"[SHUTDOWN] Synchronizing {ip_address}")
        send_device_to_backend(device)
    print("[SHUTDOWN] Device synchronization completed.")
