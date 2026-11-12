import requests
from datetime import datetime, timezone
from config import BACKEND_URL, HTTP_TIMEOUT, NETWORK_INTERFACE


def send_device_to_backend(device):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/devices",
            json=device,
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 201:
            print("[BACKEND] Device sent successfully:", device["ip_address"])
        else:
            print("[BACKEND ERROR]", response.status_code, response.text)
    except requests.exceptions.RequestException as error:
        print("[BACKEND CONNECTION ERROR]", error)


def send_traffic_to_backend(statistics):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/traffic",
            json=statistics,
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 201:
            print("[BACKEND] Traffic statistics sent successfully")
        else:
            print(
                "[BACKEND TRAFFIC ERROR]",
                response.status_code,
                response.text
            )
    except requests.exceptions.RequestException as error:
        print("[BACKEND CONNECTION ERROR]", error)


def send_connection_to_backend(connection):
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/connections",
            json=connection,
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 201:
            print(
                "[BACKEND] Connection sent successfully:",
                connection["source_ip"],
                "->",
                connection["destination_ip"]
            )
        else:
            print(
                "[BACKEND CONNECTION ERROR]",
                response.status_code,
                response.text
            )
    except requests.exceptions.RequestException as error:
        print("[BACKEND CONNECTION ERROR]", error)


def get_devices_from_backend():
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/devices",
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            devices = data.get("devices", [])
            print(f"[BACKEND] Retrieved {len(devices)} saved devices")
            return devices
        else:
            print(
                "[BACKEND ERROR] Could not retrieve devices:",
                response.status_code
            )
            return []
    except requests.exceptions.RequestException as error:
        print("[BACKEND CONNECTION ERROR]", error)
        return []


def get_connections_from_backend():
    try:
        response = requests.get(
            f"{BACKEND_URL}/api/connections",
            timeout=HTTP_TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            connections = data.get("connections", [])
            print(f"[BACKEND] Retrieved {len(connections)} saved connections")
            return connections
        else:
            print(
                "[BACKEND ERROR] Could not retrieve connections:",
                response.status_code
            )
            return []
    except requests.exceptions.RequestException as error:
        print("[BACKEND CONNECTION ERROR]", error)
        return []


def send_heartbeat_to_backend(status="ONLINE", interface=NETWORK_INTERFACE):
    payload = {
        "status": status,
        "interface": interface,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    }
    try:
        response = requests.post(
            f"{BACKEND_URL}/api/sensor/heartbeat",
            json=payload,
            timeout=HTTP_TIMEOUT
        )
        return response.status_code == 200
    except requests.exceptions.RequestException:
        # Heartbeat failure must not crash packet capture
        return False
