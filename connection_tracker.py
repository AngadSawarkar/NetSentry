from collections import defaultdict
from datetime import datetime, timezone
import time
from email.utils import parsedate_to_datetime
from config import CONNECTION_UPDATE_INTERVAL
from backend_client import (
    send_connection_to_backend,
    get_connections_from_backend
)

# Stores network flow information
# Key: (source_ip, destination_ip, source_port, destination_port, protocol)
connections = {}
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


def load_saved_connections():
    saved_connections = get_connections_from_backend()

    for conn in saved_connections:
        source_ip = conn.get("source_ip")
        destination_ip = conn.get("destination_ip")
        source_port = int(conn.get("source_port", 0))
        destination_port = int(conn.get("destination_port", 0))
        protocol = conn.get("protocol", "OTHER")

        flow_key = (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        )

        connections[flow_key] = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "first_seen": normalize_datetime(conn.get("first_seen")),
            "last_seen": normalize_datetime(conn.get("last_seen")),
            "packet_count": int(conn.get("packet_count", 0)),
            "total_bytes": int(conn.get("total_bytes", 0))
        }

        last_backend_update[flow_key] = time.time()

        print(
            f"[RESTORED CONNECTION] {source_ip}:{source_port} -> "
            f"{destination_ip}:{destination_port} ({protocol}) | "
            f"Packets: {connections[flow_key]['packet_count']} | "
            f"Bytes: {connections[flow_key]['total_bytes']}"
        )

    print(f"[RESTORE COMPLETE] {len(connections)} connections loaded")


def update_connection(packet):
    if not packet.haslayer("IP"):
        return

    ip = packet["IP"]

    source_ip = ip.src
    destination_ip = ip.dst

    source_port = 0
    destination_port = 0
    protocol = "OTHER"

    if packet.haslayer("TCP"):
        protocol = "TCP"
        source_port = packet["TCP"].sport
        destination_port = packet["TCP"].dport

    elif packet.haslayer("UDP"):
        protocol = "UDP"
        source_port = packet["UDP"].sport
        destination_port = packet["UDP"].dport

    elif packet.haslayer("ICMP"):
        protocol = "ICMP"

    # Identify a unique network flow (5-tuple)
    flow_key = (
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    )

    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Register a new flow if not already present
    if flow_key not in connections:
        connections[flow_key] = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "first_seen": current_time,
            "last_seen": current_time,
            "packet_count": 0,
            "total_bytes": 0
        }

    # Update existing flow
    connection = connections[flow_key]
    if not connection.get("first_seen"):
        connection["first_seen"] = current_time
    connection["last_seen"] = current_time
    connection["packet_count"] += 1
    connection["total_bytes"] += len(packet)

    # Send connection information periodically
    current_timestamp = time.time()

    if (
        flow_key not in last_backend_update
        or current_timestamp - last_backend_update[flow_key]
        >= CONNECTION_UPDATE_INTERVAL
    ):
        send_connection_to_backend(connection)
        last_backend_update[flow_key] = current_timestamp


def display_connections():
    print("\n========== NETWORK CONNECTIONS ==========")
    for flow in connections.values():
        print("-----------------------------------------")
        print(
            f"{flow['source_ip']}:{flow['source_port']} "
            f"-> {flow['destination_ip']}:{flow['destination_port']}"
        )
        print("Protocol:", flow["protocol"])
        print("First Seen:", flow["first_seen"])
        print("Last Seen:", flow["last_seen"])
        print("Packets:", flow["packet_count"])
        print("Total Bytes:", flow["total_bytes"])
    print("=========================================")


def flush_connections_to_backend():
    print("\n[SHUTDOWN] Saving final network connection statistics...")
    for flow_key, connection in connections.items():
        print(
            f"[SHUTDOWN] Synchronizing flow {connection['source_ip']}:{connection['source_port']} "
            f"-> {connection['destination_ip']}:{connection['destination_port']}"
        )
        send_connection_to_backend(connection)
    print("[SHUTDOWN] Network connection synchronization completed.")
