from scapy.all import sniff, IP, TCP, ICMP, UDP, DNS, DNSQR, Ether
from collections import defaultdict, deque
from datetime import datetime
import threading
import time

from config import (
    NETWORK_INTERFACE,
    CAPTURE_FILTER,
    SCAN_WINDOW,
    PORT_THRESHOLD,
    SYN_WINDOW,
    SYN_THRESHOLD,
    ICMP_WINDOW,
    ICMP_THRESHOLD,
    CONNECTION_WINDOW,
    CONNECTION_THRESHOLD,
    DNS_WINDOW,
    DNS_THRESHOLD,
    REPEATED_DNS_THRESHOLD,
    TRAFFIC_UPDATE_INTERVAL,
    HEARTBEAT_INTERVAL
)

from device_inventory import (
    update_device,
    display_devices,
    load_saved_devices,
    flush_devices_to_backend
)
from protocol_analysis import update_protocol, display_protocol_stats
from connection_tracker import (
    update_connection,
    display_connections,
    load_saved_connections,
    flush_connections_to_backend
)
from traffic_stats import (
    update_traffic_stats,
    display_traffic_stats,
    send_current_traffic_stats
)
from traffic_monitor import update_traffic_monitor, display_traffic_monitor
from alert_client import send_alert_to_backend
from backend_client import send_heartbeat_to_backend

# ==========================================
# TRACKING DATA
# ==========================================

scan_tracker = defaultdict(dict)
syn_tracker = defaultdict(deque)
icmp_tracker = defaultdict(deque)
connection_tracker = defaultdict(deque)

dns_tracker = defaultdict(deque)
repeated_dns_tracker = defaultdict(deque)

scan_alerted = set()
syn_alerted = set()
icmp_alerted = set()
connection_alerted = set()

dns_alerted = set()
repeated_dns_alerted = set()

last_traffic_update = time.time()
heartbeat_stop_event = threading.Event()


# ==========================================
# HEARTBEAT WORKER
# ==========================================

def heartbeat_worker():
    while not heartbeat_stop_event.is_set():
        try:
            send_heartbeat_to_backend(status="ONLINE", interface=NETWORK_INTERFACE)
        except Exception:
            pass
        heartbeat_stop_event.wait(HEARTBEAT_INTERVAL)


# ==========================================
# PORT SCAN DETECTION
# ==========================================

def detect_port_scan(packet):

    source_ip = packet[IP].src
    destination_port = packet[TCP].dport
    current_time = time.time()

    for ip in list(scan_tracker.keys()):

        scan_tracker[ip] = {
            port: timestamp
            for port, timestamp in scan_tracker[ip].items()
            if current_time - timestamp <= SCAN_WINDOW
        }

        if not scan_tracker[ip]:
            del scan_tracker[ip]
            scan_alerted.discard(ip)

    scan_tracker[source_ip][destination_port] = current_time

    unique_ports = len(scan_tracker[source_ip])

    if unique_ports >= PORT_THRESHOLD:

        if source_ip not in scan_alerted:

            print("\n" + "=" * 50)
            print("       SECURITY ALERT: PORT SCAN")
            print("=" * 50)
            print("Source IP:", source_ip)
            print("Destination IP:", packet[IP].dst)
            print("Unique Ports:", unique_ports)
            print("Time:", datetime.now())
            print("=" * 50 + "\n")

            send_alert_to_backend(
                alert_type="PORT_SCAN",
                source_ip=source_ip,
                destination_ip=packet[IP].dst,
                severity="HIGH",
                description=f"Port scan detected: {unique_ports} unique ports within {SCAN_WINDOW} seconds"
            )

            scan_alerted.add(source_ip)


# ==========================================
# SYN FLOOD DETECTION
# ==========================================

def detect_syn_flood(packet):

    source_ip = packet[IP].src
    current_time = time.time()

    syn_tracker[source_ip].append(current_time)

    while syn_tracker[source_ip]:

        if current_time - syn_tracker[source_ip][0] > SYN_WINDOW:
            syn_tracker[source_ip].popleft()
        else:
            break

    syn_count = len(syn_tracker[source_ip])

    if syn_count >= SYN_THRESHOLD:

        if source_ip not in syn_alerted:

            print("\n" + "=" * 50)
            print("       SECURITY ALERT: SYN FLOOD")
            print("=" * 50)
            print("Source IP:", source_ip)
            print("Destination IP:", packet[IP].dst)
            print("SYN Packets:", syn_count)
            print("Time Window:", SYN_WINDOW, "seconds")
            print("Time:", datetime.now())
            print("=" * 50 + "\n")

            send_alert_to_backend(
                alert_type="SYN_FLOOD",
                source_ip=source_ip,
                destination_ip=packet[IP].dst,
                severity="CRITICAL",
                description=f"SYN flood detected: {syn_count} SYN packets within {SYN_WINDOW} seconds"
            )
            syn_alerted.add(source_ip)


# ==========================================
# ICMP FLOOD DETECTION
# ==========================================

def detect_icmp_flood(packet):

    source_ip = packet[IP].src
    current_time = time.time()

    icmp_tracker[source_ip].append(current_time)

    while icmp_tracker[source_ip]:

        if current_time - icmp_tracker[source_ip][0] > ICMP_WINDOW:
            icmp_tracker[source_ip].popleft()
        else:
            break

    icmp_count = len(icmp_tracker[source_ip])

    if icmp_count >= ICMP_THRESHOLD:

        if source_ip not in icmp_alerted:

            print("\n" + "=" * 50)
            print("       SECURITY ALERT: ICMP FLOOD")
            print("=" * 50)
            print("Source IP:", source_ip)
            print("Destination IP:", packet[IP].dst)
            print("ICMP Requests:", icmp_count)
            print("Time Window:", ICMP_WINDOW, "seconds")
            print("Time:", datetime.now())
            print("=" * 50 + "\n")

            send_alert_to_backend(
                alert_type="ICMP_FLOOD",
                source_ip=source_ip,
                destination_ip=packet[IP].dst,
                severity="HIGH",
                description=f"ICMP flood detected: {icmp_count} requests within {ICMP_WINDOW} seconds"
            )

            icmp_alerted.add(source_ip)


# ==========================================
# REPEATED CONNECTION DETECTION
# ==========================================

def detect_repeated_connections(packet):

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport

    current_time = time.time()

    connection_key = (
        source_ip,
        destination_ip,
        destination_port
    )

    connection_tracker[connection_key].append(current_time)

    while connection_tracker[connection_key]:

        if current_time - connection_tracker[connection_key][0] > CONNECTION_WINDOW:
            connection_tracker[connection_key].popleft()
        else:
            break

    attempt_count = len(connection_tracker[connection_key])

    if attempt_count >= CONNECTION_THRESHOLD:

        if connection_key not in connection_alerted:

            print("\n" + "=" * 50)
            print("   SECURITY ALERT: REPEATED CONNECTIONS")
            print("=" * 50)
            print("Source IP:", source_ip)
            print("Destination IP:", destination_ip)
            print("Destination Port:", destination_port)
            print("Connection Attempts:", attempt_count)
            print("Time Window:", CONNECTION_WINDOW, "seconds")
            print("Time:", datetime.now())
            print("=" * 50 + "\n")

            send_alert_to_backend(
                alert_type="REPEATED_CONNECTIONS",
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity="MEDIUM",
                description=f"Repeated connection attempts: {attempt_count} attempts to port {destination_port} within {CONNECTION_WINDOW} seconds"
            )

            connection_alerted.add(connection_key)


# ==========================================
# DNS ANOMALY DETECTION
# ==========================================

def detect_dns_anomaly(packet):

    source_ip = packet[IP].src
    current_time = time.time()

    # Extract requested domain
    if DNSQR not in packet:
        return

    domain = packet[DNSQR].qname.decode(
        "utf-8", errors="ignore"
    ).rstrip(".")

    # --------------------------------------
    # Excessive DNS requests
    # --------------------------------------

    dns_tracker[source_ip].append(current_time)

    while dns_tracker[source_ip]:

        if current_time - dns_tracker[source_ip][0] > DNS_WINDOW:
            dns_tracker[source_ip].popleft()
        else:
            break

    dns_count = len(dns_tracker[source_ip])

    if dns_count >= DNS_THRESHOLD:

        if source_ip not in dns_alerted:

            print("\n" + "=" * 50)
            print("       SECURITY ALERT: DNS FLOOD")
            print("=" * 50)
            print("Source IP:", source_ip)
            print("DNS Requests:", dns_count)
            print("Time Window:", DNS_WINDOW, "seconds")
            print("Time:", datetime.now())
            print("=" * 50 + "\n")

            send_alert_to_backend(
                alert_type="DNS_FLOOD",
                source_ip=source_ip,
                destination_ip=packet[IP].dst,
                severity="HIGH",
                description=f"Excessive DNS requests: {dns_count} requests within {DNS_WINDOW} seconds"
            )

            dns_alerted.add(source_ip)

    # --------------------------------------
    # Repeated DNS requests
    # --------------------------------------

    dns_key = (source_ip, domain)

    repeated_dns_tracker[dns_key].append(current_time)

    while repeated_dns_tracker[dns_key]:

        if current_time - repeated_dns_tracker[dns_key][0] > DNS_WINDOW:
            repeated_dns_tracker[dns_key].popleft()
        else:
            break

    repeated_count = len(repeated_dns_tracker[dns_key])

    if repeated_count >= REPEATED_DNS_THRESHOLD:

        if dns_key not in repeated_dns_alerted:

            print("\n" + "=" * 50)
            print("   SECURITY ALERT: REPEATED DNS QUERY")
            print("=" * 50)
            print("Source IP:", source_ip)
            print("Domain:", domain)
            print("Requests:", repeated_count)
            print("Time Window:", DNS_WINDOW, "seconds")
            print("Time:", datetime.now())
            print("=" * 50 + "\n")

            send_alert_to_backend(
                alert_type="REPEATED_DNS",
                source_ip=source_ip,
                destination_ip=packet[IP].dst,
                severity="MEDIUM",
                description=f"Repeated DNS queries for {domain}: {repeated_count} requests within {DNS_WINDOW} seconds"
            )

            repeated_dns_alerted.add(dns_key)


# ==========================================
# PACKET PROCESSING
# ==========================================

def process_packet(packet):

    if IP not in packet:
        return

    # Update network connection information (single call)
    update_connection(packet)

    # Update overall traffic statistics (single call)
    update_traffic_stats(packet)

    # Update protocol statistics (single call)
    update_protocol(packet)

    # Update per-second rate monitor (single call)
    update_traffic_monitor(packet)

    # ======================================
    # DEVICE INVENTORY
    # ======================================

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_mac = None
    destination_mac = None

    if Ether in packet:
        source_mac = packet[Ether].src
        destination_mac = packet[Ether].dst

    update_device(
        source_ip,
        source_mac,
        len(packet)
    )

    update_device(
        destination_ip,
        destination_mac,
        len(packet)
    )

    # ======================================
    # INTRUSION DETECTION CHECKS
    # ======================================

    if TCP in packet:

        flags = int(packet[TCP].flags)

        if (flags & 0x02) and not (flags & 0x10):

            detect_port_scan(packet)
            detect_syn_flood(packet)
            detect_repeated_connections(packet)

    elif ICMP in packet:

        if packet[ICMP].type == 8:
            detect_icmp_flood(packet)

    elif UDP in packet:

        if DNS in packet and packet[DNS].qr == 0:
            detect_dns_anomaly(packet)

    # Send traffic statistics periodically
    global last_traffic_update

    current_time = time.time()

    if current_time - last_traffic_update >= TRAFFIC_UPDATE_INTERVAL:

        send_current_traffic_stats()

        last_traffic_update = current_time


# ==========================================
# START SENSOR
# ==========================================

if __name__ == "__main__":

    # Restore previously saved device information
    print("\n[STARTUP] Restoring saved devices from database...")
    load_saved_devices()

    # Restore previously saved connection information
    print("\n[STARTUP] Restoring saved network connections from database...")
    load_saved_connections()

    # Start Heartbeat background worker thread
    heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
    heartbeat_thread.start()
    print("[STARTUP] Heartbeat monitor thread started.")

    print("\n========================================")
    print("             NetSentry IDS")
    print("========================================")
    print(f"Interface: {NETWORK_INTERFACE}")
    print(f"Filter: {CAPTURE_FILTER}")
    print("Port Scan Detection: ENABLED")
    print("SYN Flood Detection: ENABLED")
    print("ICMP Flood Detection: ENABLED")
    print("Repeated Connection Detection: ENABLED")
    print("DNS Anomaly Detection: ENABLED")
    print("----------------------------------------")
    print(f"Port Scan: {PORT_THRESHOLD} ports / {SCAN_WINDOW} sec")
    print(f"SYN Flood: {SYN_THRESHOLD} packets / {SYN_WINDOW} sec")
    print(f"ICMP Flood: {ICMP_THRESHOLD} requests / {ICMP_WINDOW} sec")
    print(f"Repeated Connections: {CONNECTION_THRESHOLD} attempts / {CONNECTION_WINDOW} sec")
    print(f"DNS Flood: {DNS_THRESHOLD} requests / {DNS_WINDOW} sec")
    print(f"Repeated DNS: {REPEATED_DNS_THRESHOLD} queries / {DNS_WINDOW} sec")
    print("----------------------------------------")
    print("Status: MONITORING")
    print("========================================\n")

    try:

        sniff(
            iface=NETWORK_INTERFACE,
            filter=CAPTURE_FILTER,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:

        print("\nNetSentry monitoring stopped.")

    finally:

        print("\n[SHUTDOWN] Starting graceful shutdown...")

        # Signal heartbeat stop and send OFFLINE status
        heartbeat_stop_event.set()
        try:
            send_heartbeat_to_backend(status="OFFLINE", interface=NETWORK_INTERFACE)
            print("[SHUTDOWN] Sent OFFLINE heartbeat to backend.")
        except Exception:
            pass

        flush_devices_to_backend()
        flush_connections_to_backend()

        display_devices()
        display_protocol_stats()
        display_connections()
        display_traffic_stats()
        display_traffic_monitor()

        print("\n[SHUTDOWN] NetSentry stopped safely.")
