import os
from pathlib import Path
from dotenv import load_dotenv

# Base Project Directory
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables if present
root_env = BASE_DIR / ".env"
backend_env = BASE_DIR / "backend" / ".env"

if root_env.exists():
    load_dotenv(root_env)
if backend_env.exists():
    load_dotenv(backend_env)
load_dotenv()

# ==========================================
# BACKEND NETWORK CONFIGURATION
# ==========================================
BACKEND_HOST = os.getenv("NETSENTRY_BACKEND_HOST", "192.168.56.103")
BACKEND_PORT = int(os.getenv("NETSENTRY_BACKEND_PORT", 5000))
BACKEND_URL = os.getenv(
    "NETSENTRY_BACKEND_URL",
    f"http://{BACKEND_HOST}:{BACKEND_PORT}"
)

# ==========================================
# PACKET SENSOR & INTERFACE CONFIGURATION
# ==========================================
NETWORK_INTERFACE = os.getenv("NETSENTRY_INTERFACE", "enp0s8")
MONITORED_IP = os.getenv("NETSENTRY_MONITORED_IP", "192.168.56.103")

DEFAULT_FILTER = (
    f"dst host {MONITORED_IP} and (tcp or icmp or udp port 53)"
    if MONITORED_IP else "tcp or icmp or udp port 53"
)
CAPTURE_FILTER = os.getenv("NETSENTRY_CAPTURE_FILTER", DEFAULT_FILTER)

# ==========================================
# INTRUSION DETECTION THRESHOLDS & WINDOWS
# ==========================================
SCAN_WINDOW = int(os.getenv("NETSENTRY_SCAN_WINDOW", 10))
PORT_THRESHOLD = int(os.getenv("NETSENTRY_PORT_THRESHOLD", 10))

SYN_WINDOW = int(os.getenv("NETSENTRY_SYN_WINDOW", 5))
SYN_THRESHOLD = int(os.getenv("NETSENTRY_SYN_THRESHOLD", 50))

ICMP_WINDOW = int(os.getenv("NETSENTRY_ICMP_WINDOW", 5))
ICMP_THRESHOLD = int(os.getenv("NETSENTRY_ICMP_THRESHOLD", 50))

CONNECTION_WINDOW = int(os.getenv("NETSENTRY_CONNECTION_WINDOW", 10))
CONNECTION_THRESHOLD = int(os.getenv("NETSENTRY_CONNECTION_THRESHOLD", 20))

DNS_WINDOW = int(os.getenv("NETSENTRY_DNS_WINDOW", 10))
DNS_THRESHOLD = int(os.getenv("NETSENTRY_DNS_THRESHOLD", 30))
REPEATED_DNS_THRESHOLD = int(os.getenv("NETSENTRY_REPEATED_DNS_THRESHOLD", 15))

# ==========================================
# SYNCHRONIZATION & HEARTBEAT INTERVALS (SEC)
# ==========================================
TRAFFIC_UPDATE_INTERVAL = int(os.getenv("NETSENTRY_TRAFFIC_UPDATE_INTERVAL", 5))
DEVICE_UPDATE_INTERVAL = int(os.getenv("NETSENTRY_DEVICE_UPDATE_INTERVAL", 10))
CONNECTION_UPDATE_INTERVAL = int(os.getenv("NETSENTRY_CONNECTION_UPDATE_INTERVAL", 10))

HEARTBEAT_INTERVAL = int(os.getenv("NETSENTRY_HEARTBEAT_INTERVAL", 5))
HEARTBEAT_TIMEOUT = int(os.getenv("NETSENTRY_HEARTBEAT_TIMEOUT", 15))

# ==========================================
# HTTP CLIENT TIMEOUT (SEC)
# ==========================================
HTTP_TIMEOUT = int(os.getenv("NETSENTRY_HTTP_TIMEOUT", 5))
