import io
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request, render_template, send_file, abort

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import (
        BACKEND_HOST,
        BACKEND_PORT,
        HEARTBEAT_TIMEOUT,
        NETWORK_INTERFACE,
        MONITORED_IP,
        CAPTURE_FILTER,
        HEARTBEAT_INTERVAL,
        PORT_THRESHOLD,
        SCAN_WINDOW,
        SYN_THRESHOLD,
        SYN_WINDOW,
        ICMP_THRESHOLD,
        ICMP_WINDOW,
        CONNECTION_THRESHOLD,
        CONNECTION_WINDOW,
        DNS_THRESHOLD,
        DNS_WINDOW,
        REPEATED_DNS_THRESHOLD
    )
except ImportError:
    BACKEND_HOST             = os.getenv("NETSENTRY_BACKEND_HOST", "0.0.0.0")
    BACKEND_PORT             = int(os.getenv("NETSENTRY_BACKEND_PORT", 5000))
    HEARTBEAT_TIMEOUT        = int(os.getenv("NETSENTRY_HEARTBEAT_TIMEOUT", 15))
    HEARTBEAT_INTERVAL       = int(os.getenv("NETSENTRY_HEARTBEAT_INTERVAL", 5))
    NETWORK_INTERFACE        = os.getenv("NETSENTRY_INTERFACE", "enp0s8")
    MONITORED_IP             = os.getenv("NETSENTRY_MONITORED_IP", "")
    CAPTURE_FILTER           = os.getenv("NETSENTRY_CAPTURE_FILTER", "tcp or icmp or udp port 53")
    PORT_THRESHOLD           = int(os.getenv("NETSENTRY_PORT_THRESHOLD", 10))
    SCAN_WINDOW              = int(os.getenv("NETSENTRY_SCAN_WINDOW", 10))
    SYN_THRESHOLD            = int(os.getenv("NETSENTRY_SYN_THRESHOLD", 50))
    SYN_WINDOW               = int(os.getenv("NETSENTRY_SYN_WINDOW", 5))
    ICMP_THRESHOLD           = int(os.getenv("NETSENTRY_ICMP_THRESHOLD", 50))
    ICMP_WINDOW              = int(os.getenv("NETSENTRY_ICMP_WINDOW", 5))
    CONNECTION_THRESHOLD     = int(os.getenv("NETSENTRY_CONNECTION_THRESHOLD", 20))
    CONNECTION_WINDOW        = int(os.getenv("NETSENTRY_CONNECTION_WINDOW", 10))
    DNS_THRESHOLD            = int(os.getenv("NETSENTRY_DNS_THRESHOLD", 30))
    DNS_WINDOW               = int(os.getenv("NETSENTRY_DNS_WINDOW", 10))
    REPEATED_DNS_THRESHOLD   = int(os.getenv("NETSENTRY_REPEATED_DNS_THRESHOLD", 15))

from database import get_db_connection

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netsentry.backend")

# In-memory sensor heartbeat state
sensor_state = {
    "status": "OFFLINE",
    "interface": NETWORK_INTERFACE,
    "last_heartbeat": None,
    "last_seen_epoch": 0.0
}

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def _valid_ip(ip):
    if not ip or not _IP_RE.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(p) <= 255 for p in parts)

def _safe_str(s, max_len=512):
    if s is None:
        return None
    return str(s)[:max_len]

def _format_ts(v):
    """Format a datetime or timestamp string to ISO 8601 UTC string (YYYY-MM-DDTHH:MM:SSZ)."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, str):
        s = v.strip()
        if not s or s.lower() in ("none", "null", "—"):
            return None
        if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', s):
            return s.replace(" ", "T") + "Z"
        if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$', s):
            return s + "Z"
        return s
    return str(v)

def _serialize_row(row):
    """Convert datetime objects in a dict to ISO strings with UTC designation."""
    out = {}
    for k, v in row.items():
        if isinstance(v, datetime):
            out[k] = _format_ts(v)
        else:
            out[k] = v
    return out


# ===========================================================================
# PAGE ROUTES (serve HTML templates)
# ===========================================================================

@app.route("/")
def dashboard():
    return render_template("index.html", active_page="dashboard")

@app.route("/traffic")
def live_traffic():
    return render_template("traffic.html", active_page="traffic")

@app.route("/devices")
def devices():
    return render_template("devices.html", active_page="devices")

@app.route("/connections")
def connections():
    return render_template("connections.html", active_page="connections")

@app.route("/investigation")
def investigation():
    query = request.args.get("q", "").strip()
    return render_template("investigation.html", active_page="investigation", query=query)

@app.route("/alerts")
def alerts():
    return render_template("alerts.html", active_page="alerts")

@app.route("/rules")
def rules():
    return render_template("rules.html", active_page="rules")

@app.route("/incidents")
def incidents():
    return render_template("incidents.html", active_page="incidents")

@app.route("/analytics")
def analytics():
    return render_template("analytics.html", active_page="analytics")

@app.route("/reports")
def reports():
    return render_template("reports.html", active_page="reports")

@app.route("/settings")
def settings():
    return render_template("settings.html", active_page="settings")


# ===========================================================================
# EXISTING API ROUTES (preserved exactly)
# ===========================================================================

@app.route("/api/status")
def status():
    now = time.time()
    last_epoch = sensor_state["last_seen_epoch"]
    is_sensor_online = (
        sensor_state["status"] == "ONLINE"
        and last_epoch > 0
        and (now - last_epoch <= HEARTBEAT_TIMEOUT)
    )
    return jsonify({
        "backend":        "ONLINE",
        "sensor":         "ONLINE" if is_sensor_online else "OFFLINE",
        "interface":      sensor_state.get("interface") or "None",
        "last_heartbeat": sensor_state.get("last_heartbeat") or "None"
    })


@app.route("/api/sensor/heartbeat", methods=["POST"])
def sensor_heartbeat():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    status_val = data.get("status", "ONLINE").upper()
    iface_val  = data.get("interface", NETWORK_INTERFACE)
    raw_ts     = data.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ts_val     = _format_ts(raw_ts) or raw_ts

    sensor_state["status"]          = status_val
    sensor_state["interface"]       = iface_val
    sensor_state["last_heartbeat"]  = ts_val
    sensor_state["last_seen_epoch"] = time.time()

    return jsonify({
        "message":   "Heartbeat received",
        "sensor":    "ONLINE" if status_val == "ONLINE" else "OFFLINE",
        "interface": iface_val,
        "timestamp": ts_val
    }), 200


@app.route("/api/devices", methods=["GET", "POST"])
def manage_devices():
    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        if request.method == "POST":
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON data"}), 400

            ip_address = data.get("ip_address")
            if not ip_address:
                return jsonify({"error": "IP address is required"}), 400

            sql = """
                INSERT INTO devices (
                    ip_address, mac_address, first_seen, last_seen, packet_count, total_bytes
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    mac_address   = COALESCE(VALUES(mac_address), mac_address),
                    first_seen    = COALESCE(LEAST(first_seen, VALUES(first_seen)), first_seen, VALUES(first_seen)),
                    last_seen     = COALESCE(GREATEST(last_seen, VALUES(last_seen)), VALUES(last_seen), last_seen),
                    packet_count  = COALESCE(GREATEST(packet_count, VALUES(packet_count)), VALUES(packet_count), packet_count, 0),
                    total_bytes   = COALESCE(GREATEST(total_bytes, VALUES(total_bytes)), VALUES(total_bytes), total_bytes, 0)
            """
            cursor.execute(sql, (
                ip_address,
                data.get("mac_address"),
                data.get("first_seen"),
                data.get("last_seen"),
                data.get("packet_count", 0),
                data.get("total_bytes", 0)
            ))
            db.commit()
            return jsonify({"message": "Device saved successfully", "ip_address": ip_address}), 201

        cursor.execute("SELECT * FROM devices ORDER BY id DESC")
        rows = [_serialize_row(r) for r in cursor.fetchall()]
        return jsonify({"total_devices": len(rows), "devices": rows}), 200

    except Exception as error:
        db.rollback()
        logger.error(f"Error in manage_devices: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/alerts", methods=["GET", "POST"])
def manage_alerts():
    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        if request.method == "POST":
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON data"}), 400

            alert_type = data.get("alert_type")
            if not alert_type:
                return jsonify({"error": "Alert type is required"}), 400

            alert_ts = data.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                INSERT INTO security_alerts (
                    alert_type, source_ip, destination_ip, severity, description, timestamp
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                _safe_str(alert_type, 100),
                _safe_str(data.get("source_ip"), 45),
                _safe_str(data.get("destination_ip"), 45),
                _safe_str(data.get("severity"), 30),
                _safe_str(data.get("description")),
                alert_ts
            ))
            db.commit()
            return jsonify({"message": "Security alert saved successfully", "alert": data}), 201

        cursor.execute("""
            SELECT sa.*, COALESCE(ist.status, 'NEW') AS status
            FROM security_alerts sa
            LEFT JOIN incident_status ist ON sa.id = ist.alert_id
            ORDER BY sa.id DESC
        """)
        rows = [_serialize_row(r) for r in cursor.fetchall()]
        return jsonify({"total_alerts": len(rows), "alerts": rows}), 200

    except Exception as error:
        db.rollback()
        logger.error(f"Error in manage_alerts: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/traffic", methods=["GET", "POST"])
def manage_traffic():
    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        if request.method == "POST":
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON data"}), 400

            for field in ["total_packets", "total_bytes", "protocol_statistics"]:
                if field not in data:
                    return jsonify({"error": f"{field} is required"}), 400

            proto_stats = data["protocol_statistics"]
            if isinstance(proto_stats, (dict, list)):
                proto_json_str = json.dumps(proto_stats)
            elif isinstance(proto_stats, str):
                proto_json_str = proto_stats
            else:
                proto_json_str = "{}"

            cursor.execute("""
                INSERT INTO traffic_statistics (total_packets, total_bytes, protocol_statistics, timestamp)
                VALUES (%s, %s, %s, UTC_TIMESTAMP())
            """, (data["total_packets"], data["total_bytes"], proto_json_str))
            db.commit()
            return jsonify({"message": "Traffic statistics saved successfully"}), 201

        cursor.execute("SELECT * FROM traffic_statistics ORDER BY id DESC LIMIT 100")
        rows = []
        for row in cursor.fetchall():
            row = _serialize_row(row)
            proto_val = row.get("protocol_statistics")
            if isinstance(proto_val, str):
                try:
                    row["protocol_statistics"] = json.loads(proto_val)
                except (json.JSONDecodeError, TypeError):
                    row["protocol_statistics"] = {}
            elif proto_val is None:
                row["protocol_statistics"] = {}
            rows.append(row)

        return jsonify({"total_records": len(rows), "traffic_statistics": rows}), 200

    except Exception as error:
        db.rollback()
        logger.error(f"Error in manage_traffic: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/connections", methods=["GET", "POST"])
def manage_connections():
    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        if request.method == "POST":
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON data"}), 400

            for field in ["source_ip", "destination_ip", "source_port", "destination_port", "protocol"]:
                if field not in data:
                    return jsonify({"error": f"{field} is required"}), 400

            cursor.execute("""
                INSERT INTO network_connections (
                    source_ip, destination_ip, source_port, destination_port,
                    protocol, first_seen, last_seen, packet_count, total_bytes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    first_seen   = COALESCE(LEAST(first_seen, VALUES(first_seen)), first_seen, VALUES(first_seen)),
                    last_seen    = COALESCE(GREATEST(last_seen, VALUES(last_seen)), VALUES(last_seen), last_seen),
                    packet_count = COALESCE(GREATEST(packet_count, VALUES(packet_count)), VALUES(packet_count), packet_count, 0),
                    total_bytes  = COALESCE(GREATEST(total_bytes, VALUES(total_bytes)), VALUES(total_bytes), total_bytes, 0)
            """, (
                data["source_ip"], data["destination_ip"],
                data["source_port"], data["destination_port"], data["protocol"],
                data.get("first_seen"), data.get("last_seen"),
                data.get("packet_count", 0), data.get("total_bytes", 0)
            ))
            db.commit()
            return jsonify({"message": "Network connection saved successfully"}), 201

        cursor.execute("SELECT * FROM network_connections ORDER BY id DESC LIMIT 500")
        rows = [_serialize_row(r) for r in cursor.fetchall()]
        return jsonify({"total_connections": len(rows), "connections": rows}), 200

    except Exception as error:
        db.rollback()
        logger.error(f"Error in manage_connections: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


# ===========================================================================
# NEW API ROUTES
# ===========================================================================

@app.route("/api/investigation/ip/<path:ip_address>")
def investigate_ip(ip_address):
    """Return all recorded observations for a given IP address."""
    ip_address = ip_address.strip()
    if not _valid_ip(ip_address):
        return jsonify({"error": "Invalid IP address"}), 400

    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        # Device record
        cursor.execute("SELECT * FROM devices WHERE ip_address = %s", (ip_address,))
        device = cursor.fetchone()
        if device:
            device = _serialize_row(device)

        # Aggregate traffic stats for this IP from connections
        cursor.execute("""
            SELECT
                MIN(first_seen) AS first_seen,
                MAX(last_seen)  AS last_seen,
                SUM(packet_count) AS packet_count,
                SUM(total_bytes)  AS total_bytes
            FROM network_connections
            WHERE source_ip = %s OR destination_ip = %s
        """, (ip_address, ip_address))
        agg = cursor.fetchone() or {}

        # Fall back to device table values if no connections
        if not agg.get("first_seen") and device:
            agg["first_seen"]   = device.get("first_seen")
            agg["last_seen"]    = device.get("last_seen")
            agg["packet_count"] = device.get("packet_count")
            agg["total_bytes"]  = device.get("total_bytes")

        # Related connections
        cursor.execute("""
            SELECT * FROM network_connections
            WHERE source_ip = %s OR destination_ip = %s
            ORDER BY last_seen DESC LIMIT 50
        """, (ip_address, ip_address))
        conns = [_serialize_row(r) for r in cursor.fetchall()]

        # Related alerts
        cursor.execute("""
            SELECT * FROM security_alerts
            WHERE source_ip = %s OR destination_ip = %s
            ORDER BY timestamp DESC LIMIT 20
        """, (ip_address, ip_address))
        alert_rows = [_serialize_row(r) for r in cursor.fetchall()]

        result = {
            "ip_address":   ip_address,
            "device":       device,
            "first_seen":   _format_ts(agg.get("first_seen")),
            "last_seen":    _format_ts(agg.get("last_seen")),
            "packet_count": agg.get("packet_count"),
            "total_bytes":  agg.get("total_bytes"),
            "connections":  conns,
            "alerts":       alert_rows
        }

        if not result["first_seen"] and not device:
            return jsonify({"error": f"No observations found for {ip_address}"}), 404

        return jsonify(result), 200

    except Exception as error:
        logger.error(f"Error in investigate_ip: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/investigation/domain/<path:domain>")
def investigate_domain(domain):
    """
    Return DNS-related observations for a given domain.
    Domain data is derived from alert descriptions that mention the domain,
    since DNS query content is captured in alert descriptions for REPEATED_DNS alerts.
    """
    domain = domain.strip().lower().rstrip(".")
    # Basic domain validation
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,250}[a-zA-Z0-9])?$', domain):
        return jsonify({"error": "Invalid domain name"}), 400

    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        # 1. Search dns_records table
        cursor.execute("""
            SELECT * FROM dns_records
            WHERE LOWER(domain) = %s
            ORDER BY last_seen DESC
        """, (domain,))
        dns_rows = [_serialize_row(r) for r in cursor.fetchall()]

        # 2. Search alert descriptions for mentions of this domain
        cursor.execute("""
            SELECT * FROM security_alerts
            WHERE (alert_type = 'REPEATED_DNS' OR alert_type = 'DNS_FLOOD')
              AND LOWER(description) LIKE %s
            ORDER BY timestamp DESC LIMIT 50
        """, (f"%{domain}%",))
        domain_alerts = [_serialize_row(r) for r in cursor.fetchall()]

        # Also search all alerts mentioning the domain
        cursor.execute("""
            SELECT * FROM security_alerts
            WHERE LOWER(description) LIKE %s
            ORDER BY timestamp DESC LIMIT 20
        """, (f"%{domain}%",))
        all_alerts = [_serialize_row(r) for r in cursor.fetchall()]

        if not dns_rows and not domain_alerts and not all_alerts:
            return jsonify({"error": f"No DNS observations found for domain '{domain}'"}), 404

        # Extract querying and resolved IPs
        querying_ips = set()
        resolved_ips = set()
        timestamps = []
        total_queries = 0

        for dr in dns_rows:
            if dr.get("querying_ip"): querying_ips.add(dr["querying_ip"])
            if dr.get("resolved_ip"): resolved_ips.add(dr["resolved_ip"])
            total_queries += dr.get("query_count", 1)
            if dr.get("first_seen"): timestamps.append(dr["first_seen"])
            if dr.get("last_seen"):  timestamps.append(dr["last_seen"])

        for a in domain_alerts:
            if a.get("source_ip"): querying_ips.add(a["source_ip"])
            if a.get("timestamp"): timestamps.append(a["timestamp"])
            total_queries += 1

        querying_ips_list = list(querying_ips)

        # Related connections (from querying IPs to port 53 / DNS destinations)
        conns = []
        if querying_ips_list:
            placeholders = ",".join(["%s"] * len(querying_ips_list))
            cursor.execute(f"""
                SELECT * FROM network_connections
                WHERE source_ip IN ({placeholders})
                  AND (destination_port = 53 OR protocol = 'UDP')
                ORDER BY last_seen DESC LIMIT 20
            """, tuple(querying_ips_list))
            conns = [_serialize_row(r) for r in cursor.fetchall()]

        result = {
            "domain":       domain,
            "query_count":  total_queries,
            "first_seen":   _format_ts(min(timestamps)) if timestamps else None,
            "last_seen":    _format_ts(max(timestamps)) if timestamps else None,
            "querying_ips": querying_ips_list,
            "resolved_ips": list(resolved_ips),
            "connections":  conns,
            "alerts":       all_alerts[:10]
        }

        return jsonify(result), 200

    except Exception as error:
        logger.error(f"Error in investigate_domain: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/incidents/<int:alert_id>/status", methods=["POST"])
def update_incident_status(alert_id):
    """Update or set incident investigation status for a given alert."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    status_val = (data.get("status") or "NEW").upper()
    allowed_statuses = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
    if status_val not in allowed_statuses:
        return jsonify({"error": f"Invalid status. Must be one of: {', '.join(allowed_statuses)}"}), 400

    notes_val = _safe_str(data.get("notes"), 1000)

    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO incident_status (alert_id, status, notes)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
                status = VALUES(status),
                notes  = COALESCE(VALUES(notes), notes)
        """, (alert_id, status_val, notes_val))
        db.commit()
        return jsonify({
            "message": "Incident status updated successfully",
            "alert_id": alert_id,
            "status": status_val
        }), 200

    except Exception as error:
        db.rollback()
        logger.error(f"Error in update_incident_status: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/dns", methods=["POST"])
def record_dns():
    """Optional endpoint to record DNS observations."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    querying_ip = _safe_str(data.get("querying_ip"), 45)
    resolved_ip = _safe_str(data.get("resolved_ip"), 45)

    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor()
    try:
        cursor.execute("""
            INSERT INTO dns_records (domain, querying_ip, resolved_ip, first_seen, last_seen, query_count)
            VALUES (%s, %s, %s, UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1)
            ON DUPLICATE KEY UPDATE
                resolved_ip = COALESCE(VALUES(resolved_ip), resolved_ip),
                last_seen   = UTC_TIMESTAMP(),
                query_count = query_count + 1
        """, (domain, querying_ip, resolved_ip))
        db.commit()
        return jsonify({"message": "DNS record saved successfully"}), 201

    except Exception as error:
        db.rollback()
        logger.error(f"Error in record_dns: {error}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        cursor.close()
        db.close()


@app.route("/api/rules")
def get_rules():
    """Return current IDS detection rules (read-only, from config)."""
    rules = [
        {
            "id":          "PORT_SCAN",
            "name":        "TCP Port Scan Detection",
            "description": "Detects when a source IP scans multiple destination ports within a short time window.",
            "threshold":   PORT_THRESHOLD,
            "window":      SCAN_WINDOW,
            "enabled":     True,
            "config_key":  "NETSENTRY_PORT_THRESHOLD / NETSENTRY_SCAN_WINDOW"
        },
        {
            "id":          "SYN_FLOOD",
            "name":        "SYN Flood Detection",
            "description": "Detects excessive TCP SYN packets (without ACK) from a source IP, indicating a potential DoS attack.",
            "threshold":   SYN_THRESHOLD,
            "window":      SYN_WINDOW,
            "enabled":     True,
            "config_key":  "NETSENTRY_SYN_THRESHOLD / NETSENTRY_SYN_WINDOW"
        },
        {
            "id":          "ICMP_FLOOD",
            "name":        "ICMP Flood Detection",
            "description": "Detects excessive ICMP echo requests (ping flood) from a source IP.",
            "threshold":   ICMP_THRESHOLD,
            "window":      ICMP_WINDOW,
            "enabled":     True,
            "config_key":  "NETSENTRY_ICMP_THRESHOLD / NETSENTRY_ICMP_WINDOW"
        },
        {
            "id":          "REPEATED_CONNECTIONS",
            "name":        "Repeated Connection Detection",
            "description": "Detects repeated connection attempts from a source IP to the same destination IP and port.",
            "threshold":   CONNECTION_THRESHOLD,
            "window":      CONNECTION_WINDOW,
            "enabled":     True,
            "config_key":  "NETSENTRY_CONNECTION_THRESHOLD / NETSENTRY_CONNECTION_WINDOW"
        },
        {
            "id":          "DNS_FLOOD",
            "name":        "DNS Anomaly Detection (Flood)",
            "description": "Detects excessive DNS queries from a single source IP within a short time window.",
            "threshold":   DNS_THRESHOLD,
            "window":      DNS_WINDOW,
            "enabled":     True,
            "config_key":  "NETSENTRY_DNS_THRESHOLD / NETSENTRY_DNS_WINDOW"
        },
        {
            "id":          "REPEATED_DNS",
            "name":        "Repeated DNS Query Detection",
            "description": "Detects repeated queries for the same domain name from a source IP, which may indicate beaconing.",
            "threshold":   REPEATED_DNS_THRESHOLD,
            "window":      DNS_WINDOW,
            "enabled":     True,
            "config_key":  "NETSENTRY_REPEATED_DNS_THRESHOLD / NETSENTRY_DNS_WINDOW"
        }
    ]

    config_values = {
        "interface":          NETWORK_INTERFACE,
        "monitored_ip":       MONITORED_IP or "Not set",
        "capture_filter":     CAPTURE_FILTER,
        "heartbeat_interval": HEARTBEAT_INTERVAL,
        "heartbeat_timeout":  HEARTBEAT_TIMEOUT
    }

    return jsonify({"rules": rules, "config": config_values}), 200


@app.route("/api/reports/generate")
def generate_report():
    """Generate a PDF report from actual database records."""
    title    = request.args.get("title",   "NetSentry Security Report")[:100]
    date_from = request.args.get("from",   "")
    date_to   = request.args.get("to",     "")
    inc_devices     = request.args.get("devices",     "1") == "1"
    inc_traffic     = request.args.get("traffic",     "1") == "1"
    inc_connections = request.args.get("connections", "1") == "1"
    inc_alerts      = request.args.get("alerts",      "1") == "1"

    db = get_db_connection()
    if db is None:
        return jsonify({"error": "Database connection failed"}), 500

    cursor = db.cursor(dictionary=True)
    try:
        # Build date filter SQL fragment
        def ts_filter(col, table_alias=""):
            clauses = []
            prefix = table_alias + "." if table_alias else ""
            if date_from:
                clauses.append(f"{prefix}{col} >= %s")
            if date_to:
                clauses.append(f"{prefix}{col} <= %s")
            return clauses

        def ts_params():
            p = []
            if date_from: p.append(date_from + " 00:00:00")
            if date_to:   p.append(date_to   + " 23:59:59")
            return p

        # Devices
        devices_rows = []
        if inc_devices:
            where_parts = ts_filter("last_seen")
            sql = "SELECT * FROM devices"
            if where_parts: sql += " WHERE " + " AND ".join(where_parts)
            sql += " ORDER BY packet_count DESC LIMIT 200"
            cursor.execute(sql, ts_params())
            devices_rows = [_serialize_row(r) for r in cursor.fetchall()]

        # Traffic summary
        traffic_rows = []
        if inc_traffic:
            where_parts = ts_filter("timestamp")
            sql = "SELECT * FROM traffic_statistics"
            if where_parts: sql += " WHERE " + " AND ".join(where_parts)
            sql += " ORDER BY id DESC LIMIT 100"
            cursor.execute(sql, ts_params())
            for row in cursor.fetchall():
                row = _serialize_row(row)
                proto = row.get("protocol_statistics")
                if isinstance(proto, str):
                    try: row["protocol_statistics"] = json.loads(proto)
                    except: row["protocol_statistics"] = {}
                elif proto is None:
                    row["protocol_statistics"] = {}
                traffic_rows.append(row)

        # Connections
        conn_rows = []
        if inc_connections:
            where_parts = ts_filter("last_seen")
            sql = "SELECT * FROM network_connections"
            if where_parts: sql += " WHERE " + " AND ".join(where_parts)
            sql += " ORDER BY packet_count DESC LIMIT 200"
            cursor.execute(sql, ts_params())
            conn_rows = [_serialize_row(r) for r in cursor.fetchall()]

        # Alerts
        alert_rows = []
        if inc_alerts:
            where_parts = ts_filter("timestamp")
            sql = "SELECT * FROM security_alerts"
            if where_parts: sql += " WHERE " + " AND ".join(where_parts)
            sql += " ORDER BY timestamp DESC LIMIT 500"
            cursor.execute(sql, ts_params())
            alert_rows = [_serialize_row(r) for r in cursor.fetchall()]

        # Also get sensor status
        now = time.time()
        last_ep = sensor_state["last_seen_epoch"]
        sensor_online = (sensor_state["status"] == "ONLINE" and last_ep > 0 and (now - last_ep <= HEARTBEAT_TIMEOUT))

        # Build PDF
        pdf_bytes = _build_pdf(
            title=title,
            date_from=date_from,
            date_to=date_to,
            devices=devices_rows,
            traffic=traffic_rows,
            connections=conn_rows,
            alerts=alert_rows,
            sensor_online=sensor_online,
            iface=sensor_state.get("interface") or NETWORK_INTERFACE,
            last_heartbeat=sensor_state.get("last_heartbeat") or "—"
        )

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"netsentry_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

    except Exception as error:
        logger.error(f"Error generating report: {error}")
        return jsonify({"error": f"Report generation failed: {str(error)}"}), 500
    finally:
        cursor.close()
        db.close()


def _build_pdf(title, date_from, date_to, devices, traffic, connections, alerts, sensor_online, iface, last_heartbeat):
    """Build PDF using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    # Custom styles
    title_style    = ParagraphStyle('NSTitle',   parent=styles['Title'],   fontSize=22, spaceAfter=6, textColor=colors.HexColor('#2f81f7'))
    h1_style       = ParagraphStyle('NSH1',      parent=styles['Heading1'],fontSize=14, spaceBefore=16, spaceAfter=6, textColor=colors.HexColor('#e6edf3'))
    h2_style       = ParagraphStyle('NSH2',      parent=styles['Heading2'],fontSize=11, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor('#8b949e'))
    normal_style   = ParagraphStyle('NSNormal',  parent=styles['Normal'],  fontSize=9,  textColor=colors.HexColor('#c9d1d9'))
    muted_style    = ParagraphStyle('NSMuted',   parent=styles['Normal'],  fontSize=8,  textColor=colors.HexColor('#8b949e'))
    warning_style  = ParagraphStyle('NSWarn',    parent=styles['Normal'],  fontSize=9,  textColor=colors.HexColor('#d29922'))

    story = []

    # -- COVER --
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(title, title_style))
    story.append(Paragraph("NetSentry Network Monitoring &amp; Intrusion Detection System", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#30363d'), spaceAfter=10))

    gen_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC+0")
    period = f"{date_from or 'All time'} → {date_to or 'Now'}"

    info_data = [
        ["Report Generated:", gen_date],
        ["Monitoring Period:", period],
        ["Monitored Interface:", iface],
        ["Sensor Status:",    "ONLINE" if sensor_online else "OFFLINE"],
        ["Last Heartbeat:",   str(last_heartbeat).replace("T", " ")[:19] if last_heartbeat else "—"],
    ]
    info_table = Table(info_data, colWidths=[5*cm, 12*cm])
    info_table.setStyle(TableStyle([
        ('FONTSIZE',  (0,0),(-1,-1), 9),
        ('TEXTCOLOR', (0,0),(0,-1), colors.HexColor('#8b949e')),
        ('TEXTCOLOR', (1,0),(1,-1), colors.HexColor('#e6edf3')),
        ('BOTTOMPADDING', (0,0),(-1,-1), 4),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.5*cm))

    # Summary stats
    total_devices    = len(devices)
    total_conns      = len(connections)
    total_alerts     = len(alerts)
    critical_alerts  = len([a for a in alerts if (a.get("severity") or "").upper() in ("CRITICAL","HIGH")])
    total_packets    = max((t.get("total_packets",0) for t in traffic), default=0)
    total_bytes_val  = max((t.get("total_bytes",0)   for t in traffic), default=0)

    story.append(Paragraph("Summary", h1_style))
    summary_data = [
        ["Metric", "Value"],
        ["Total Devices",          str(total_devices)],
        ["Network Connections",    str(total_conns)],
        ["Total Security Alerts",  str(total_alerts)],
        ["Critical / High Alerts", str(critical_alerts)],
        ["Max Packets (snapshot)", str(total_packets)],
        ["Max Traffic (snapshot)", f"{total_bytes_val/1024:.1f} KB"],
    ]
    story.append(_make_table(summary_data))
    story.append(Spacer(1, 0.5*cm))

    # -- DEVICE INVENTORY --
    if devices:
        story.append(PageBreak())
        story.append(Paragraph("Device Inventory", h1_style))
        story.append(Paragraph(f"{len(devices)} device(s) recorded.", normal_style))
        story.append(Spacer(1, 0.3*cm))
        dev_data = [["IP Address", "MAC Address", "First Seen", "Last Seen", "Packets", "Bytes"]]
        for d in devices[:100]:
            dev_data.append([
                d.get("ip_address","—"),
                d.get("mac_address","—"),
                str(d.get("first_seen","—")).replace("T", " ")[:19],
                str(d.get("last_seen","—")).replace("T", " ")[:19],
                str(d.get("packet_count","—")),
                f"{(d.get('total_bytes') or 0)//1024} KB"
            ])
        story.append(_make_table(dev_data, header=True))

    # -- TRAFFIC SUMMARY --
    if traffic:
        story.append(PageBreak())
        story.append(Paragraph("Network Traffic Summary", h1_style))
        # Protocol aggregate
        agg = {}
        for t in traffic:
            ps = t.get("protocol_statistics") or {}
            for proto, val in ps.items():
                if isinstance(val, dict):
                    cnt = val.get("packets", 0)
                elif isinstance(val, (int, float)):
                    cnt = int(val)
                else:
                    cnt = 0
                agg[proto] = agg.get(proto, 0) + cnt
        if agg:
            story.append(Paragraph("Protocol Distribution", h2_style))
            proto_data = [["Protocol","Total Packets"]] + [[k, str(v)] for k,v in sorted(agg.items(), key=lambda x:-x[1])]
            story.append(_make_table(proto_data, header=True))

    # -- CONNECTIONS --
    if connections:
        story.append(PageBreak())
        story.append(Paragraph("Connection Summary", h1_style))
        story.append(Paragraph(f"{len(connections)} unique network flow(s) recorded.", normal_style))
        story.append(Spacer(1, 0.3*cm))
        conn_data = [["Source IP", "Destination IP", "Protocol", "Dst Port", "Packets", "Last Seen"]]
        for c in connections[:100]:
            conn_data.append([
                c.get("source_ip","—"),
                c.get("destination_ip","—"),
                c.get("protocol","—"),
                str(c.get("destination_port","—")),
                str(c.get("packet_count","—")),
                str(c.get("last_seen","—")).replace("T", " ")[:19],
            ])
        story.append(_make_table(conn_data, header=True))

    # -- ALERTS --
    if alerts:
        story.append(PageBreak())
        story.append(Paragraph("Security Alert Summary", h1_style))
        story.append(Paragraph(f"{len(alerts)} alert(s) recorded. {critical_alerts} are Critical or High severity.", normal_style))
        story.append(Spacer(1, 0.3*cm))
        alert_data = [["ID","Type","Source IP","Severity","Timestamp"]]
        for a in alerts[:200]:
            alert_data.append([
                str(a.get("id","—")),
                a.get("alert_type","—"),
                a.get("source_ip","—"),
                a.get("severity","—"),
                str(a.get("timestamp","—")).replace("T", " ")[:19],
            ])
        story.append(_make_table(alert_data, header=True))

    # -- LIMITATIONS --
    story.append(PageBreak())
    story.append(Paragraph("Observations and Limitations", h1_style))
    limitations = [
        "• This report contains only data recorded by the NetSentry sensor during the specified monitoring period.",
        "• Security alerts indicate suspicious activity detected by the IDS rules – they do not confirm successful attacks.",
        "• Domain attribution is based on observed DNS queries only. HTTPS content is never inspected.",
        "• Device online/offline status in this report is based on the last-seen timestamp, not live probing.",
        "• Traffic statistics reflect cumulative snapshot records, not individual packet details.",
        "• IP addresses are based on observed network traffic and may include NAT-translated or spoofed addresses.",
        "• NetSentry is a final-year academic project. For production security monitoring, use certified SOC tools.",
    ]
    for lim in limitations:
        story.append(Paragraph(lim, normal_style))
        story.append(Spacer(1, 0.2*cm))

    # Page numbers via canvas callback
    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor('#8b949e'))
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(A4[0] - 2*cm, 1.2*cm, f"Page {doc.page}")
        canvas.drawString(2*cm, 1.2*cm, "NetSentry — Confidential — Not for external distribution")
        canvas.restoreState()

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return buffer.getvalue()


def _make_table(data, header=False):
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors

    col_count = len(data[0]) if data else 1
    t = Table(data, repeatRows=1 if header else 0)
    style = [
        ('FONTSIZE',    (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0, 1 if header else 0), (-1,-1),
         [colors.HexColor('#1c2130'), colors.HexColor('#161b22')]),
        ('TEXTCOLOR',   (0,0), (-1,-1), colors.HexColor('#c9d1d9')),
        ('GRID',        (0,0), (-1,-1), 0.3, colors.HexColor('#30363d')),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
    ]
    if header:
        style += [
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0d1117')),
            ('TEXTCOLOR',  (0,0), (-1,0), colors.HexColor('#8b949e')),
            ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ]
    t.setStyle(TableStyle(style))
    return t


# ===========================================================================
# MAIN
# ===========================================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=BACKEND_PORT, debug=False)
