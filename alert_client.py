import requests
from datetime import datetime, timezone
from config import BACKEND_URL, HTTP_TIMEOUT


def send_alert_to_backend(
    alert_type,
    source_ip,
    destination_ip,
    severity,
    description
):

    alert_data = {
        "alert_type": alert_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    }

    try:
        response = requests.post(
            f"{BACKEND_URL}/api/alerts",
            json=alert_data,
            timeout=HTTP_TIMEOUT
        )

        if response.status_code == 201:
            print("[BACKEND] Security alert sent:", alert_type)
        else:
            print("[BACKEND ALERT ERROR]", response.status_code, response.text)

    except requests.exceptions.RequestException as error:
        print("[BACKEND CONNECTION ERROR]", error)
