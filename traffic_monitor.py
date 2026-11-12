import time
from collections import defaultdict


# Store traffic information for each second
traffic_data = defaultdict(lambda: {
    "packets": 0,
    "bytes": 0
})


def update_traffic_monitor(packet):

    if not packet.haslayer("IP"):
        return

    # Get current second
    current_second = int(time.time())

    # Count packet and bytes
    traffic_data[current_second]["packets"] += 1
    traffic_data[current_second]["bytes"] += len(packet)


def display_traffic_monitor():

    print("\n========== TRAFFIC OVER TIME ==========")

    for timestamp in sorted(traffic_data):

        data = traffic_data[timestamp]

        print(
            f"Time: {time.strftime('%H:%M:%S', time.localtime(timestamp))}"
        )

        print("Packets/sec:", data["packets"])
        print("Bytes/sec:", data["bytes"])
        print("---------------------------------------")

    print("=======================================")
