from collections import defaultdict
from backend_client import send_traffic_to_backend

# Overall traffic statistics
total_packets = 0
total_bytes = 0

# Traffic statistics by protocol
protocol_packets = defaultdict(int)
protocol_bytes = defaultdict(int)


def update_traffic_stats(packet):

    global total_packets, total_bytes

    if not packet.haslayer("IP"):
        return

    packet_size = len(packet)

    total_packets += 1
    total_bytes += packet_size

    # Identify packet protocol
    if packet.haslayer("TCP"):
        protocol = "TCP"

    elif packet.haslayer("UDP"):
        protocol = "UDP"

    elif packet.haslayer("ICMP"):
        protocol = "ICMP"

    else:
        protocol = "OTHER"

    # Update protocol statistics
    protocol_packets[protocol] += 1
    protocol_bytes[protocol] += packet_size


def display_traffic_stats():

    print("\n========== TRAFFIC STATISTICS ==========")

    print("Total Packets:", total_packets)
    print("Total Bytes:", total_bytes)

    print("\nProtocol-wise Traffic:")

    for protocol in protocol_packets:

        print(
            f"{protocol}: "
            f"{protocol_packets[protocol]} packets, "
            f"{protocol_bytes[protocol]} bytes"
        )

    print("========================================")

def get_traffic_statistics():

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,

        "protocol_statistics": {
            protocol: {
                "packets": protocol_packets[protocol],
                "bytes": protocol_bytes[protocol]
            }
            for protocol in protocol_packets
        }
    }


def send_current_traffic_stats():

    statistics = get_traffic_statistics()

    send_traffic_to_backend(statistics)
