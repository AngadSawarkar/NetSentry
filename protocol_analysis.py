from collections import defaultdict


# Stores protocol statistics
protocol_stats = defaultdict(int)


def update_protocol(packet):

    if packet.haslayer("IP"):

        if packet.haslayer("TCP"):
            protocol_stats["TCP"] += 1

        elif packet.haslayer("UDP"):

            protocol_stats["UDP"] += 1

            if packet.haslayer("DNS"):
                if packet["DNS"].qr == 0:
                    protocol_stats["DNS Requests"] += 1

        elif packet.haslayer("ICMP"):
            protocol_stats["ICMP"] += 1

        else:
            protocol_stats["Other IP"] += 1


def display_protocol_stats():

    print("\n========== PROTOCOL STATISTICS ==========")

    for protocol, count in protocol_stats.items():

        print(f"{protocol}: {count} packets")

    print("=========================================")
