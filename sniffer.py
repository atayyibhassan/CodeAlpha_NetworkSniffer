# Basic Network Sniffer using Scapy
# Captures packets and shows: source IP, destination IP, protocol, ports, payload.

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# How many packets to capture (0 = keep going until Ctrl+C)
PACKET_LIMIT = 20

# Counters for the final summary
packet_count = 0
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}


def get_protocol_name(packet):
    """Return the protocol name of a packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def get_payload_text(packet, max_bytes=50):
    """Return the first few payload bytes as readable text."""
    if not packet.haslayer(Raw):
        return "(no payload)"

    data = bytes(packet[Raw].load)[:max_bytes]

    # Replace unreadable bytes with a dot so the output stays clean
    text = ""
    for byte in data:
        if 32 <= byte <= 126:       # printable ASCII characters
            text += chr(byte)
        else:
            text += "."
    return text


def process_packet(packet):
    """This function runs once for every captured packet."""
    global packet_count

    # We only analyze packets that have an IP layer
    if not packet.haslayer(IP):
        return

    packet_count += 1
    protocol = get_protocol_name(packet)
    protocol_counts[protocol] += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    print("-" * 60)
    print(f"Packet #{packet_count}")
    print(f"Source IP      : {source_ip}")
    print(f"Destination IP : {destination_ip}")
    print(f"Protocol       : {protocol}")

    # Ports and flags exist only in TCP and UDP
    if protocol == "TCP":
        print(f"Source Port    : {packet[TCP].sport}")
        print(f"Dest Port      : {packet[TCP].dport}")
        print(f"TCP Flags      : {packet[TCP].flags}")
    elif protocol == "UDP":
        print(f"Source Port    : {packet[UDP].sport}")
        print(f"Dest Port      : {packet[UDP].dport}")
    elif protocol == "ICMP":
        print(f"ICMP Type      : {packet[ICMP].type}")

    print(f"Packet Size    : {len(packet)} bytes")
    print(f"Payload        : {get_payload_text(packet)}")


def print_summary():
    """Show how many packets of each protocol were captured."""
    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)
    print(f"Total IP packets: {packet_count}")
    for name, count in protocol_counts.items():
        print(f"{name:6}: {count}")


def main():
    print("Starting sniffer... (press Ctrl+C to stop)")
    print("Only capture traffic on networks you own or have permission to monitor.\n")

    try:
        # store=False means packets are not kept in memory (saves RAM)
        sniff(prn=process_packet, count=PACKET_LIMIT, store=False)
    except PermissionError:
        print("ERROR: Run this program as Administrator (Windows) or with sudo (Linux/macOS).")
        return
    except KeyboardInterrupt:
        print("\nStopped by user.")

    print_summary()


main()
