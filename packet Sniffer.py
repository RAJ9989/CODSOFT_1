from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


def get_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "Other"


def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = get_protocol(packet)
        packet_size = len(packet)

        # Extract limited payload information
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            data = payload[:30].hex()
        else:
            data = "No payload"

        print(
            f"{timestamp:<10} "
            f"{source_ip:<16} "
            f"{destination_ip:<16} "
            f"{protocol:<8} "
            f"{packet_size:<10} "
            f"{data}"
        )


def main():
    print("=" * 100)
    print("              PYTHON NETWORK PACKET SNIFFER")
    print("=" * 100)

    print(
        f"{'TIME':<10}"
        f"{'SOURCE IP':<16}"
        f"{'DESTINATION IP':<16}"
        f"{'PROTOCOL':<8}"
        f"{'SIZE':<10}"
        f"PAYLOAD"
    )

    print("-" * 100)

    try:
        sniff(
            filter="ip",
            prn=packet_callback,
            store=False
        )

    except PermissionError:
        print("\nPermission denied.")
        print("Run the program with administrator/root privileges.")

    except KeyboardInterrupt:
        print("\n\nPacket capture stopped by user.")


if __name__ == "__main__":
    main()