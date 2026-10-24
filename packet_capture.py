from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    conf
)

from database import (
    create_database,
    save_packet
)


def process_packet(packet):

    # ==========================================
    # Ignore non-IP packets
    # ==========================================

    if IP not in packet:
        return


    # ==========================================
    # Basic Packet Information
    # ==========================================

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    source_port = "-"
    destination_port = "-"
    tcp_flags = "-"


    # ==========================================
    # TCP
    # ==========================================

    if TCP in packet:

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # Store TCP flags
        tcp_flags = str(packet[TCP].flags)


    # ==========================================
    # UDP
    # ==========================================

    elif UDP in packet:

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport


    # ==========================================
    # ICMP
    # ==========================================

    elif ICMP in packet:

        protocol = "ICMP"


    # ==========================================
    # Other
    # ==========================================

    else:

        protocol = "Other"


    # ==========================================
    # Display Packet
    # ==========================================

    print("----------------------------------------")

    print(f"Source IP       : {source_ip}")
    print(f"Destination IP  : {destination_ip}")
    print(f"Protocol        : {protocol}")
    print(f"Source Port     : {source_port}")
    print(f"Destination Port: {destination_port}")
    print(f"TCP Flags       : {tcp_flags}")
    print(f"Packet Size     : {packet_size} bytes")


    # ==========================================
    # Save Packet
    # ==========================================

    save_packet(
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        tcp_flags
    )


def start_capture():

    print("Starting packet capture...")
    print("--------------------------------")

    create_database()


    # ==========================================
    # Wi-Fi Interface
    # ==========================================

    wifi_interface = conf.ifaces.dev_from_index(7)

    print(
        "Using network interface:",
        wifi_interface
    )

    print("--------------------------------")


    # ==========================================
    # Start Packet Capture
    # ==========================================

    sniff(
        iface=wifi_interface,
        prn=process_packet,
        count=0
    )


if __name__ == "__main__":

    start_capture()