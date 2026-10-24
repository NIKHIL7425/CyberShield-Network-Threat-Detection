from collections import defaultdict
import time
import sqlite3
from datetime import datetime, timezone, timedelta

from database import get_india_time


DATABASE = "database/threats.db"

LOCAL_IP = "192.168.1.14"


# ==========================================
# Threat Cooldown
# ==========================================

threat_cooldown = {}

THREAT_COOLDOWN_SECONDS = 300
DATABASE_THREAT_COOLDOWN_SECONDS = 60


def can_save_threat(source_ip, threat_type):

    current_time = time.time()

    key = (source_ip, threat_type)

    last_detected = threat_cooldown.get(key)

    if last_detected is not None:

        if (
            current_time - last_detected
            < THREAT_COOLDOWN_SECONDS
        ):
            return False

    threat_cooldown[key] = current_time

    return True


# ==========================================
# PORT SCAN DETECTION
# ==========================================

port_activity = defaultdict(set)

port_activity_time = {}


def detect_port_scan(
    source_ip,
    destination_port
):

    current_time = time.time()

    if source_ip not in port_activity_time:

        port_activity_time[source_ip] = current_time

    if (
        current_time -
        port_activity_time[source_ip]
        > 10
    ):

        port_activity[source_ip].clear()

        port_activity_time[source_ip] = current_time

    if destination_port is None:

        return {
            "threat": False
        }

    port_activity[source_ip].add(
        destination_port
    )

    port_count = len(
        port_activity[source_ip]
    )

    if port_count >= 20:

        if port_count < 50:

            severity = "High"

        else:

            severity = "Critical"

        return {
            "threat": True,
            "type": "Port Scan",
            "source_ip": source_ip,
            "ports_detected": port_count,
            "severity": severity
        }

    return {
        "threat": False
    }


# ==========================================
# ICMP FLOOD DETECTION
# ==========================================

icmp_activity = defaultdict(int)

icmp_activity_time = {}


def detect_icmp_flood(source_ip):

    current_time = time.time()

    if source_ip not in icmp_activity_time:

        icmp_activity_time[source_ip] = current_time

    if (
        current_time -
        icmp_activity_time[source_ip]
        > 10
    ):

        icmp_activity[source_ip] = 0

        icmp_activity_time[source_ip] = current_time

    icmp_activity[source_ip] += 1

    packet_count = (
        icmp_activity[source_ip]
    )

    if packet_count >= 20:

        if packet_count >= 80:

            severity = "Critical"

        elif packet_count >= 40:

            severity = "High"

        else:

            severity = "Medium"

        return {
            "threat": True,
            "type": "ICMP Flood",
            "source_ip": source_ip,
            "packets_detected": packet_count,
            "severity": severity
        }

    return {
        "threat": False
    }


# ==========================================
# TCP SYN FLOOD DETECTION
# ==========================================

syn_activity = defaultdict(int)

syn_activity_time = {}


def detect_syn_flood(source_ip):

    current_time = time.time()

    if source_ip not in syn_activity_time:

        syn_activity_time[source_ip] = current_time

    # Reset after 10 seconds

    if (
        current_time -
        syn_activity_time[source_ip]
        > 10
    ):

        syn_activity[source_ip] = 0

        syn_activity_time[source_ip] = current_time

    # Count SYN packet

    syn_activity[source_ip] += 1

    packet_count = (
        syn_activity[source_ip]
    )

    # Detection threshold

    if packet_count >= 30:

        if packet_count >= 100:

            severity = "Critical"

        elif packet_count >= 60:

            severity = "High"

        else:

            severity = "Medium"

        return {
            "threat": True,
            "type": "TCP SYN Flood",
            "source_ip": source_ip,
            "packets_detected": packet_count,
            "severity": severity
        }

    return {
        "threat": False
    }


# ==========================================
# BRUTE FORCE DETECTION
# ==========================================

bruteforce_activity = defaultdict(int)

bruteforce_activity_time = {}


# Common login / remote access service ports

LOGIN_SERVICE_PORTS = {
    "21": "FTP",
    "22": "SSH",
    "23": "Telnet",
    "3389": "RDP"
}


def detect_bruteforce(
    source_ip,
    destination_port
):

    current_time = time.time()

    destination_port = str(
        destination_port
    )


    # ==========================================
    # Check Login Service Port
    # ==========================================

    if (
        destination_port
        not in LOGIN_SERVICE_PORTS
    ):

        return {
            "threat": False
        }


    # ==========================================
    # Track Source IP + Destination Port
    # ==========================================

    activity_key = (
        source_ip,
        destination_port
    )


    if (
        activity_key
        not in bruteforce_activity_time
    ):

        bruteforce_activity_time[
            activity_key
        ] = current_time


    # ==========================================
    # Reset After 30 Seconds
    # ==========================================

    if (
        current_time
        -
        bruteforce_activity_time[
            activity_key
        ]
        > 30
    ):

        bruteforce_activity[
            activity_key
        ] = 0

        bruteforce_activity_time[
            activity_key
        ] = current_time


    # ==========================================
    # Count Connection Attempt
    # ==========================================

    bruteforce_activity[
        activity_key
    ] += 1


    attempt_count = (
        bruteforce_activity[
            activity_key
        ]
    )


    # ==========================================
    # Detection Threshold
    # ==========================================

    if attempt_count >= 10:

        if attempt_count >= 30:

            severity = "Critical"

        elif attempt_count >= 20:

            severity = "High"

        else:

            severity = "Medium"


        return {
            "threat": True,
            "type": "Brute Force Attempt",
            "source_ip": source_ip,
            "destination_port": destination_port,
            "service": LOGIN_SERVICE_PORTS[
                destination_port
            ],
            "attempts_detected": attempt_count,
            "severity": severity
        }


    return {
        "threat": False
    }


# ==========================================
# UDP FLOOD DETECTION
# ==========================================

udp_activity = defaultdict(int)

udp_activity_time = {}


def detect_udp_flood(
    source_ip,
    destination_port
):

    current_time = time.time()

    # Track Source IP + Destination Port
    activity_key = (
        source_ip,
        str(destination_port)
    )

    if activity_key not in udp_activity_time:

        udp_activity_time[
            activity_key
        ] = current_time

    # Reset after 10 seconds

    if (
        current_time -
        udp_activity_time[activity_key]
        > 10
    ):

        udp_activity[activity_key] = 0

        udp_activity_time[
            activity_key
        ] = current_time

    # Count UDP packet

    udp_activity[activity_key] += 1

    packet_count = (
        udp_activity[activity_key]
    )

    # Detection threshold

    if packet_count >= 30:

        if packet_count >= 100:

            severity = "Critical"

        elif packet_count >= 60:

            severity = "High"

        else:

            severity = "Medium"

        return {
            "threat": True,
            "type": "UDP Flood",
            "source_ip": source_ip,
            "destination_port": destination_port,
            "packets_detected": packet_count,
            "severity": severity
        }

    return {
        "threat": False
    }


# ==========================================
# SAVE THREAT
# ==========================================

def save_threat(
    source_ip,
    threat_type,
    severity,
    details
):

    connection = sqlite3.connect(
        DATABASE
    )

    cursor = connection.cursor()


    # ==========================================
    # Calculate 60-second IST cutoff
    # ==========================================

    india_timezone = timezone(
        timedelta(hours=5, minutes=30)
    )

    cutoff_time = (
        datetime.now(india_timezone)
        - timedelta(seconds=60)
    ).strftime("%Y-%m-%d %H:%M:%S")


    # ==========================================
    # Check Recent Duplicate Threat
    # ==========================================

    recent_threat = cursor.execute(
        """
        SELECT id
        FROM threats
        WHERE source_ip = ?
        AND threat_type = ?
        AND timestamp >= ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (
            source_ip,
            threat_type,
            cutoff_time
        )
    ).fetchone()


    if recent_threat is not None:

        connection.close()

        return False


    # ==========================================
    # Save Threat Using India Time
    # ==========================================

    cursor.execute(
        """
        INSERT INTO threats
        (
            source_ip,
            threat_type,
            severity,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            source_ip,
            threat_type,
            severity,
            details,
            get_india_time()
        )
    )


    connection.commit()

    connection.close()

    return True


# ==========================================
# MONITOR PACKETS
# ==========================================

def monitor_packets():

    print(
        "Threat Detector Started..."
    )

    print(
        "Monitoring new network packets..."
    )

    print("--------------------------------")


    # ==========================================
    # Start From Latest Packet
    # ==========================================

    try:

        connection = sqlite3.connect(
            DATABASE
        )

        cursor = connection.cursor()

        cursor.execute(
            "SELECT MAX(id) FROM packets"
        )

        result = cursor.fetchone()

        connection.close()

        last_packet_id = (
            result[0]
            if result[0] is not None
            else 0
        )

        print(
            "Starting from Packet ID:",
            last_packet_id
        )

        print("--------------------------------")


    except Exception as error:

        print(
            "Database Error:",
            error
        )

        last_packet_id = 0


    # ==========================================
    # Continuous Monitoring
    # ==========================================

    while True:

        try:

            connection = sqlite3.connect(
                DATABASE
            )

            connection.row_factory = (
                sqlite3.Row
            )

            cursor = connection.cursor()

            packets = cursor.execute(
                """
                SELECT
                    id,
                    source_ip,
                    destination_ip,
                    protocol,
                    destination_port,
                    tcp_flags
                FROM packets
                WHERE id > ?
                ORDER BY id ASC
                """,
                (
                    last_packet_id,
                )
            ).fetchall()

            connection.close()


            # ======================================
            # Process Packets
            # ======================================

            for packet in packets:

                last_packet_id = packet["id"]

                source_ip = packet["source_ip"]

                destination_ip = packet["destination_ip"]

                protocol = packet["protocol"]

                destination_port = packet["destination_port"]

                tcp_flags = packet["tcp_flags"]


                # ==================================
                # TCP
                # ==================================

                if protocol == "TCP":

                    # --------------------------------
                    # Port Scan
                    # --------------------------------

                    tcp_flag_string = str(
                        tcp_flags
                    )

                    is_syn_packet = (
                        "S" in tcp_flag_string
                        and
                        "A" not in tcp_flag_string
                    )

                    if (
                        is_syn_packet
                        and
                        destination_ip == LOCAL_IP
                    ):

                        result = detect_port_scan(
                            source_ip,
                            destination_port
                        )

                        if result["threat"]:

                            if can_save_threat(
                                source_ip,
                                result["type"]
                            ):

                                details = (
                                    f'{result["ports_detected"]} '
                                    f'unique destination ports '
                                    f'detected within 10 seconds.'
                                )

                                saved = save_threat(
                                    source_ip,
                                    result["type"],
                                    result["severity"],
                                    details
                                )

                                if saved:

                                    print(
                                        "🚨 THREAT DETECTED!"
                                    )

                                    print(
                                        "Threat Type:",
                                        result["type"]
                                    )

                                    print(
                                        "Source IP:",
                                        result["source_ip"]
                                    )

                                    print(
                                        "Ports Detected:",
                                        result["ports_detected"]
                                    )

                                    print(
                                        "Severity:",
                                        result["severity"]
                                    )

                                    print(
                                        "Details:",
                                        details
                                    )

                                    print(
                                        "--------------------------------"
                                    )

                                else:

                                    print(
                                        "Duplicate threat ignored:",
                                        source_ip,
                                        result["type"]
                                    )

                                port_activity[
                                    source_ip
                                ].clear()

                                port_activity_time[
                                    source_ip
                                ] = time.time()


                    # --------------------------------
                    # Brute Force Detection
                    # --------------------------------

                    tcp_flag_string = str(
                        tcp_flags
                    )

                    is_syn_packet = (
                        "S" in tcp_flag_string
                        and
                        "A" not in tcp_flag_string
                    )


                    if (
                        is_syn_packet
                        and
                        destination_ip == LOCAL_IP
                    ):

                        result = detect_bruteforce(
                            source_ip,
                            destination_port
                        )


                        if result["threat"]:

                            if can_save_threat(
                                source_ip,
                                result["type"]
                            ):

                                details = (
                                    f'{result["attempts_detected"]} '
                                    f'connection attempts from '
                                    f'{result["source_ip"]} '
                                    f'targeting {result["service"]} '
                                    f'port {result["destination_port"]} '
                                    f'within 30 seconds.'
                                )


                                saved = save_threat(
                                    source_ip,
                                    result["type"],
                                    result["severity"],
                                    details
                                )


                                if saved:

                                    print(
                                        "🚨 THREAT DETECTED!"
                                    )

                                    print(
                                        "Threat Type:",
                                        result["type"]
                                    )

                                    print(
                                        "Source IP:",
                                        result["source_ip"]
                                    )

                                    print(
                                        "Service:",
                                        result["service"]
                                    )

                                    print(
                                        "Destination Port:",
                                        result["destination_port"]
                                    )

                                    print(
                                        "Attempts:",
                                        result["attempts_detected"]
                                    )

                                    print(
                                        "Severity:",
                                        result["severity"]
                                    )

                                    print(
                                        "Details:",
                                        details
                                    )

                                    print(
                                        "--------------------------------"
                                    )

                                else:

                                    print(
                                        "Duplicate threat ignored:",
                                        source_ip,
                                        result["type"]
                                    )


                                # Reset after detection

                                activity_key = (
                                    source_ip,
                                    str(destination_port)
                                )

                                bruteforce_activity[
                                    activity_key
                                ] = 0

                                bruteforce_activity_time[
                                    activity_key
                                ] = time.time()


                    # --------------------------------
                    # TCP SYN Flood
                    # --------------------------------

                    tcp_flag_string = str(
                        tcp_flags
                    )

                    is_syn_packet = (
                        "S" in tcp_flag_string
                        and
                        "A" not in tcp_flag_string
                    )

                    if (
                        is_syn_packet
                        and
                        destination_ip == LOCAL_IP
                    ):

                        result = detect_syn_flood(
                            source_ip
                        )

                        if result["threat"]:

                            if can_save_threat(
                                source_ip,
                                result["type"]
                            ):

                                details = (
                                    f'{result["packets_detected"]} '
                                    f'TCP SYN packets detected '
                                    f'within 10 seconds.'
                                )

                                saved = save_threat(
                                    source_ip,
                                    result["type"],
                                    result["severity"],
                                    details
                                )

                                if saved:

                                    print(
                                        "🚨 THREAT DETECTED!"
                                    )

                                    print(
                                        "Threat Type:",
                                        result["type"]
                                    )

                                    print(
                                        "Source IP:",
                                        result["source_ip"]
                                    )

                                    print(
                                        "SYN Packets:",
                                        result["packets_detected"]
                                    )

                                    print(
                                        "Severity:",
                                        result["severity"]
                                    )

                                    print(
                                        "Details:",
                                        details
                                    )

                                    print(
                                        "--------------------------------"
                                    )

                                else:

                                    print(
                                        "Duplicate threat ignored:",
                                        source_ip,
                                        result["type"]
                                    )

                                syn_activity[
                                    source_ip
                                ] = 0

                                syn_activity_time[
                                    source_ip
                                ] = time.time()


                # ==================================
                # ICMP
                # ==================================

                elif protocol == "ICMP":

                    # Only monitor ICMP
                    # traffic targeting local IP

                    if (
                        destination_ip != LOCAL_IP
                    ):

                        continue

                    result = detect_icmp_flood(
                        source_ip
                    )

                    if result["threat"]:

                        if can_save_threat(
                            source_ip,
                            result["type"]
                        ):

                            details = (
                                f'{result["packets_detected"]} '
                                f'ICMP packets detected '
                                f'within 10 seconds.'
                            )

                            saved = save_threat(
                                source_ip,
                                result["type"],
                                result["severity"],
                                details
                            )

                            if saved:

                                print(
                                    "🚨 THREAT DETECTED!"
                                )

                                print(
                                    "Threat Type:",
                                    result["type"]
                                )

                                print(
                                    "Source IP:",
                                    result["source_ip"]
                                )

                                print(
                                    "Packets Detected:",
                                    result["packets_detected"]
                                )

                                print(
                                    "Severity:",
                                    result["severity"]
                                )

                                print(
                                    "Details:",
                                    details
                                )

                                print(
                                    "--------------------------------"
                                )

                            else:

                                print(
                                    "Duplicate threat ignored:",
                                    source_ip,
                                    result["type"]
                                )

                            icmp_activity[
                                source_ip
                            ] = 0

                            icmp_activity_time[
                                source_ip
                            ] = time.time()


                # ==================================
                # UDP
                # ==================================

                elif protocol == "UDP":

                    # Only monitor UDP
                    # traffic targeting local IP

                    if (
                        destination_ip != LOCAL_IP
                    ):

                        continue

                    result = detect_udp_flood(
                        source_ip,
                        destination_port
                    )

                    if result["threat"]:

                        if can_save_threat(
                            source_ip,
                            result["type"]
                        ):

                            details = (
                                f'{result["packets_detected"]} '
                                f'UDP packets from source '
                                f'{result["source_ip"]} '
                                f'targeting destination port '
                                f'{result["destination_port"]} '
                                f'within 10 seconds.'
                            )

                            saved = save_threat(
                                source_ip,
                                result["type"],
                                result["severity"],
                                details
                            )

                            if saved:

                                print(
                                    "🚨 THREAT DETECTED!"
                                )

                                print(
                                    "Threat Type:",
                                    result["type"]
                                )

                                print(
                                    "Source IP:",
                                    result["source_ip"]
                                )

                                print(
                                    "Destination Port:",
                                    result["destination_port"]
                                )

                                print(
                                    "UDP Packets:",
                                    result["packets_detected"]
                                )

                                print(
                                    "Severity:",
                                    result["severity"]
                                )

                                print(
                                    "Details:",
                                    details
                                )

                                print(
                                    "--------------------------------"
                                )

                            else:

                                print(
                                    "Duplicate threat ignored:",
                                    source_ip,
                                    result["type"]
                                )

                            # Reset the same
                            # source + destination
                            # port combination

                            activity_key = (
                                source_ip,
                                str(destination_port)
                            )

                            udp_activity[
                                activity_key
                            ] = 0

                            udp_activity_time[
                                activity_key
                            ] = time.time()


            # ======================================
            # Wait Before Next Check
            # ======================================

            time.sleep(2)


        except Exception as error:

            print(
                "Detector Error:",
                error
            )

            time.sleep(2)


if __name__ == "__main__":

    monitor_packets()