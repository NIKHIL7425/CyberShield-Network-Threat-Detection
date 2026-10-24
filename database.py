import sqlite3
from datetime import datetime, timezone, timedelta


DATABASE = "database/threats.db"


def get_india_time():

    india_timezone = timezone(
        timedelta(hours=5, minutes=30)
    )

    return datetime.now(
        india_timezone
    ).strftime("%Y-%m-%d %H:%M:%S")


def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    # ==========================================
    # Packets Table
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port TEXT,
            destination_port TEXT,
            packet_size INTEGER,
            tcp_flags TEXT,
            timestamp TEXT
        )
    """)


    # ==========================================
    # Threats Table
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            threat_type TEXT,
            severity TEXT,
            details TEXT,
            timestamp TEXT
        )
    """)


    connection.commit()

    connection.close()



def save_packet(
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    packet_size,
    tcp_flags="-"
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO packets (
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        destination_ip,
        protocol,
        str(source_port),
        str(destination_port),
        packet_size,
        str(tcp_flags),
        get_india_time()
    ))


    connection.commit()

    connection.close()



def save_threat(
    source_ip,
    threat_type,
    severity,
    details
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO threats (
            source_ip,
            threat_type,
            severity,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        source_ip,
        threat_type,
        severity,
        details,
        get_india_time()
    ))


    connection.commit()

    connection.close()



if __name__ == "__main__":

    create_database()

    print(
        "Database created successfully."
    )