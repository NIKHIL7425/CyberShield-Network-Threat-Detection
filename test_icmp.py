from detector import detect_icmp_flood
from database import create_database, save_threat


source_ip = "127.0.0.1"

# Make sure database exists
create_database()

print("Testing ICMP Flood Detector...")
print("--------------------------------")


for packet in range(1, 21):

    result = detect_icmp_flood(source_ip)

    print(f"Testing ICMP packet {packet}")

    if result["threat"]:

        print("🚨 THREAT DETECTED!")
        print(f"Threat Type: {result['type']}")
        print(f"Source IP: {result['source_ip']}")
        print(f"Packets Detected: {result['packets_detected']}")

        # Save threat to database
        save_threat(
            result["source_ip"],
            result["type"],
            "High",
            f"{result['packets_detected']} ICMP packets detected"
        )

        print("✅ ICMP threat saved to database.")