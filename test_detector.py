from detector import detect_port_scan
from database import create_database, save_threat


source_ip = "127.0.0.1"

# Make sure database exists
create_database()

print("Testing Port Scan Detector...")
print("--------------------------------")


for port in range(1, 11):

    result = detect_port_scan(
        source_ip,
        port
    )

    print(f"Testing port {port}")

    if result["threat"]:

        print("🚨 THREAT DETECTED!")
        print(f"Threat Type: {result['type']}")
        print(f"Source IP: {result['source_ip']}")
        print(f"Ports Detected: {result['ports_detected']}")

        # Save threat to database
        save_threat(
            result["source_ip"],
            result["type"],
            "High",
            f"{result['ports_detected']} different ports detected"
        )

        print("✅ Threat saved to database.")