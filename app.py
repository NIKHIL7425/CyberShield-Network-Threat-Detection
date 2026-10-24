from flask import Flask, render_template, jsonify, request
import sqlite3


app = Flask(__name__)


DATABASE = "database/threats.db"


# ==========================================================
# Dashboard Page
# ==========================================================

@app.route("/")
def dashboard():

    return render_template("dashboard.html")


# ==========================================================
# Live Traffic Page
# ==========================================================

@app.route("/live-traffic")
def live_traffic():

    return render_template("live_traffic.html")


# ==========================================================
# Threats Page
# ==========================================================

@app.route("/threats")
def threats_page():

    return render_template("threats.html")


# ==========================================================
# Threat Details Page
# ==========================================================

@app.route("/threat-details")
def threat_details_page():

    return render_template(
        "threat_details.html"
    )


# ==========================================================
# Reports Page
# ==========================================================

@app.route("/reports")
def reports_page():

    return render_template("reports.html")


# ==========================================================
# Settings Page
# ==========================================================

@app.route("/settings")
def settings_page():

    return render_template("settings.html")


# ==========================================================
# Dashboard Statistics API
# ==========================================================

@app.route("/api/stats")
def stats():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    # ======================================================
    # Total Packets
    # ======================================================

    total_packets = cursor.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]


    # ======================================================
    # Total Threats
    # ======================================================

    total_threats = cursor.execute(
        "SELECT COUNT(*) FROM threats"
    ).fetchone()[0]


    # ======================================================
    # Monitored Packets
    # ======================================================

    monitored_packets = total_packets


    # ======================================================
    # Protocol Statistics
    # ======================================================

    tcp_packets = cursor.execute("""
        SELECT COUNT(*)
        FROM packets
        WHERE protocol = 'TCP'
    """).fetchone()[0]


    udp_packets = cursor.execute("""
        SELECT COUNT(*)
        FROM packets
        WHERE protocol = 'UDP'
    """).fetchone()[0]


    icmp_packets = cursor.execute("""
        SELECT COUNT(*)
        FROM packets
        WHERE protocol = 'ICMP'
    """).fetchone()[0]


    connection.close()


    return jsonify({

        "total_packets":
            total_packets,

        "monitored_packets":
            monitored_packets,

        "total_threats":
            total_threats,

        "alerts":
            total_threats,

        "tcp_packets":
            tcp_packets,

        "udp_packets":
            udp_packets,

        "icmp_packets":
            icmp_packets

    })


# ==========================================================
# Recent Threats API
# ==========================================================

@app.route("/api/threats")
def threats():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    # ======================================================
    # Get Filters
    # ======================================================

    severity = request.args.get("severity")

    threat_type = request.args.get("type")

    source_ip = request.args.get("source_ip")


    # ======================================================
    # Base Query
    # ======================================================

    query = """
        SELECT
            id,
            source_ip,
            threat_type,
            severity,
            details,
            timestamp
        FROM threats
        WHERE 1=1
    """


    parameters = []


    # ======================================================
    # Severity Filter
    # ======================================================

    if severity and severity.lower() != "all":

        query += """
            AND LOWER(severity) = LOWER(?)
        """

        parameters.append(
            severity
        )


    # ======================================================
    # Threat Type Filter
    # ======================================================

    if threat_type and threat_type.lower() != "all":

        query += """
            AND LOWER(threat_type) = LOWER(?)
        """

        parameters.append(
            threat_type
        )


    # ======================================================
    # Source IP Filter
    # ======================================================

    if source_ip:

        query += """
            AND source_ip LIKE ?
        """

        parameters.append(
            "%" + source_ip + "%"
        )


    # ======================================================
    # Latest 50 Threats
    # ======================================================

    query += """
        ORDER BY id DESC
        LIMIT 50
    """


    rows = cursor.execute(
        query,
        parameters
    ).fetchall()


    connection.close()


    # ======================================================
    # Convert Rows To JSON
    # ======================================================

    threats_list = []


    for row in rows:

        threats_list.append({

            "id":
                row["id"],

            "source_ip":
                row["source_ip"],

            "threat_type":
                row["threat_type"],

            "severity":
                row["severity"],

            "details":
                row["details"],

            "timestamp":
                row["timestamp"]

        })


    return jsonify(
        threats_list
    )


# ==========================================================
# Single Threat Details API
# ==========================================================

@app.route("/api/threat/<int:threat_id>")
def threat_details_api(threat_id):

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    # ======================================================
    # Find Threat By ID
    # ======================================================

    threat = cursor.execute("""
        SELECT
            id,
            source_ip,
            threat_type,
            severity,
            details,
            timestamp
        FROM threats
        WHERE id = ?
    """, (
        threat_id,
    )).fetchone()


    connection.close()


    # ======================================================
    # Threat Not Found
    # ======================================================

    if threat is None:

        return jsonify({

            "error":
                "Threat not found."

        }), 404


    # ======================================================
    # Return Threat Details
    # ======================================================

    return jsonify({

        "id":
            threat["id"],

        "source_ip":
            threat["source_ip"],

        "threat_type":
            threat["threat_type"],

        "severity":
            threat["severity"],

        "details":
            threat["details"],

        "timestamp":
            threat["timestamp"]

    })


# ==========================================================
# Related Packets For Threat API
# ==========================================================

@app.route("/api/threat/<int:threat_id>/packets")
def threat_packets(threat_id):

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    # ======================================================
    # Get Threat Information
    # ======================================================

    threat = cursor.execute("""
        SELECT
            id,
            source_ip,
            threat_type,
            severity,
            details,
            timestamp
        FROM threats
        WHERE id = ?
    """, (
        threat_id,
    )).fetchone()


    # ======================================================
    # Threat Not Found
    # ======================================================

    if threat is None:

        connection.close()

        return jsonify({

            "error":
                "Threat not found."

        }), 404


    # ======================================================
    # Get Related Packets
    #
    # Both threat and packet timestamps are stored
    # using the same India Standard Time.
    #
    # Therefore, no timezone conversion is required.
    #
    # Search within 10 seconds before and after
    # the threat detection time.
    # ======================================================

    packets = cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags,
            timestamp
        FROM packets
        WHERE source_ip = ?

        AND timestamp BETWEEN

            datetime(
                ?,
                '-10 seconds'
            )

            AND

            datetime(
                ?,
                '+10 seconds'
            )

        ORDER BY id DESC

        LIMIT 50
    """, (
        threat["source_ip"],
        threat["timestamp"],
        threat["timestamp"]
    )).fetchall()


    connection.close()


    # ======================================================
    # Convert Packets To JSON
    # ======================================================

    packet_list = []


    for packet in packets:

        packet_list.append({

            "source_ip":
                packet["source_ip"],

            "destination_ip":
                packet["destination_ip"],

            "protocol":
                packet["protocol"],

            "source_port":
                packet["source_port"],

            "destination_port":
                packet["destination_port"],

            "packet_size":
                packet["packet_size"],

            "tcp_flags":
                packet["tcp_flags"],

            "timestamp":
                packet["timestamp"]

        })


    # ======================================================
    # Return Related Packets
    # ======================================================

    return jsonify({

        "threat_id":
            threat["id"],

        "source_ip":
            threat["source_ip"],

        "total":
            len(packet_list),

        "packets":
            packet_list

    })


# ==========================================================
# Total Threat Count API
# ==========================================================

@app.route("/api/threat-count")
def threat_count():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    total = cursor.execute("""
        SELECT COUNT(*)
        FROM threats
    """).fetchone()[0]


    connection.close()


    return jsonify({

        "total":
            total

    })


# ==========================================================
# Clear Threat Records API
# ==========================================================

@app.route(
    "/api/clear-threats",
    methods=["POST"]
)
def clear_threats():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    try:

        # ==================================================
        # Get Current Threat Count
        # ==================================================

        threat_count_before = cursor.execute("""
            SELECT COUNT(*)
            FROM threats
        """).fetchone()[0]


        # ==================================================
        # Delete ONLY Threat Records
        # ==================================================

        cursor.execute("""
            DELETE FROM threats
        """)


        connection.commit()


        # ==================================================
        # Confirm Remaining Threats
        # ==================================================

        threat_count_after = cursor.execute("""
            SELECT COUNT(*)
            FROM threats
        """).fetchone()[0]


        connection.close()


        return jsonify({

            "success":
                True,

            "deleted":
                threat_count_before,

            "remaining":
                threat_count_after,

            "message":
                "Threat records cleared successfully."

        })


    except Exception as error:

        connection.rollback()

        connection.close()


        return jsonify({

            "success":
                False,

            "message":
                "Failed to clear threat records: "
                + str(error)

        }), 500


# ==========================================================
# Recent Captured Packets API
# ==========================================================

@app.route("/api/packets")
def packets():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    rows = cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            protocol,
            destination_port,
            packet_size,
            timestamp
        FROM packets
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()


    connection.close()


    packets_list = []


    for row in rows:

        packets_list.append({

            "source_ip":
                row["source_ip"],

            "destination_ip":
                row["destination_ip"],

            "protocol":
                row["protocol"],

            "destination_port":
                row["destination_port"],

            "packet_size":
                row["packet_size"],

            "timestamp":
                row["timestamp"]

        })


    return jsonify(
        packets_list
    )


# ==========================================================
# Reports API
# ==========================================================

@app.route("/api/report")
def report():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()


    # ======================================================
    # Total Packets
    # ======================================================

    total_packets = cursor.execute(
        "SELECT COUNT(*) FROM packets"
    ).fetchone()[0]


    # ======================================================
    # Total Threats
    # ======================================================

    total_threats = cursor.execute(
        "SELECT COUNT(*) FROM threats"
    ).fetchone()[0]


    # ======================================================
    # Monitored Packets
    # ======================================================

    monitored_packets = total_packets


    # ======================================================
    # Threat Summary
    # ======================================================

    threat_types = cursor.execute("""
        SELECT
            threat_type,
            COUNT(*) AS count
        FROM threats
        GROUP BY threat_type
    """).fetchall()


    threat_summary = []


    for row in threat_types:

        threat_summary.append({

            "threat_type":
                row["threat_type"],

            "count":
                row["count"]

        })


    # ======================================================
    # Severity Summary
    # ======================================================

    severity_types = cursor.execute("""
        SELECT
            severity,
            COUNT(*) AS count
        FROM threats
        GROUP BY severity
    """).fetchall()


    severity_summary = []


    for row in severity_types:

        severity_summary.append({

            "severity":
                row["severity"],

            "count":
                row["count"]

        })


    # ======================================================
    # Latest Threats
    #
    # Include threat ID so Reports page can open
    # the Threat Details page.
    # ======================================================

    latest_threats = cursor.execute("""
        SELECT
            id,
            source_ip,
            threat_type,
            severity,
            details,
            timestamp
        FROM threats
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()


    recent_threats = []


    for row in latest_threats:

        recent_threats.append({

            "id":
                row["id"],

            "source_ip":
                row["source_ip"],

            "threat_type":
                row["threat_type"],

            "severity":
                row["severity"],

            "details":
                row["details"],

            "timestamp":
                row["timestamp"]

        })


    connection.close()


    # ======================================================
    # Return Report Data
    # ======================================================

    return jsonify({

        "total_packets":
            total_packets,

        "monitored_packets":
            monitored_packets,

        "total_threats":
            total_threats,

        "threat_summary":
            threat_summary,

        "severity_summary":
            severity_summary,

        "recent_threats":
            recent_threats

    })


# ==========================================================
# Start Flask Server
# ==========================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)