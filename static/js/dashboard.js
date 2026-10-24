// ==========================================
// Get refresh interval from Settings
// ==========================================

const savedInterval =
    localStorage.getItem("refreshInterval");

// Default: 3 seconds
const refreshInterval = savedInterval
    ? parseInt(savedInterval)
    : 3000;


// ==========================================
// Load Dashboard Statistics
// ==========================================

async function loadStats() {

    try {

        const response =
            await fetch("/api/stats");


        if (!response.ok) {

            throw new Error(
                "Failed to fetch statistics"
            );

        }


        const data =
            await response.json();


        // ======================================
        // Main Statistics
        // ======================================

        document.getElementById(
            "total-packets"
        ).textContent =
            data.total_packets;


        document.getElementById(
            "threats-detected"
        ).textContent =
            data.total_threats;


        document.getElementById(
            "normal-traffic"
        ).textContent =
            data.monitored_packets;


        document.getElementById(
            "alerts"
        ).textContent =
            data.alerts;


        // ======================================
        // Protocol Statistics
        // ======================================

        document.getElementById(
            "tcp-packets"
        ).textContent =
            data.tcp_packets;


        document.getElementById(
            "udp-packets"
        ).textContent =
            data.udp_packets;


        document.getElementById(
            "icmp-packets"
        ).textContent =
            data.icmp_packets;

    }

    catch (error) {

        console.error(
            "Error loading dashboard statistics:",
            error
        );

    }

}


// ==========================================
// Load Recent Threats
// ==========================================

async function loadThreats() {

    try {

        const response =
            await fetch("/api/threats");


        if (!response.ok) {

            throw new Error(
                "Failed to fetch threats"
            );

        }


        const threats =
            await response.json();


        const tableBody =
            document.getElementById(
                "threat-table-body"
            );


        tableBody.innerHTML = "";


        // ======================================
        // No threats
        // ======================================

        if (threats.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="4">
                        No threats detected yet.
                    </td>
                </tr>
            `;

            return;

        }


        // ======================================
        // Display threats
        // ======================================

        threats.forEach(threat => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>${threat.source_ip}</td>

                <td>${threat.threat_type}</td>

                <td>
                    <span class="severity-badge ${getSeverityClass(threat.severity)}">
                        ${threat.severity || "Medium"}
                    </span>
                </td>

                <td>${threat.timestamp}</td>
            `;


            tableBody.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "Error loading threats:",
            error
        );

    }

}


// ==========================================
// Severity Class
// ==========================================

function getSeverityClass(severity) {

    if (!severity) {

        return "severity-medium";

    }


    const level =
        severity.toLowerCase();


    if (level === "critical") {

        return "severity-critical";

    }


    if (level === "high") {

        return "severity-high";

    }


    if (level === "medium") {

        return "severity-medium";

    }


    return "severity-medium";

}


// ==========================================
// Load Network Packets
// ==========================================

async function loadPackets() {

    try {

        const response =
            await fetch("/api/packets");


        if (!response.ok) {

            throw new Error(
                "Failed to fetch packets"
            );

        }


        const packets =
            await response.json();


        const tableBody =
            document.getElementById(
                "traffic-table-body"
            );


        tableBody.innerHTML = "";


        // ======================================
        // No packets
        // ======================================

        if (packets.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="6">
                        No network traffic available.
                    </td>
                </tr>
            `;

            return;

        }


        // ======================================
        // Display packets
        // ======================================

        packets.forEach(packet => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>${packet.source_ip}</td>

                <td>${packet.destination_ip}</td>

                <td>${packet.protocol}</td>

                <td>${packet.destination_port}</td>

                <td>${packet.packet_size} bytes</td>

                <td>${packet.timestamp}</td>
            `;


            tableBody.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "Error loading network traffic:",
            error
        );

    }

}


// ==========================================
// Load All Dashboard Data
// ==========================================

function loadDashboardData() {

    loadStats();

    loadThreats();

    loadPackets();

}


// ==========================================
// Load Immediately
// ==========================================

loadDashboardData();


// ==========================================
// Auto Refresh Using Settings
// ==========================================

setInterval(
    loadDashboardData,
    refreshInterval
);