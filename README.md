
# CyberShield – Network Threat Detection System

CyberShield is a web-based network monitoring and threat detection system developed using Python, Flask, Scapy, and SQLite. It captures network packets, identifies selected suspicious activities, and displays network information through a user-friendly dashboard.

## Features

- Network packet capture and monitoring
- Detection of port scans
- Detection of ICMP floods
- Detection of TCP SYN floods
- Detection of UDP floods
- Detection of brute-force attempts
- Live network traffic dashboard
- Threat details and severity information
- Threat reports and CSV export
- SQLite database for storing packet and threat records
- Configurable dashboard refresh settings

## Technologies Used

- **Python** – Main programming language
- **Flask** – Web application framework
- **Scapy** – Network packet capture and analysis
- **SQLite** – Database
- **HTML, CSS, JavaScript** – User interface

## Project Structure

```text
NetworkThreatDetection/
├── app.py
├── database.py
├── detector.py
├── packet_capture.py
├── test_detector.py
├── test_icmp.py
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
├── templates/
│   ├── dashboard.html
│   ├── live_traffic.html
│   ├── reports.html
│   ├── settings.html
│   ├── threat_details.html
│   └── threats.html
└── .gitignore
```

## Installation and Setup

1. Install Python on your computer.
2. Clone this repository:

   ```bash
   git clone https://github.com/NIKHIL7425/CyberShield-Network-Threat-Detection.git
   ```

3. Open the project folder:

   ```bash
   cd CyberShield-Network-Threat-Detection
   ```

4. Install the required Python packages used by the project:

   ```bash
   pip install flask scapy
   ```

   Install any other dependencies required by your local setup.

5. Start the Flask application:

   ```bash
   python app.py
   ```

6. Open the local dashboard in your browser at `http://127.0.0.1:5000`.

**Note:** Packet capture may require administrator privileges and a compatible network capture setup. Run monitoring only on networks you own or have permission to monitor.

## Limitations

- Detection is based on implemented rules and selected traffic patterns.
- False positives and missed detections are possible.
- The system does not automatically block attacks.
- Results depend on the traffic visible to the packet capture process.

## Purpose

This project was developed as an academic project to demonstrate basic network monitoring, threat detection, database management, and web-based reporting.

## Repository

https://github.com/NIKHIL7425/CyberShield-Network-Threat-Detection
