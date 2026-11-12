# NetSentry
### Network Intrusion Detection and Monitoring System

> **Project Status: Work in Progress**

NetSentry is a Python-based Network Intrusion Detection and Monitoring System (NIDS) designed to monitor network traffic, identify suspicious activities, generate security alerts and provide network visibility through a web-based dashboard.

The project combines packet analysis, traffic monitoring, intrusion detection, device inventory and security event management into a centralised monitoring application.

## Project Objectives

- Monitor network traffic and analyse packets.
- Detect suspicious network behaviour.
- Identify potential network attacks.
- Maintain network device and connection information.
- Generate and store security alerts.
- Provide a centralised security monitoring dashboard.
- Maintain historical network statistics and investigation records.

## Key Features

### Network Monitoring
- Live network packet monitoring.
- Protocol analysis.
- Traffic statistics.
- Connection tracking.
- Device inventory.

### Intrusion Detection

Implemented detection mechanisms include:

- Port scan detection.
- SYN flood detection.
- ICMP flood detection.
- Repeated DNS query detection.
- Repeated connection detection.

Additional detection validation is ongoing.

### Web Dashboard

The dashboard includes interfaces for:

- Security overview.
- Network connections.
- Device inventory.
- Security alerts.
- Incident management.
- IP and domain investigation.
- Traffic analytics.
- Detection rules.
- PDF reports.
- System settings.

Dashboard functionality is currently undergoing testing.

### Data Management

- MySQL database integration.
- Persistent monitoring statistics.
- Security alert storage.
- Historical network information.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and detection logic |
| Scapy | Network packet capture and analysis |
| Flask | Web application backend |
| MySQL | Database management |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Dashboard interactions |
| Linux / Ubuntu Server | Development and deployment environment |
| Kali Linux | Controlled security testing |
| Git / GitHub | Version control |

## Project Architecture

NetSentry consists of two primary components:

**1. Network Monitoring Sensor**

Responsible for packet capture, traffic analysis, connection tracking, device inventory and detection of suspicious network activities.

**2. Web Dashboard and Backend**

Responsible for presenting monitoring information, managing security alerts, accessing stored data and providing investigation and reporting interfaces.

The sensor and dashboard communicate through the application's backend client/server components.

## Detection Mechanisms

| Detection | Purpose |
|---|---|
| PORT_SCAN | Identifies suspicious port scanning activity |
| SYN_FLOOD | Identifies unusually high volumes of SYN packets |
| ICMP_FLOOD | Identifies unusually high ICMP traffic |
| DNS_FLOOD | Identifies excessive DNS requests |
| REPEATED_DNS | Identifies repeated DNS queries |
| REPEATED_CONNECTIONS | Identifies unusually frequent connections |

Detection thresholds and validation results are subject to ongoing testing.

## Development Environment

The project is developed and tested using:

- Ubuntu Server
- Kali Linux
- Python virtual environments
- MySQL
- Flask

Testing is conducted in a controlled virtual network environment.

## Current Development Status

The core monitoring and detection components have been developed.

The remaining work includes:

- Complete dashboard functionality testing.
- Connection details and filtering validation.
- IP and domain investigation testing.
- Security alert and severity filter testing.
- Detection rule validation.
- Incident management testing.
- Analytics and date filter testing.
- PDF report generation testing.
- Controlled IDS testing using Kali Linux.
- Database persistence verification.
- Sensor disconnection and reconnection testing.
- Reliability and regression testing.

## Project Goals

Future development will focus on improving detection accuracy, dashboard reliability, monitoring capabilities, investigation features and overall system performance.

## Disclaimer

NetSentry is an educational cybersecurity project developed for learning and research purposes.

All security testing should be performed only on networks and systems for which permission has been granted.

---

**Developed by Angad Sawarkar**

BCA Student | Aspiring Cloud Security & Cybersecurity Professional
