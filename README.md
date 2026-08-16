# Advanced Network Traffic Analyzer

A professional terminal-based network packet analyzer and flow tracker built with Python and Scapy. Designed for cybersecurity education, network troubleshooting, and traffic analysis.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Scapy](https://img.shields.io/badge/scapy-2.5+-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🚀 Features

### Packet Analysis
- **Multi-Layer Capture**: Ethernet (Layer 2), IP (Layer 3), TCP/UDP (Layer 4), Application protocols (Layer 7)
- **Protocol Support**: TCP, UDP, ICMP, ICMPv6, ARP, DNS, HTTP, HTTPS, DHCP, SSH, FTP, SMTP, and more
- **Deep Inspection**: TCP flags, sequence numbers, DNS queries/responses, HTTP methods, service identification
- **Metadata Extraction**: MAC addresses, TTL/Hop Limit, payload lengths, fragmentation detection

### Flow Tracking
- **Stateful Connection Tracking**: Bidirectional flow identification and lifecycle monitoring
- **TCP State Machine**: 3-way handshake tracking, connection establishment, graceful/abrupt teardowns
- **Flow Metrics**: Duration, packet counts (sent/received), byte volumes, average packet size
- **Connection Analysis**: Established vs half-open connections, retransmission detection

### Anomaly Detection (Heuristic-Based)
- **Attack Indicators**: SYN floods, port scans, ICMP/DNS floods, ARP storms
- **Traffic Anomalies**: Abnormally large packets, high connection counts, suspicious packet rates
- **Severity Classification**: INFO/WARNING/CRITICAL levels with detailed reporting
- **Disclaimer**: Educational heuristics, not production IDS

### Statistics & Reporting
- **Real-Time Statistics**: Live packet/flow counters during capture
- **Comprehensive Summaries**: Protocol distribution, traffic direction, top talkers, bandwidth analysis
- **Flow Analysis**: Top flows by volume, connection state breakdown, throughput metrics
- **Anomaly Reports**: Timestamped observations with source attribution

### Filtering & Performance
- **Advanced Filters**: Protocol, IP (source/dest/any), port (source/dest/any), service name
- **BPF Integration**: Berkeley Packet Filter for kernel-level filtering (massive performance boost)
- **Memory Management**: Configurable packet limits, flow table caps, summary-only mode
- **Streaming Analysis**: Efficient PCAP reading for multi-GB files

### Export Capabilities
- **CSV Exports**: Packets, flows, and anomalies with all metadata
- **Forensic-Ready**: Timestamp preservation, flow correlation, anomaly linking

## 📸 Screenshots

*(Placeholder - Add screenshots of:)*
1. *Live capture with colored output*
2. *Capture summary report*
3. *Flow analysis table*
4. *Anomaly report*

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Administrator/root privileges (for live capture)
- Scapy 2.5+

### Install Dependencies
```bash
pip install scapy