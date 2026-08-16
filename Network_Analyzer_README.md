# Network Traffic Analyzer

A Python-based network traffic analyzer built with **Scapy** for live packet capture, PCAP analysis, flow tracking, traffic statistics, and heuristic-based anomaly detection.

The project is designed as a practical cybersecurity tool for understanding how network traffic can be captured, parsed, grouped into flows, summarized, and inspected for suspicious patterns.

> **Note:** Anomaly detection in this project is heuristic-based. Its findings are indicators for investigation, not proof of a confirmed attack.

## Features

### Packet Analysis

- Live packet capture from a selected network interface
- Offline PCAP file analysis
- Ethernet/MAC address extraction
- IPv4 and IPv6 metadata extraction
- TCP, UDP, ICMP, ICMPv6, and ARP analysis
- TCP flags, sequence numbers, ACK numbers, and window size
- Packet length and raw payload length
- IPv4 TTL and IPv6 Hop Limit
- IPv4 fragmentation detection
- Traffic direction classification:
  - Incoming
  - Outgoing
  - Local
  - External
  - Unknown

### Protocol and Service Identification

The analyzer identifies:

- TCP
- UDP
- ICMP
- ICMPv6
- ARP
- DNS
- HTTP
- HTTPS
- DHCP
- SSH
- FTP
- SMTP

It also maps common port numbers to service names.

For HTTP, the analyzer can identify plaintext HTTP traffic using common request signatures such as `GET`, `POST`, `PUT`, and `DELETE`.

HTTPS is identified primarily through the standard TCP port 443; the project does **not** decrypt or inspect encrypted HTTPS application data.

### DNS Analysis

For DNS packets, the analyzer extracts:

- Query name
- Query type
- IPv4/IPv6 response addresses when available

Supported query types include common records such as:

- A
- AAAA
- CNAME
- MX
- TXT
- NS

### Flow Tracking

The analyzer maintains bidirectional TCP/UDP flows and records:

- Source and destination IP addresses
- Source and destination ports
- Protocol
- Packets sent and received
- Bytes sent and received
- Total packets and bytes
- Flow duration
- Average packet size

TCP flow state tracking includes:

- SYN observed
- SYN-ACK observed
- Final ACK observed
- FIN observed
- RST observed
- Established connection indication
- Half-open connection indication

The flow table is capped at **10,000 tracked flows**. When the limit is reached, the oldest flow is removed to control memory usage.

### Heuristic Anomaly Detection

The analyzer checks for several traffic patterns that may warrant investigation:

- Possible port scans
- SYN flood indicators
- ICMP traffic bursts
- DNS query bursts
- ARP traffic bursts
- Unusually large packets
- High connection counts to a destination

The configured thresholds include:

| Indicator | Current threshold |
|---|---:|
| Possible port scan | More than 20 destination ports |
| SYN flood indicator | More than 70% SYN packets after 100 TCP packets |
| ICMP burst | More than 100 ICMP/ICMPv6 packets |
| DNS query burst | More than 50 queries from a source |
| ARP storm | More than 50 ARP packets |
| Large packet | More than 9,000 bytes |
| High connection count | More than 100 connections to a destination |

Findings are reported with severity labels such as **INFO** and **WARNING**.

These are intentionally treated as **observations rather than confirmed attacks**, because the analyzer does not perform full behavioral analysis, signature matching, or machine-learning-based detection.

### Statistics and Reporting

The analyzer provides:

- Total packets and bytes
- Capture duration
- Packet rate
- Average packet size
- Unique IP counts
- Active flow count
- Traffic direction distribution
- Protocol distribution by packet count
- Protocol distribution by bytes
- Top services
- Top source IPs
- Top destination IPs
- TCP flag distribution
- DNS query count
- HTTP traffic count
- HTTPS traffic count
- Top flows by data volume
- TCP connection-state summary
- Anomaly reports

### Filtering

Interactive filters can be configured for:

- Protocol
- Source IP
- Destination IP
- Any IP
- Source port
- Destination port
- Any port
- Service

For live capture, supported IP/port/protocol filters are also converted into a **Berkeley Packet Filter (BPF)** expression so filtering can occur before packets are processed by the Python application.

### Memory and PCAP Processing

The analyzer processes PCAP files using Scapy's `PcapReader`, allowing packets to be processed incrementally instead of loading the complete capture into memory.

Individual packet records are stored up to a limit of **50,000 packets**. After that limit is reached, the analyzer switches to summary-only mode while continuing to process incoming packets for statistics, flow tracking, and anomaly detection.

Statistics such as packet counts, byte counts, protocol counts, direction counts, and service counts are updated incrementally as packets are processed.

### CSV Export

The project supports CSV export for:

- Packet records
- Flow records
- Anomaly reports

Packet exports can include fields such as:

- Timestamp
- Source/destination IP
- Source/destination ports
- Protocol
- Service
- Direction
- Packet/payload length
- TTL
- TCP flags
- TCP sequence/ACK numbers
- TCP window size
- MAC addresses
- DNS information
- Suspicious status and reason

## Menu

When the program starts, it provides:

```text
1. Capture Live Packets
2. Analyze PCAP File
3. Show Capture Summary
4. Show Flow Analysis
5. Show Anomaly Report
6. Export Packets to CSV
7. Export Flows to CSV
8. Export Anomalies to CSV
9. Configure Filters
0. Exit
```

## Requirements

- Python 3.8+
- Scapy 2.5.0 or newer

Install the dependency with:

```bash
pip install -r requirements.txt
```

## Usage

### Live Capture

Run:

```bash
python network_traffic_analyzer.py
```

Choose **Capture Live Packets**, select a network interface, specify the packet count, and optionally enable live statistics.

Live packet capture may require elevated privileges. On Windows, a packet-capture driver such as **Npcap** may also be required.

### PCAP Analysis

Choose **Analyze PCAP File** and provide the path to an existing `.pcap` or compatible capture file.

The analyzer processes packets incrementally and then displays a capture summary.

## Project Structure

```text
network_analyzer/
├── network_traffic_analyzer.py
├── requirements.txt
├── README.md
└── description.txt
```

## What This Project Demonstrates

- Packet capture and protocol parsing with Scapy
- Network-layer and transport-layer traffic analysis
- Selected application-protocol inspection
- Stateful TCP/UDP flow tracking
- TCP connection-state analysis
- Traffic statistics and aggregation
- Heuristic network anomaly detection
- BPF-based live-capture filtering
- Incremental PCAP processing
- Memory-aware packet and flow handling
- CSV-based security reporting

## Limitations

This project is intentionally a lightweight educational analyzer rather than a full IDS/IPS or forensic platform.

- Anomaly detection is heuristic and can produce false positives or miss attacks.
- It does not perform packet payload reconstruction or deep packet inspection for all protocols.
- HTTPS traffic is identified but not decrypted.
- It does not implement TCP retransmission detection.
- It does not provide machine-learning-based detection.
- It does not provide chain-of-custody or evidence-management functionality.
- Packet records are retained only up to the configured in-memory limit.

## Future Improvements

Possible future improvements include:

- TCP retransmission detection using sequence-number tracking
- Additional protocol parsers
- More sophisticated anomaly correlation
- PCAP/report visualization
- Configurable anomaly thresholds
- Additional export formats
- Automated test coverage

## Author

**Darshan Kalburgi**

Cybersecurity student interested in practical security, network analysis, web security, and hands-on security tooling.
