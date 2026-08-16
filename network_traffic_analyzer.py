"""
Advanced Network Traffic Analyzer
==================================
A professional terminal-based network packet analyzer and flow tracker using Scapy.

This tool goes beyond simple packet capture to provide:
  - Stateful TCP/UDP flow tracking
  - Protocol identification and service mapping
  - Connection state analysis (handshakes, teardowns)
  - Real-time anomaly detection (port scans, floods, suspicious patterns)
  - Comprehensive traffic statistics and reporting
  - Memory-efficient streaming analysis for large captures

Designed for cybersecurity portfolio demonstration and educational purposes.
NOT a production IDS - uses heuristic warnings, not ML-based threat detection.

Author: Darshan Kalburgi
License: MIT
"""

import csv
import sys
import ipaddress
import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Set
from enum import Enum

# Terminal colors for better UX (ANSI escape codes work on Linux/Mac/Windows 10+)
class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

try:
    from scapy.all import sniff, PcapReader, wrpcap, get_if_list, conf
    from scapy.all import DNSRR
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, Ether
    from scapy.error import Scapy_Exception
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA
except Exception as e:
    import traceback
    print("\n=== Import Error ===")
    traceback.print_exc()
    sys.exit(1)

# ============================================================================
# CONSTANTS & CONFIGURATIONS
# ============================================================================

# Well-known service port mappings (cybersecurity professionals need to know these)
SERVICE_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MS-SQL", 1521: "Oracle-DB",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

# HTTP methods for plaintext detection
HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
    b"PATCH ", b"TRACE ", b"CONNECT ", b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2"
)

# Anomaly detection thresholds (heuristics, not ML)
class AnomalyThresholds:
    SYN_RATIO = 0.7              # >70% SYN packets suggests SYN flood
    PORT_SCAN_THRESHOLD = 20     # >20 unique ports to same host in short time
    ICMP_BURST_THRESHOLD = 100   # >100 ICMP packets in analysis window
    DNS_QUERY_BURST = 50         # >50 DNS queries from one host
    LARGE_PACKET_SIZE = 9000     # Jumbo frames or fragmentation attack
    CONNECTION_THRESHOLD = 100   # >100 connections to single host
    ARP_STORM_THRESHOLD = 50     # >50 ARP packets in short time
    PACKET_RATE_HIGH = 1000      # >1000 packets/sec is high rate

# Memory management
MAX_PACKETS_IN_MEMORY = 50000   # Beyond this, switch to summary-only mode
MAX_FLOWS_TRACKED = 10000       # Limit flow table size

# ============================================================================
# DATA STRUCTURES
# ============================================================================

class Protocol(Enum):
    """Enumeration for protocol types (safer than strings)."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPv6 = "ICMPv6"
    ARP = "ARP"
    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DHCP = "DHCP"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    OTHER = "Other"

class Direction(Enum):
    """Traffic direction classification."""
    INCOMING = "Incoming"
    OUTGOING = "Outgoing"
    LOCAL = "Local"
    EXTERNAL = "External"
    UNKNOWN = "Unknown"

@dataclass
class PacketRecord:
    """
    Complete packet metadata for analysis and export.
    
    This structure captures everything needed for forensic analysis:
    - Timing: actual packet timestamp (not processing time)
    - Layer 2: MAC addresses for ARP/spoofing detection
    - Layer 3: IP addresses, TTL/HopLimit
    - Layer 4: Ports, flags, sequence numbers, window size
    - Layer 7: Protocol identification, service mapping, payloads
    - Context: Direction, flow association, anomaly flags
    """
    # Timing
    timestamp: str
    epoch_time: float  # For calculations (RTT, duration, etc.)
    
    # Layer 2 (Ethernet)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    
    # Layer 3 (Network)
    src_ip: str = ""
    dst_ip: str = ""
    ttl: Optional[int] = None
    ip_version: int = 4
    
    # Layer 4 (Transport)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "Other"
    
    # TCP-specific
    tcp_flags: Optional[str] = None
    seq_num: Optional[int] = None
    ack_num: Optional[int] = None
    window_size: Optional[int] = None
    
    # Packet metrics
    packet_length: int = 0
    payload_length: int = 0
    
    # Analysis metadata
    direction: str = "Unknown"
    service: Optional[str] = None  # Mapped from port
    flow_id: Optional[str] = None  # For flow tracking
    
    # Protocol-specific data
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None
    dns_response: Optional[str] = None
    
    # Flags for anomaly detection
    is_fragmented: bool = False
    is_suspicious: bool = False
    suspicious_reason: Optional[str] = None

@dataclass
class FlowRecord:
    """
    Stateful connection/flow tracking.
    
    Why flows matter: Network attacks often involve multiple packets
    forming a conversation. Port scans open many connections. DDoS
    creates thousands of half-open connections. Data exfiltration
    involves sustained large transfers. Flows reveal these patterns.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    
    # Flow statistics
    packets_sent: int = 0  # Src → Dst
    packets_recv: int = 0  # Dst → Src
    bytes_sent: int = 0
    bytes_recv: int = 0
    
    # Timing
    start_time: float = 0.0
    last_seen: float = 0.0
    
    # TCP state tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    ack_seen: bool = False  # Handshake complete
    fin_seen: bool = False
    rst_seen: bool = False
    
    # Computed metrics
    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time if self.last_seen > 0 else 0.0
    
    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_recv
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv
    
    @property
    def avg_packet_size(self) -> float:
        return self.total_bytes / self.total_packets if self.total_packets > 0 else 0.0
    
    @property
    def is_established(self) -> bool:
        """TCP connection fully established (3-way handshake complete)."""
        return self.syn_seen and self.syn_ack_seen and self.ack_seen
    
    @property
    def is_half_open(self) -> bool:
        """SYN sent but no SYN-ACK received (potential SYN flood victim)."""
        return self.syn_seen and not self.syn_ack_seen

@dataclass
class FilterSettings:
    """Comprehensive filtering options."""
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    any_ip: Optional[str] = None  # Matches either src or dst
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    any_port: Optional[int] = None
    service: Optional[str] = None  # Filter by service name (e.g., "SSH")
    
    def is_active(self) -> bool:
        return any([
            self.protocol, self.src_ip, self.dst_ip, self.any_ip,
            self.src_port, self.dst_port, self.any_port, self.service
        ])
    
    def __str__(self) -> str:
        parts = []
        if self.protocol:
            parts.append(f"protocol={self.protocol}")
        if self.src_ip:
            parts.append(f"src_ip={self.src_ip}")
        if self.dst_ip:
            parts.append(f"dst_ip={self.dst_ip}")
        if self.any_ip:
            parts.append(f"ip={self.any_ip}")
        if self.src_port:
            parts.append(f"src_port={self.src_port}")
        if self.dst_port:
            parts.append(f"dst_port={self.dst_port}")
        if self.any_port:
            parts.append(f"port={self.any_port}")
        if self.service:
            parts.append(f"service={self.service}")
        return ", ".join(parts) if parts else "none"

@dataclass
class AnomalyReport:
    """Heuristic-based anomaly observation (not confirmed attack)."""
    timestamp: str
    anomaly_type: str
    description: str
    severity: str  # "INFO", "WARNING", "CRITICAL"
    source: Optional[str] = None
    details: Dict = field(default_factory=dict)

# ============================================================================
# MAIN ANALYZER CLASS
# ============================================================================

class AdvancedNetworkAnalyzer:
    """
    Professional network traffic analyzer with flow tracking and anomaly detection.
    
    Architecture:
    - Packet ingestion: handle_packet() processes raw Scapy packets
    - Flow tracking: Maintains stateful connection table
    - Protocol analysis: Deep inspection of DNS, HTTP, TCP state
    - Anomaly detection: Heuristic-based warnings (not ML/IDS)
    - Statistics: Real-time incremental counters (not on-demand iteration)
    - Export: CSV export for packets, flows, and anomalies
    
    Memory management:
    - Caps packet storage at MAX_PACKETS_IN_MEMORY
    - Flow table limited to MAX_FLOWS_TRACKED
    - Switches to summary-only mode on memory pressure
    """
    
    def __init__(self):
        # Core storage
        self.packets: List[PacketRecord] = []
        self.flows: Dict[str, FlowRecord] = {}  # flow_id → FlowRecord
        self.anomalies: List[AnomalyReport] = []
        
        # Filters
        self.filters = FilterSettings()
        
        # Statistics (incremental counters for O(1) updates)
        self.stats = {
            'total_packets': 0,
            'filtered_packets': 0,
            'total_bytes': 0,
            'start_time': None,
            'end_time': None,
            'protocol_counts': Counter(),
            'protocol_bytes': Counter(),
            'direction_counts': Counter(),
            'service_counts': Counter(),
            'unique_ips': set(),
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
            'tcp_flags_counts': Counter(),
            'dns_queries': 0,
            'http_requests': 0,
            'https_connections': 0,
        }
        
        # Anomaly detection state
        self.anomaly_state = {
            'syn_packets': 0,
            'total_tcp': 0,
            'icmp_count': 0,
            'arp_count': 0,
            'dns_per_host': Counter(),
            'ports_per_dst': defaultdict(set),  # dst_ip → set(ports)
            'connections_per_host': Counter(),
        }
        
        # Memory management
        self.summary_only_mode = False
        self.packet_buffer_full = False
        
        # Live display
        self.show_live_stats = False
        self.packets_processed = 0

    # ========================================================================
    # HELPER UTILITIES
    # ========================================================================
    
    @staticmethod
    def get_timestamp(packet) -> Tuple[str, float]:
        """
        Extract human-readable and numeric timestamps from packet.
        
        Returns:
            (formatted_string, epoch_time)
        """
        try:
            epoch = float(packet.time)
            formatted = datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            return formatted, epoch
        except Exception:
            now = datetime.now()
            return now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], now.timestamp()
    
    @staticmethod
    def get_mac_addresses(packet) -> Tuple[Optional[str], Optional[str]]:
        """Extract source and destination MAC addresses."""
        if packet.haslayer(Ether):
            return packet[Ether].src, packet[Ether].dst
        return None, None
    
    @staticmethod
    def get_service_name(port: Optional[int]) -> Optional[str]:
        """Map port number to service name."""
        if port is None:
            return None
        return SERVICE_PORTS.get(port)
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is in private range (RFC 1918, RFC 4193)."""
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False
    
    @staticmethod
    def create_flow_id(src_ip: str, dst_ip: str, src_port: Optional[int], 
                       dst_port: Optional[int], protocol: str) -> str:
        """
        Generate unique bidirectional flow identifier.
        
        Why bidirectional: A TCP connection from 192.168.1.5:12345 to 
        8.8.8.8:53 and the return traffic (8.8.8.8:53 to 192.168.1.5:12345)
        are the SAME flow. We normalize the tuple so both directions hash
        to the same ID.
        """
        # Normalize: smaller IP/port first (bidirectional matching)
        if (src_ip, src_port) > (dst_ip, dst_port):
            src_ip, dst_ip = dst_ip, src_ip
            src_port, dst_port = dst_port, src_port
        
        flow_tuple = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        return hashlib.md5(flow_tuple.encode()).hexdigest()[:16]
    
    @staticmethod
    def detect_direction(src_ip: str, dst_ip: str) -> str:
        """Enhanced direction detection with better external traffic handling."""
        try:
            src_private = ipaddress.ip_address(src_ip).is_private
            dst_private = ipaddress.ip_address(dst_ip).is_private
        except ValueError:
            return Direction.UNKNOWN.value
        
        if src_private and dst_private:
            return Direction.LOCAL.value
        elif src_private and not dst_private:
            return Direction.OUTGOING.value
        elif not src_private and dst_private:
            return Direction.INCOMING.value
        else:
            return Direction.EXTERNAL.value
    
    @staticmethod
    def parse_tcp_flags(flags) -> str:
        """
        Convert TCP flags to readable string.
        
        TCP flags are critical for state analysis:
        - S (SYN): Connection initiation
        - A (ACK): Acknowledgment
        - F (FIN): Graceful close
        - R (RST): Abrupt close (often indicates problems)
        - P (PSH): Push data immediately
        - U (URG): Urgent data
        
        Combinations reveal intent:
        - S: SYN scan
        - SA: SYN-ACK (handshake response)
        - FA: FIN-ACK (normal close)
        - R: Connection rejected or reset (suspicious if frequent)
        """
        flag_str = str(flags)
        return flag_str if flag_str else "None"
    
    @staticmethod
    def is_http_traffic(packet) -> bool:
        """Detect plaintext HTTP by payload inspection."""
        if packet.haslayer(Raw):
            try:
                payload = bytes(packet[Raw].load)
                return any(payload.startswith(sig) for sig in HTTP_METHODS)
            except Exception:
                pass
        return False
    
    # ========================================================================
    # PROTOCOL DETECTION & CLASSIFICATION
    # ========================================================================
    
    def detect_protocol(self, packet) -> str:
        """
        Comprehensive protocol detection with service awareness.
        
        Priority order (most specific first):
        1. Application layer: DNS, HTTP, HTTPS, DHCP
        2. Transport layer: TCP, UDP
        3. Network layer: ICMP, ICMPv6
        4. Link layer: ARP
        """
        # Layer 2
        if packet.haslayer(ARP):
            return Protocol.ARP.value
        
        # Application layer (most specific)
        if packet.haslayer(DNS):
            return Protocol.DNS.value
        
        if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
            return Protocol.DHCP.value
        
        # Transport layer with service detection
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # HTTP detection (port + payload)
            if dport == 80 or sport == 80 or self.is_http_traffic(packet):
                return Protocol.HTTP.value
            
            # HTTPS (port only, payload is encrypted)
            if dport == 443 or sport == 443:
                return Protocol.HTTPS.value
            
            # SSH
            if dport == 22 or sport == 22:
                return Protocol.SSH.value
            
            # FTP
            if dport in (20, 21) or sport in (20, 21):
                return Protocol.FTP.value
            
            # SMTP
            if dport in (25, 465, 587) or sport in (25, 465, 587):
                return Protocol.SMTP.value
            
            return Protocol.TCP.value
        
        if packet.haslayer(UDP):
            # DNS over UDP (port 53)
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                if packet.haslayer(DNS):
                    return Protocol.DNS.value
            return Protocol.UDP.value
        
        # Network layer
        if packet.haslayer(ICMP):
            return Protocol.ICMP.value
        
        if packet.haslayer(IPv6):
            # ICMPv6
            if packet[IPv6].nh == 58:
                return Protocol.ICMPv6.value
            return "IPv6"
        
        return Protocol.OTHER.value
    
    # ========================================================================
    # PACKET ANALYSIS
    # ========================================================================
    
    def analyze_dns(self, packet) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract DNS query name, type, and response IPs.
        
        DNS analysis is critical for security:
        - DNS tunneling: Abnormally long domain names
        - Fast-flux: Rapidly changing A records
        - DGA (Domain Generation Algorithm): Random-looking domains
        - C2 communication: Beaconing to suspicious domains
        """
        query_name = None
        query_type = None
        response_ips = []
        
        if not packet.haslayer(DNS):
            return None, None, None
        
        dns = packet[DNS]
        
        # Question section
        if dns.qd is not None:
            try:
                query_name = dns.qd.qname.decode(errors='ignore').rstrip('.')
                # DNS query types: 1=A (IPv4), 28=AAAA (IPv6), 5=CNAME, 15=MX, etc.
                qtype = dns.qd.qtype
                qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}
                query_type = qtype_map.get(qtype, f"Type-{qtype}")
            except Exception:
                pass
        
        # Answer section
        if dns.ancount > 0 and dns.an is not None:
            try:
                # Handle both single answer and list of answers
                answers = dns.an if isinstance(dns.an, list) else [dns.an]
                for rr in answers:
                    if hasattr(rr, 'type') and rr.type in (1, 28):  # A or AAAA
                        if hasattr(rr, 'rdata'):
                            response_ips.append(str(rr.rdata))
            except Exception:
                pass
        
        response_str = ", ".join(response_ips) if response_ips else None
        return query_name, query_type, response_str
    
    def build_packet_record(self, packet) -> Optional[PacketRecord]:
        """
        Convert raw Scapy packet into analyzed PacketRecord.
        
        This is the core analysis pipeline - extracts everything needed
        for forensics, statistics, and anomaly detection.
        """
        timestamp, epoch_time = self.get_timestamp(packet)
        src_mac, dst_mac = self.get_mac_addresses(packet)
        protocol = self.detect_protocol(packet)
        
        # Initialize with defaults
        record = PacketRecord(
            timestamp=timestamp,
            epoch_time=epoch_time,
            src_mac=src_mac,
            dst_mac=dst_mac,
            protocol=protocol,
            packet_length=len(packet)
        )
        
        # ARP (no IP layer)
        if packet.haslayer(ARP):
            arp = packet[ARP]
            record.src_ip = arp.psrc
            record.dst_ip = arp.pdst
            record.direction = Direction.LOCAL.value
            return record
        
        # IP layer (IPv4 or IPv6)
        if packet.haslayer(IP):
            ip = packet[IP]
            record.src_ip = ip.src
            record.dst_ip = ip.dst
            record.ttl = ip.ttl
            record.ip_version = 4
            record.is_fragmented = bool(ip.flags & 0x1) or (ip.frag > 0)
        elif packet.haslayer(IPv6):
            ip = packet[IPv6]
            record.src_ip = ip.src
            record.dst_ip = ip.dst
            record.ttl = ip.hlim
            record.ip_version = 6
        else:
            return None  # No analyzable IP layer
        
        record.direction = self.detect_direction(record.src_ip, record.dst_ip)
        
        # Transport layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            record.src_port = tcp.sport
            record.dst_port = tcp.dport
            record.tcp_flags = self.parse_tcp_flags(tcp.flags)
            record.seq_num = tcp.seq
            record.ack_num = tcp.ack
            record.window_size = tcp.window
            
            # Service mapping
            record.service = (self.get_service_name(tcp.dport) or 
                            self.get_service_name(tcp.sport))
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            record.src_port = udp.sport
            record.dst_port = udp.dport
            record.service = (self.get_service_name(udp.dport) or 
                            self.get_service_name(udp.sport))
        
        # Payload length
        if packet.haslayer(Raw):
            record.payload_length = len(packet[Raw].load)
        
        # DNS-specific analysis
        if protocol == Protocol.DNS.value:
            query, qtype, response = self.analyze_dns(packet)
            record.dns_query = query
            record.dns_type = qtype
            record.dns_response = response
        
        # Flow ID for connection tracking
        record.flow_id = self.create_flow_id(
            record.src_ip, record.dst_ip,
            record.src_port, record.dst_port,
            protocol
        )
        
        return record
    
    # ========================================================================
    # FLOW TRACKING
    # ========================================================================
    
    def update_flow(self, record: PacketRecord):
        """
        Update stateful flow tracking.
        
        Why flows matter in security:
        - Port scans: Many flows to different ports on same host
        - DDoS: Thousands of half-open connections
        - Data exfiltration: Large sustained flows to external IPs
        - Beaconing: Regular small flows at fixed intervals
        """
        if not record.flow_id:
            return
        
        # Memory limit check
        if len(self.flows) >= MAX_FLOWS_TRACKED and record.flow_id not in self.flows:
            # Evict oldest flow (simple LRU-like behavior)
            oldest_flow = min(self.flows.values(), key=lambda f: f.last_seen)
            del self.flows[oldest_flow.flow_id]
        
        if record.flow_id not in self.flows:
            # New flow
            self.flows[record.flow_id] = FlowRecord(
                flow_id=record.flow_id,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                src_port=record.src_port,
                dst_port=record.dst_port,
                protocol=record.protocol,
                start_time=record.epoch_time
            )
        
        flow = self.flows[record.flow_id]
        flow.last_seen = record.epoch_time
        
        # Determine direction within flow (src→dst or dst→src)
        if record.src_ip == flow.src_ip:
            flow.packets_sent += 1
            flow.bytes_sent += record.packet_length
        else:
            flow.packets_recv += 1
            flow.bytes_recv += record.packet_length
        
        # TCP state tracking
        if record.protocol == Protocol.TCP.value and record.tcp_flags:
            flags = record.tcp_flags
            if 'S' in flags and 'A' not in flags:
                flow.syn_seen = True
            if 'S' in flags and 'A' in flags:
                flow.syn_ack_seen = True
            if 'A' in flags and flow.syn_seen and flow.syn_ack_seen:
                flow.ack_seen = True
            if 'F' in flags:
                flow.fin_seen = True
            if 'R' in flags:
                flow.rst_seen = True
    
    # ========================================================================
    # ANOMALY DETECTION (HEURISTICS)
    # ========================================================================
    
    def detect_anomalies(self, record: PacketRecord):
        """
        Heuristic-based anomaly detection.
        
        IMPORTANT: These are OBSERVATIONS, not confirmed attacks.
        Real IDS use ML, behavioral analysis, and signature databases.
        This provides educational examples of what to look for.
        """
        # 1. SYN Flood Detection
        if record.protocol == Protocol.TCP.value and record.tcp_flags:
            self.anomaly_state['total_tcp'] += 1
            if 'S' in record.tcp_flags and 'A' not in record.tcp_flags:
                self.anomaly_state['syn_packets'] += 1
            
            # Check ratio
            if self.anomaly_state['total_tcp'] > 100:
                syn_ratio = self.anomaly_state['syn_packets'] / self.anomaly_state['total_tcp']
                if syn_ratio > AnomalyThresholds.SYN_RATIO:
                    self.add_anomaly(
                        "SYN Flood Indicator",
                        f"High SYN packet ratio: {syn_ratio:.1%} (>{AnomalyThresholds.SYN_RATIO:.0%})",
                        "WARNING",
                        record.src_ip,
                        {"syn_count": self.anomaly_state['syn_packets'], "total_tcp": self.anomaly_state['total_tcp']}
                    )
        
        # 2. Port Scan Detection
        if record.dst_port:
            self.anomaly_state['ports_per_dst'][record.dst_ip].add(record.dst_port)
            unique_ports = len(self.anomaly_state['ports_per_dst'][record.dst_ip])
            if unique_ports > AnomalyThresholds.PORT_SCAN_THRESHOLD:
                self.add_anomaly(
                    "Possible Port Scan",
                    f"Host {record.dst_ip} contacted on {unique_ports} different ports",
                    "WARNING",
                    record.src_ip,
                    {"target": record.dst_ip, "ports_count": unique_ports}
                )
        
        # 3. ICMP Flood
        if record.protocol in (Protocol.ICMP.value, Protocol.ICMPv6.value):
            self.anomaly_state['icmp_count'] += 1
            if self.anomaly_state['icmp_count'] > AnomalyThresholds.ICMP_BURST_THRESHOLD:
                self.add_anomaly(
                    "ICMP Flood",
                    f"High ICMP traffic: {self.anomaly_state['icmp_count']} packets",
                    "WARNING",
                    details={"icmp_count": self.anomaly_state['icmp_count']}
                )
        
        # 4. DNS Query Flood
        if record.protocol == Protocol.DNS.value and record.dns_query:
            self.anomaly_state['dns_per_host'][record.src_ip] += 1
            if self.anomaly_state['dns_per_host'][record.src_ip] > AnomalyThresholds.DNS_QUERY_BURST:
                self.add_anomaly(
                    "DNS Query Flood",
                    f"Host {record.src_ip} made {self.anomaly_state['dns_per_host'][record.src_ip]} DNS queries",
                    "INFO",
                    record.src_ip,
                    {"query_count": self.anomaly_state['dns_per_host'][record.src_ip]}
                )
        
        # 5. ARP Storm
        if record.protocol == Protocol.ARP.value:
            self.anomaly_state['arp_count'] += 1
            if self.anomaly_state['arp_count'] > AnomalyThresholds.ARP_STORM_THRESHOLD:
                self.add_anomaly(
                    "ARP Storm",
                    f"Excessive ARP traffic: {self.anomaly_state['arp_count']} packets",
                    "WARNING",
                    details={"arp_count": self.anomaly_state['arp_count']}
                )
        
        # 6. Large Packet (Fragmentation Attack / Jumbo Frame)
        if record.packet_length > AnomalyThresholds.LARGE_PACKET_SIZE:
            record.is_suspicious = True
            record.suspicious_reason = f"Unusually large packet ({record.packet_length} bytes)"
            self.add_anomaly(
                "Large Packet",
                f"Packet size {record.packet_length} bytes (>{AnomalyThresholds.LARGE_PACKET_SIZE})",
                "INFO",
                record.src_ip,
                {"size": record.packet_length}
            )
        
        # 7. Connection Threshold
        self.anomaly_state['connections_per_host'][record.dst_ip] += 1
        if self.anomaly_state['connections_per_host'][record.dst_ip] > AnomalyThresholds.CONNECTION_THRESHOLD:
            self.add_anomaly(
                "High Connection Count",
                f"Host {record.dst_ip} received {self.anomaly_state['connections_per_host'][record.dst_ip]} connections",
                "INFO",
                details={"target": record.dst_ip, "connection_count": self.anomaly_state['connections_per_host'][record.dst_ip]}
            )
    
    def add_anomaly(self, anomaly_type: str, description: str, severity: str, 
                    source: Optional[str] = None, details: Dict = None):
        """Add anomaly to report (deduplicates similar anomalies)."""
        # Simple deduplication: don't add if same type already reported recently
        if len(self.anomalies) > 0:
            last = self.anomalies[-1]
            if last.anomaly_type == anomaly_type and last.source == source:
                return  # Skip duplicate
        
        self.anomalies.append(AnomalyReport(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            anomaly_type=anomaly_type,
            description=description,
            severity=severity,
            source=source,
            details=details or {}
        ))
    
    # ========================================================================
    # FILTERING
    # ========================================================================
    
    def passes_filters(self, record: PacketRecord) -> bool:
        """Check if packet passes configured filters."""
        f = self.filters
        
        if f.protocol and record.protocol.upper() != f.protocol.upper():
            return False
        
        if f.src_ip and record.src_ip != f.src_ip:
            return False
        
        if f.dst_ip and record.dst_ip != f.dst_ip:
            return False
        
        if f.any_ip and f.any_ip not in (record.src_ip, record.dst_ip):
            return False
        
        if f.src_port and record.src_port != f.src_port:
            return False
        
        if f.dst_port and record.dst_port != f.dst_port:
            return False
        
        if f.any_port and f.any_port not in (record.src_port, record.dst_port):
            return False
        
        if f.service and record.service != f.service:
            return False
        
        return True
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def update_statistics(self, record: PacketRecord):
        """Incrementally update statistics (O(1) instead of O(n))."""
        self.stats['total_bytes'] += record.packet_length
        self.stats['protocol_counts'][record.protocol] += 1
        self.stats['protocol_bytes'][record.protocol] += record.packet_length
        self.stats['direction_counts'][record.direction] += 1
        
        if record.service:
            self.stats['service_counts'][record.service] += 1
        
        self.stats['unique_ips'].add(record.src_ip)
        self.stats['unique_ips'].add(record.dst_ip)
        self.stats['unique_src_ips'].add(record.src_ip)
        self.stats['unique_dst_ips'].add(record.dst_ip)
        
        if record.tcp_flags:
            self.stats['tcp_flags_counts'][record.tcp_flags] += 1
        
        if record.dns_query:
            self.stats['dns_queries'] += 1
        
        if record.protocol == Protocol.HTTP.value:
            self.stats['http_requests'] += 1
        
        if record.protocol == Protocol.HTTPS.value:
            self.stats['https_connections'] += 1
        
        # Timing
        if self.stats['start_time'] is None:
            self.stats['start_time'] = record.epoch_time
        self.stats['end_time'] = record.epoch_time
    
    # ========================================================================
    # DISPLAY
    # ========================================================================
    
    def print_packet(self, record: PacketRecord):
        """Pretty-print packet with color coding and alignment."""
        # Color by protocol
        proto_color = {
            Protocol.HTTP.value: Color.GREEN,
            Protocol.HTTPS.value: Color.CYAN,
            Protocol.DNS.value: Color.BLUE,
            Protocol.ICMP.value: Color.YELLOW,
            Protocol.ARP.value: Color.YELLOW,
        }.get(record.protocol, Color.END)
        
        sport = record.src_port if record.src_port else "-"
        dport = record.dst_port if record.dst_port else "-"
        
        # Main line
        line = (
            f"{Color.BOLD}[{record.timestamp}]{Color.END} "
            f"{record.src_ip:>15}:{sport:<5} → {record.dst_ip:>15}:{dport:<5} | "
            f"{proto_color}{record.protocol:<6}{Color.END} | "
            f"Len:{record.packet_length:<5} | "
            f"TTL:{str(record.ttl):<3} | "
            f"{record.direction}"
        )
        
        if record.service:
            line += f" | {Color.CYAN}{record.service}{Color.END}"
        
        print(line)
        
        # Protocol-specific details
        if record.tcp_flags:
            print(f"      TCP Flags: {record.tcp_flags}  |  "
                  f"Seq: {record.seq_num}  |  Ack: {record.ack_num}  |  "
                  f"Win: {record.window_size}")
        
        if record.dns_query:
            response = record.dns_response or "(no answer)"
            print(f"      {Color.BLUE}DNS Query:{Color.END} {record.dns_query} ({record.dns_type})  →  {response}")
        
        if record.is_suspicious:
            print(f"      {Color.RED}⚠ SUSPICIOUS: {record.suspicious_reason}{Color.END}")
        
        if record.src_mac and record.dst_mac:
            print(f"      MAC: {record.src_mac} → {record.dst_mac}")
    
    def show_live_statistics(self):
        """Display real-time statistics during capture."""
        if not self.show_live_stats:
            return
        
        if self.packets_processed % 20 == 0:  # Update every 20 packets
            print(f"\n{Color.CYAN}--- Live Stats: {self.stats['total_packets']} total, "
                  f"{self.stats['filtered_packets']} shown, "
                  f"{len(self.flows)} flows ---{Color.END}")
    
    # ========================================================================
    # CORE PACKET HANDLER
    # ========================================================================
    
    def handle_packet(self, packet):
        """
        Main packet processing pipeline (used for both live and pcap).
        
        Pipeline:
        1. Build packet record
        2. Apply filters
        3. Update statistics
        4. Update flow tracking
        5. Detect anomalies
        6. Store packet (if memory allows)
        7. Display packet
        """
        record = self.build_packet_record(packet)
        if not record:
            return
        
        self.stats['total_packets'] += 1
        self.packets_processed += 1
        
        # Filter check
        if not self.passes_filters(record):
            return
        
        self.stats['filtered_packets'] += 1
        
        # Update statistics
        self.update_statistics(record)
        
        # Flow tracking
        self.update_flow(record)
        
        # Anomaly detection
        self.detect_anomalies(record)
        
        # Memory management
        if len(self.packets) >= MAX_PACKETS_IN_MEMORY:
            if not self.summary_only_mode:
                print(f"\n{Color.YELLOW}[!] Packet limit reached ({MAX_PACKETS_IN_MEMORY}). "
                      f"Switching to summary-only mode.{Color.END}\n")
                self.summary_only_mode = True
        
        # Store packet
        if not self.summary_only_mode:
            self.packets.append(record)
        
        # Display
        self.print_packet(record)
        self.show_live_statistics()
    
    # ========================================================================
    # FEATURE 1: LIVE CAPTURE
    # ========================================================================
    
    def choose_interface(self) -> Optional[str]:
        """Interactive interface selection."""
        try:
            interfaces = get_if_list()
        except Exception as e:
            print(f"{Color.YELLOW}[!] Could not list interfaces: {e}{Color.END}")
            return None
        
        if not interfaces:
            return None
        
        print(f"\n{Color.CYAN}Available Network Interfaces:{Color.END}")
        for idx, iface in enumerate(interfaces, 1):
            marker = "✓" if iface == conf.iface else " "
            print(f"  {marker} {idx}. {iface}")
        print(f"    0. Use default ({conf.iface})")
        
        choice = input(f"\n{Color.BOLD}Select interface [0-{len(interfaces)}]:{Color.END} ").strip()
        
        if not choice or choice == "0":
            return None
        
        try:
            return interfaces[int(choice) - 1]
        except (ValueError, IndexError):
            print(f"{Color.YELLOW}[!] Invalid selection, using default.{Color.END}")
            return None
    
    def capture_live(self):
        """Live packet capture with interface selection and real-time analysis."""
        try:
            iface = self.choose_interface()
            
            count_input = input(f"{Color.BOLD}Number of packets to capture (0 = unlimited):{Color.END} ").strip()
            packet_count = int(count_input)
            
            if packet_count < 0:
                print(f"{Color.RED}[!] Invalid count.{Color.END}")
                return
            
            live_stats_input = input(f"{Color.BOLD}Show live statistics? (y/n):{Color.END} ").strip().lower()
            self.show_live_stats = live_stats_input == 'y'
            
            print(f"\n{Color.GREEN}[*] Starting live capture...{Color.END}")
            print(f"[*] Interface: {iface or conf.iface}")
            print(f"[*] Count: {'unlimited' if packet_count == 0 else packet_count}")
            if self.filters.is_active():
                print(f"[*] Filters: {self.filters}")
            print(f"{Color.YELLOW}[*] Press Ctrl+C to stop{Color.END}\n")
            
            # Build BPF filter for kernel-level filtering (performance optimization)
            bpf_filter = self.build_bpf_filter()
            
            if packet_count == 0:
                sniff(prn=self.handle_packet, iface=iface, filter=bpf_filter, store=False)
            else:
                sniff(count=packet_count, prn=self.handle_packet, iface=iface, filter=bpf_filter, store=False)
            
            print(f"\n{Color.GREEN}[*] Capture complete.{Color.END}")
            self.show_capture_summary()
            
        except ValueError:
            print(f"{Color.RED}[ERROR] Invalid input.{Color.END}")
        except PermissionError:
            print(f"{Color.RED}[ERROR] Permission denied. Run as administrator/root.{Color.END}")
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[*] Capture stopped by user.{Color.END}")
            self.show_capture_summary()
        except Exception as e:
            print(f"{Color.RED}[ERROR] Capture failed: {e}{Color.END}")
    
    def build_bpf_filter(self) -> str:
        """
        Build Berkeley Packet Filter expression from current filters.
        
        BPF filtering happens in the kernel BEFORE packets reach Python,
        dramatically improving performance for filtered captures.
        """
        parts = []
        
        if self.filters.protocol:
            proto = self.filters.protocol.lower()
            if proto in ("tcp", "udp", "icmp"):
                parts.append(proto)
        
        if self.filters.any_ip:
            parts.append(f"host {self.filters.any_ip}")
        elif self.filters.src_ip or self.filters.dst_ip:
            if self.filters.src_ip:
                parts.append(f"src host {self.filters.src_ip}")
            if self.filters.dst_ip:
                parts.append(f"dst host {self.filters.dst_ip}")
        
        if self.filters.any_port:
            parts.append(f"port {self.filters.any_port}")
        elif self.filters.src_port or self.filters.dst_port:
            if self.filters.src_port:
                parts.append(f"src port {self.filters.src_port}")
            if self.filters.dst_port:
                parts.append(f"dst port {self.filters.dst_port}")
        
        return " and ".join(parts) if parts else ""
    
    # ========================================================================
    # FEATURE 2: PCAP ANALYSIS
    # ========================================================================
    
    def analyze_pcap(self):
        """Analyze existing PCAP file with streaming reader."""
        try:
            file_path = input(f"{Color.BOLD}Enter PCAP file path:{Color.END} ").strip()
            
            print(f"\n{Color.GREEN}[*] Analyzing: {file_path}{Color.END}")
            if self.filters.is_active():
                print(f"[*] Filters: {self.filters}")
            print()
            
            with PcapReader(file_path) as reader:
                for packet in reader:
                    self.handle_packet(packet)
            
            print(f"\n{Color.GREEN}[*] Analysis complete.{Color.END}")
            self.show_capture_summary()
            
        except FileNotFoundError:
            print(f"{Color.RED}[ERROR] File not found.{Color.END}")
        except Scapy_Exception as e:
            print(f"{Color.RED}[ERROR] Invalid PCAP file: {e}{Color.END}")
        except Exception as e:
            print(f"{Color.RED}[ERROR] Analysis failed: {e}{Color.END}")
    
    # ========================================================================
    # FEATURE 3: STATISTICS & REPORTING
    # ========================================================================
    
    def show_capture_summary(self):
        """Comprehensive post-capture summary report."""
        if self.stats['total_packets'] == 0:
            print(f"{Color.YELLOW}[!] No packets captured.{Color.END}")
            return
        
        duration = (self.stats['end_time'] - self.stats['start_time']) if self.stats['start_time'] else 0
        
        print(f"\n{Color.CYAN}{'='*70}")
        print(f"{Color.BOLD}CAPTURE SUMMARY{Color.END}")
        print(f"{Color.CYAN}{'='*70}{Color.END}\n")
        
        # Basic metrics
        print(f"{Color.BOLD}Overall Statistics:{Color.END}")
        print(f"  Packets Captured      : {self.stats['total_packets']:,}")
        print(f"  Packets Displayed     : {self.stats['filtered_packets']:,}")
        print(f"  Capture Duration      : {duration:.2f} seconds")
        if duration > 0:
            print(f"  Packet Rate           : {self.stats['total_packets']/duration:.1f} packets/sec")
        print(f"  Total Bytes           : {self.stats['total_bytes']:,} ({self.format_bytes(self.stats['total_bytes'])})")
        print(f"  Average Packet Size   : {self.stats['total_bytes']/self.stats['total_packets']:.1f} bytes")
        
        # Unique hosts
        print(f"\n{Color.BOLD}Network Overview:{Color.END}")
        print(f"  Unique IP Addresses   : {len(self.stats['unique_ips'])}")
        print(f"  Unique Source IPs     : {len(self.stats['unique_src_ips'])}")
        print(f"  Unique Dest IPs       : {len(self.stats['unique_dst_ips'])}")
        print(f"  Active Flows          : {len(self.flows)}")
        
        # Traffic direction
        print(f"\n{Color.BOLD}Traffic Direction:{Color.END}")
        for direction, count in self.stats['direction_counts'].most_common():
            pct = count / self.stats['filtered_packets'] * 100
            print(f"  {direction:<12} : {count:>6,} ({pct:>5.1f}%)")
        
        # Protocol distribution by packet count
        print(f"\n{Color.BOLD}Protocol Distribution (by packets):{Color.END}")
        for proto, count in self.stats['protocol_counts'].most_common(10):
            pct = count / self.stats['filtered_packets'] * 100
            print(f"  {proto:<12} : {count:>6,} ({pct:>5.1f}%)")
        
        # Protocol distribution by bytes
        print(f"\n{Color.BOLD}Protocol Distribution (by bytes):{Color.END}")
        for proto, bytes_count in self.stats['protocol_bytes'].most_common(10):
            pct = bytes_count / self.stats['total_bytes'] * 100
            print(f"  {proto:<12} : {self.format_bytes(bytes_count):>10} ({pct:>5.1f}%)")
        
        # Top services
        if self.stats['service_counts']:
            print(f"\n{Color.BOLD}Top Services:{Color.END}")
            for service, count in self.stats['service_counts'].most_common(10):
                print(f"  {service:<15} : {count:>6,} packets")
        
        # Top talkers
        src_counter = Counter()
        dst_counter = Counter()
        for pkt in self.packets:
            src_counter[pkt.src_ip] += 1
            dst_counter[pkt.dst_ip] += 1
        
        print(f"\n{Color.BOLD}Top Source IPs:{Color.END}")
        for ip, count in src_counter.most_common(5):
            print(f"  {ip:<20} : {count:>6,} packets")
        
        print(f"\n{Color.BOLD}Top Destination IPs:{Color.END}")
        for ip, count in dst_counter.most_common(5):
            print(f"  {ip:<20} : {count:>6,} packets")
        
        # TCP specifics
        if self.stats['tcp_flags_counts']:
            print(f"\n{Color.BOLD}TCP Flags Distribution:{Color.END}")
            for flags, count in self.stats['tcp_flags_counts'].most_common(5):
                print(f"  {flags:<10} : {count:>6,}")
        
        # Application layer stats
        print(f"\n{Color.BOLD}Application Layer:{Color.END}")
        print(f"  DNS Queries           : {self.stats['dns_queries']:,}")
        print(f"  HTTP Requests         : {self.stats['http_requests']:,}")
        print(f"  HTTPS Connections     : {self.stats['https_connections']:,}")
        
        print(f"\n{Color.CYAN}{'='*70}{Color.END}\n")
        
        # Anomaly report
        if self.anomalies:
            self.show_anomaly_report()
    
    def show_flow_analysis(self):
        """Display detailed flow statistics."""
        if not self.flows:
            print(f"{Color.YELLOW}[!] No flows tracked.{Color.END}")
            return
        
        print(f"\n{Color.CYAN}{'='*70}")
        print(f"{Color.BOLD}FLOW ANALYSIS{Color.END}")
        print(f"{Color.CYAN}{'='*70}{Color.END}\n")
        
        print(f"Total Flows: {len(self.flows)}\n")
        
        # Sort by total bytes (largest flows first)
        sorted_flows = sorted(self.flows.values(), key=lambda f: f.total_bytes, reverse=True)
        
        print(f"{Color.BOLD}Top 10 Flows by Data Volume:{Color.END}\n")
        print(f"{'Source':<20} {'Dest':<20} {'Proto':<6} {'Packets':<8} {'Bytes':<12} {'Duration':<10}")
        print("-" * 90)
        
        for flow in sorted_flows[:10]:
            src = f"{flow.src_ip}:{flow.src_port or '-'}"
            dst = f"{flow.dst_ip}:{flow.dst_port or '-'}"
            print(f"{src:<20} {dst:<20} {flow.protocol:<6} "
                  f"{flow.total_packets:<8} {self.format_bytes(flow.total_bytes):<12} "
                  f"{flow.duration:.2f}s")
        
        # TCP connection analysis
        tcp_flows = [f for f in self.flows.values() if f.protocol == Protocol.TCP.value]
        if tcp_flows:
            print(f"\n{Color.BOLD}TCP Connection States:{Color.END}")
            established = sum(1 for f in tcp_flows if f.is_established)
            half_open = sum(1 for f in tcp_flows if f.is_half_open)
            with_fin = sum(1 for f in tcp_flows if f.fin_seen)
            with_rst = sum(1 for f in tcp_flows if f.rst_seen)
            
            print(f"  Established (full 3-way handshake) : {established}")
            print(f"  Half-Open (SYN without SYN-ACK)     : {half_open}")
            print(f"  With FIN flag (graceful close)      : {with_fin}")
            print(f"  With RST flag (abrupt close)        : {with_rst}")
        
        print(f"\n{Color.CYAN}{'='*70}{Color.END}\n")
    
    def show_anomaly_report(self):
        """Display detected anomalies with severity color coding."""
        if not self.anomalies:
            return
        
        print(f"\n{Color.RED}{'='*70}")
        print(f"{Color.BOLD}⚠  ANOMALY REPORT (Heuristic Observations){Color.END}")
        print(f"{Color.RED}{'='*70}{Color.END}\n")
        
        print(f"{Color.YELLOW}NOTE: These are automated observations, NOT confirmed attacks.{Color.END}")
        print(f"{Color.YELLOW}Further investigation is required for validation.{Color.END}\n")
        
        severity_colors = {
            "INFO": Color.CYAN,
            "WARNING": Color.YELLOW,
            "CRITICAL": Color.RED
        }
        
        for anomaly in self.anomalies:
            color = severity_colors.get(anomaly.severity, Color.END)
            print(f"{color}[{anomaly.severity}]{Color.END} {Color.BOLD}{anomaly.anomaly_type}{Color.END}")
            print(f"  Time: {anomaly.timestamp}")
            if anomaly.source:
                print(f"  Source: {anomaly.source}")
            print(f"  Description: {anomaly.description}")
            if anomaly.details:
                print(f"  Details: {anomaly.details}")
            print()
        
        print(f"{Color.RED}{'='*70}{Color.END}\n")
    
    @staticmethod
    def format_bytes(num_bytes: int) -> str:
        """Human-readable byte formatting."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} TB"
    
    # ========================================================================
    # FEATURE 4: CSV EXPORT
    # ========================================================================
    
    def export_packets_csv(self):
        """Export packet records to CSV."""
        if not self.packets:
            print(f"{Color.YELLOW}[!] No packet data to export.{Color.END}")
            return
        
        try:
            filename = input(f"{Color.BOLD}Enter filename (default: packets.csv):{Color.END} ").strip()
            filename = filename or "packets.csv"
            if not filename.endswith('.csv'):
                filename += '.csv'
            
            with open(filename, 'w', newline='') as f:
                # Custom field order for better readability
                fields = [
                    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'protocol', 'service', 'direction', 'packet_length', 'payload_length',
                    'ttl', 'tcp_flags', 'seq_num', 'ack_num', 'window_size',
                    'src_mac', 'dst_mac', 'dns_query', 'dns_type', 'dns_response',
                    'is_suspicious', 'suspicious_reason'
                ]
                
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                
                for record in self.packets:
                    writer.writerow(asdict(record))
            
            print(f"{Color.GREEN}[*] Exported {len(self.packets)} packets to {filename}{Color.END}")
            
        except Exception as e:
            print(f"{Color.RED}[ERROR] Export failed: {e}{Color.END}")
    
    def export_flows_csv(self):
        """Export flow records to CSV."""
        if not self.flows:
            print(f"{Color.YELLOW}[!] No flow data to export.{Color.END}")
            return
        
        try:
            filename = input(f"{Color.BOLD}Enter filename (default: flows.csv):{Color.END} ").strip()
            filename = filename or "flows.csv"
            if not filename.endswith('.csv'):
                filename += '.csv'
            
            with open(filename, 'w', newline='') as f:
                fields = [
                    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                    'packets_sent', 'packets_recv', 'total_packets',
                    'bytes_sent', 'bytes_recv', 'total_bytes',
                    'duration', 'avg_packet_size',
                    'syn_seen', 'syn_ack_seen', 'ack_seen', 'fin_seen', 'rst_seen',
                    'is_established', 'is_half_open'
                ]
                
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for flow in self.flows.values():
                    row = asdict(flow)
                    row['total_packets'] = flow.total_packets
                    row['total_bytes'] = flow.total_bytes
                    row['duration'] = flow.duration
                    row['avg_packet_size'] = flow.avg_packet_size
                    row['is_established'] = flow.is_established
                    row['is_half_open'] = flow.is_half_open
                    writer.writerow(row)
            
            print(f"{Color.GREEN}[*] Exported {len(self.flows)} flows to {filename}{Color.END}")
            
        except Exception as e:
            print(f"{Color.RED}[ERROR] Export failed: {e}{Color.END}")
    
    def export_anomalies_csv(self):
        """Export anomaly reports to CSV."""
        if not self.anomalies:
            print(f"{Color.YELLOW}[!] No anomalies to export.{Color.END}")
            return
        
        try:
            filename = input(f"{Color.BOLD}Enter filename (default: anomalies.csv):{Color.END} ").strip()
            filename = filename or "anomalies.csv"
            if not filename.endswith('.csv'):
                filename += '.csv'
            
            with open(filename, 'w', newline='') as f:
                fields = ['timestamp', 'severity', 'anomaly_type', 'description', 'source', 'details']
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for anomaly in self.anomalies:
                    row = asdict(anomaly)
                    row['details'] = str(row['details'])  # Convert dict to string
                    writer.writerow(row)
            
            print(f"{Color.GREEN}[*] Exported {len(self.anomalies)} anomalies to {filename}{Color.END}")
            
        except Exception as e:
            print(f"{Color.RED}[ERROR] Export failed: {e}{Color.END}")
    
    # ========================================================================
    # FEATURE 5: FILTER CONFIGURATION
    # ========================================================================
    
    def configure_filters(self):
        """Interactive filter configuration."""
        print(f"\n{Color.CYAN}{'='*70}")
        print(f"{Color.BOLD}FILTER CONFIGURATION{Color.END}")
        print(f"{Color.CYAN}{'='*70}{Color.END}\n")
        
        print("Leave blank to clear a filter.\n")
        
        # Protocol
        print(f"{Color.BOLD}Protocol Options:{Color.END} TCP, UDP, ICMP, DNS, ARP, HTTP, HTTPS, DHCP, SSH, FTP, SMTP")
        proto = input(f"Protocol [{self.filters.protocol or 'none'}]: ").strip().upper()
        self.filters.protocol = proto or None
        
        # IPs
        print(f"\n{Color.BOLD}IP Filters:{Color.END}")
        src_ip = input(f"Source IP [{self.filters.src_ip or 'none'}]: ").strip()
        self.filters.src_ip = src_ip or None
        
        dst_ip = input(f"Destination IP [{self.filters.dst_ip or 'none'}]: ").strip()
        self.filters.dst_ip = dst_ip or None
        
        any_ip = input(f"Any IP (source OR destination) [{self.filters.any_ip or 'none'}]: ").strip()
        self.filters.any_ip = any_ip or None
        
        # Ports
        print(f"\n{Color.BOLD}Port Filters:{Color.END}")
        try:
            src_port = input(f"Source Port [{self.filters.src_port or 'none'}]: ").strip()
            self.filters.src_port = int(src_port) if src_port else None
        except ValueError:
            print(f"{Color.YELLOW}[!] Invalid port, ignoring.{Color.END}")
            self.filters.src_port = None
        
        try:
            dst_port = input(f"Destination Port [{self.filters.dst_port or 'none'}]: ").strip()
            self.filters.dst_port = int(dst_port) if dst_port else None
        except ValueError:
            print(f"{Color.YELLOW}[!] Invalid port, ignoring.{Color.END}")
            self.filters.dst_port = None
        
        try:
            any_port = input(f"Any Port (source OR destination) [{self.filters.any_port or 'none'}]: ").strip()
            self.filters.any_port = int(any_port) if any_port else None
        except ValueError:
            print(f"{Color.YELLOW}[!] Invalid port, ignoring.{Color.END}")
            self.filters.any_port = None
        
        # Service
        print(f"\n{Color.BOLD}Service Filter:{Color.END} e.g., SSH, HTTP, HTTPS, DNS, MySQL")
        service = input(f"Service [{self.filters.service or 'none'}]: ").strip()
        self.filters.service = service or None
        
        # Summary
        print(f"\n{Color.GREEN}[*] Filters updated:{Color.END}")
        if self.filters.is_active():
            print(f"    {self.filters}")
        else:
            print("    All filters cleared")
        print()
    
    # ========================================================================
    # MENU & MAIN LOOP
    # ========================================================================
    
    @staticmethod
    def print_menu():
        """Display main menu with color coding."""
        print(f"\n{Color.CYAN}{'='*70}")
        print(f"{Color.BOLD}ADVANCED NETWORK TRAFFIC ANALYZER{Color.END}")
        print(f"{Color.CYAN}{'='*70}{Color.END}\n")
        print(f"  {Color.BOLD}1.{Color.END} Capture Live Packets")
        print(f"  {Color.BOLD}2.{Color.END} Analyze PCAP File")
        print(f"  {Color.BOLD}3.{Color.END} Show Capture Summary")
        print(f"  {Color.BOLD}4.{Color.END} Show Flow Analysis")
        print(f"  {Color.BOLD}5.{Color.END} Show Anomaly Report")
        print(f"  {Color.BOLD}6.{Color.END} Export Packets to CSV")
        print(f"  {Color.BOLD}7.{Color.END} Export Flows to CSV")
        print(f"  {Color.BOLD}8.{Color.END} Export Anomalies to CSV")
        print(f"  {Color.BOLD}9.{Color.END} Configure Filters")
        print(f"  {Color.BOLD}0.{Color.END} Exit")
        print(f"\n{Color.CYAN}{'='*70}{Color.END}")
    
    def run(self):
        """Main application loop."""
        print(f"\n{Color.GREEN}{'='*70}")
        print(f"{Color.BOLD}Advanced Network Traffic Analyzer v2.0{Color.END}")
        print(f"{Color.GREEN}{'='*70}{Color.END}")
        print(f"\n{Color.YELLOW}Educational cybersecurity tool for packet analysis and flow tracking.{Color.END}")
        print(f"{Color.YELLOW}Heuristic anomaly detection included (not a production IDS).{Color.END}\n")
        
        while True:
            self.print_menu()
            choice = input(f"\n{Color.BOLD}Enter choice [0-9]:{Color.END} ").strip()
            
            if choice == '1':
                self.capture_live()
            elif choice == '2':
                self.analyze_pcap()
            elif choice == '3':
                self.show_capture_summary()
            elif choice == '4':
                self.show_flow_analysis()
            elif choice == '5':
                self.show_anomaly_report()
            elif choice == '6':
                self.export_packets_csv()
            elif choice == '7':
                self.export_flows_csv()
            elif choice == '8':
                self.export_anomalies_csv()
            elif choice == '9':
                self.configure_filters()
            elif choice == '0':
                print(f"\n{Color.GREEN}[*] Exiting. Goodbye!{Color.END}\n")
                sys.exit(0)
            else:
                print(f"{Color.RED}[!] Invalid choice. Please enter 0-9.{Color.END}")

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        AdvancedNetworkAnalyzer().run()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}[*] Program interrupted. Exiting safely.{Color.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Color.RED}[FATAL ERROR] {e}{Color.END}\n")
        sys.exit(1)