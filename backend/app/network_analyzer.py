
from collections import defaultdict
from datetime import datetime, timezone
from io import BytesIO

from scapy.all import IP, IPv6, TCP, UDP, rdpcap


def analyze_pcap(file_content: bytes) -> list[dict]:
    """Extract bidirectional TCP and UDP network-flow metadata."""

    if not file_content:
        raise ValueError("The uploaded PCAP file is empty.")

    packets = rdpcap(BytesIO(file_content))

    flows = defaultdict(
        lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": None,
            "end_time": None,
            "tcp_flags": set(),
        }
    )

    for packet in packets:
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
        else:
            continue

        if TCP in packet:
            protocol = "TCP"
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
            tcp_flags = str(packet[TCP].flags)
        elif UDP in packet:
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)
            tcp_flags = None
        else:
            continue

        forward_key = (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
        )

        reverse_key = (
            destination_ip,
            source_ip,
            destination_port,
            source_port,
            protocol,
        )

        flow_key = min(forward_key, reverse_key)

        flow = flows[flow_key]

        packet_time = datetime.fromtimestamp(
            float(packet.time),
            tz=timezone.utc,
        )

        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)

        if flow["start_time"] is None:
            flow["start_time"] = packet_time

        flow["end_time"] = packet_time

        if tcp_flags:
            flow["tcp_flags"].add(tcp_flags)

    results = []

    for key, flow in flows.items():
        source_ip, destination_ip, source_port, destination_port, protocol = key

        start_time = flow["start_time"]
        end_time = flow["end_time"]

        results.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": (end_time - start_time).total_seconds(),
            "tcp_flags": (
                ",".join(sorted(flow["tcp_flags"]))
                if flow["tcp_flags"] else None
            ),
        })

    return results
