from io import BytesIO

from scapy.utils import RawPcapReader


MAX_PCAP_SIZE = 10 * 1024 * 1024
MAX_PACKET_COUNT = 50_000


def validate_pcap(file_content: bytes) -> dict:
    """Validate PCAP size, format, and packet count."""

    if not file_content:
        raise ValueError("The uploaded PCAP file is empty.")

    if len(file_content) > MAX_PCAP_SIZE:
        raise ValueError("PCAP file exceeds the 10 MB upload limit.")

    packet_count = 0

    try:
        reader = RawPcapReader(BytesIO(file_content))

        try:
            for _ in reader:
                packet_count += 1

                if packet_count > MAX_PACKET_COUNT:
                    raise ValueError(
                        "PCAP exceeds the 50,000 packet limit."
                    )
        finally:
            reader.close()

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(
            "Invalid or unsupported PCAP file."
        ) from exc

    if packet_count == 0:
        raise ValueError("PCAP file contains no packets.")

    return {
        "valid": True,
        "file_size_bytes": len(file_content),
        "packet_count": packet_count,
        "message": "PCAP validation successful.",
    }
