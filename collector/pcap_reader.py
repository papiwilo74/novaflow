"""
NovaFlow NDR - Standalone Pure-Python PCAP / PCAPNG Reader
Lee y extrae datagramas binarios desde capturas de red estándar de Wireshark/tcpdump
sin dependencias externas (usa struct para parsear la cabecera global y bloques de paquetes).
"""

import struct
from typing import Generator, Tuple, Optional


class PcapReader:
    """
    Lector nativo de archivos .pcap (formato clásico libpcap / tcpdump).
    Permite reproducir paquetes UDP capturados en tráfico de red real.
    """

    # Global Header PCAP (24 bytes)
    # magic_number (4B), version_major (2B), version_minor (2B), thiszone (4B), sigfigs (4B), snaplen (4B), network (4B)
    PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
    PCAP_MAGIC_NANOSECONDS = 0xA1B23C4D
    PCAP_MAGIC_MODIFIED = 0xA1B2CD34

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.endian = "<"  # Default little-endian
        self.snaplen = 65535
        self.network_link_type = 1  # 1 = Ethernet

    def __iter__(self) -> Generator[Tuple[float, bytes], None, None]:
        with open(self.filepath, "rb") as f:
            header_bytes = f.read(24)
            if len(header_bytes) < 24:
                raise ValueError("Archivo PCAP corrupto o demasiado corto para cabecera global (24 bytes).")

            magic = struct.unpack("<I", header_bytes[:4])[0]
            if magic in (self.PCAP_MAGIC_MICROSECONDS, self.PCAP_MAGIC_NANOSECONDS, self.PCAP_MAGIC_MODIFIED):
                self.endian = "<"
            else:
                magic_be = struct.unpack(">I", header_bytes[:4])[0]
                if magic_be in (self.PCAP_MAGIC_MICROSECONDS, self.PCAP_MAGIC_NANOSECONDS, self.PCAP_MAGIC_MODIFIED):
                    self.endian = ">"
                else:
                    raise ValueError(f"Firma mágica PCAP inválida: 0x{magic:08X}")

            _, _, _, _, self.snaplen, self.network_link_type = struct.unpack(
                f"{self.endian}HHIIII", header_bytes[4:]
            )

            # Iterar sobre cada paquete (Packet Header = 16 bytes: ts_sec, ts_usec, incl_len, orig_len)
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self.endian}IIII", pkt_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                timestamp = ts_sec + (ts_usec / 1_000_000.0)
                yield (timestamp, pkt_data)

    @staticmethod
    def extract_udp_payload(raw_packet: bytes, target_port: Optional[int] = 2055) -> Optional[bytes]:
        """
        Desempaqueta capas Ethernet (14B) e IPv4 (20B) para extraer el payload UDP del puerto especificado
        (o cualquier payload UDP si target_port es None).
        """
        # 1. Validar capa Ethernet (14 bytes mínimo)
        if len(raw_packet) < 14 + 20 + 8:
            return None

        eth_type = struct.unpack("!H", raw_packet[12:14])[0]
        offset = 14

        # Manejo de VLAN 802.1Q (4 bytes adicionales)
        if eth_type == 0x8100:
            offset += 4
            eth_type = struct.unpack("!H", raw_packet[offset - 2:offset])[0]

        # Solo IPv4 (0x0800)
        if eth_type != 0x0800:
            return None

        # 2. Capa IPv4
        ip_header_first_byte = raw_packet[offset]
        ihl = (ip_header_first_byte & 0x0F) * 4
        protocol = raw_packet[offset + 9]

        if protocol != 17:  # 17 = UDP
            return None

        udp_offset = offset + ihl
        if len(raw_packet) < udp_offset + 8:
            return None

        # 3. Capa UDP (8 bytes)
        src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", raw_packet[udp_offset:udp_offset + 8])

        if target_port is None or dst_port == target_port or src_port == target_port:
            payload = raw_packet[udp_offset + 8:udp_offset + udp_len]
            return payload

        return None


class PcapWriter:
    """Utilidad para generar capturas PCAP sintéticas de prueba válidas en Wireshark."""

    @staticmethod
    def create_pcap(filepath: str, udp_packets: list):
        """
        Escribe un archivo PCAP válido con tramas Ethernet/IPv4/UDP.
        udp_packets es una lista de tuplas: (timestamp, src_ip_str, dst_ip_str, src_port, dst_port, payload_bytes)
        """
        import socket

        with open(filepath, "wb") as f:
            # Global Header: magic 0xA1B2C3D4 (microsec), v2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

            for ts, src_ip, dst_ip, s_port, d_port, payload in udp_packets:
                ts_sec = int(ts)
                ts_usec = int((ts - ts_sec) * 1_000_000)

                # Capa Ethernet (14B)
                eth = b"\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00"

                # Capa IPv4 (20B)
                src_bin = socket.inet_aton(src_ip)
                dst_bin = socket.inet_aton(dst_ip)
                total_ip_len = 20 + 8 + len(payload)
                ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_ip_len, 54321, 0, 64, 17, 0, src_bin, dst_bin)

                # Capa UDP (8B)
                udp_hdr = struct.pack("!HHHH", s_port, d_port, 8 + len(payload), 0)

                frame = eth + ip_hdr + udp_hdr + payload
                incl_len = len(frame)

                # Packet Header (16B)
                pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, incl_len)
                f.write(pkt_hdr)
                f.write(frame)
