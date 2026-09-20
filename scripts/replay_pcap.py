"""
NovaFlow NDR - PCAP Replay Utility
Reproduce capturas de red reales de Wireshark (.pcap) inyectando datagramas UDP NetFlow
hacia el colector local (udp://127.0.0.1:2055) respetando la tasa y offsets temporales.
"""

import argparse
import socket
import sys
import time
from typing import Optional

from collector.pcap_reader import PcapReader
from collector.parser import NetFlowParser


def replay_pcap(
    pcap_path: str,
    target_host: str = "127.0.0.1",
    target_port: int = 2055,
    filter_pcap_port: Optional[int] = 2055,
    realtime: bool = False,
    max_packets: Optional[int] = None,
) -> dict:
    """
    Lee un archivo PCAP y envía cada datagrama UDP correspondiente al puerto NetFlow.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reader = PcapReader(pcap_path)

    packets_read = 0
    netflow_packets_sent = 0
    total_flows_unpacked = 0
    bytes_sent = 0
    start_wall_time = time.time()
    first_pcap_ts = None

    print(f"[*] Iniciando reproduccion PCAP desde: {pcap_path}")
    print(f"[*] Destino: udp://{target_host}:{target_port}")

    for ts, raw_pkt in reader:
        packets_read += 1
        payload = PcapReader.extract_udp_payload(raw_pkt, target_port=filter_pcap_port)

        if not payload:
            continue

        # Validar consistencia con NetFlow v5
        header, records = NetFlowParser.parse_packet(payload)
        if header and header.version == 5:
            total_flows_unpacked += len(records)

        # Control de timing si se pide reproduccion a velocidad real
        if realtime:
            if first_pcap_ts is None:
                first_pcap_ts = ts
            else:
                elapsed_pcap = ts - first_pcap_ts
                elapsed_wall = time.time() - start_wall_time
                wait_time = elapsed_pcap - elapsed_wall
                if wait_time > 0:
                    time.sleep(min(wait_time, 2.0))

        sock.sendto(payload, (target_host, target_port))
        netflow_packets_sent += 1
        bytes_sent += len(payload)

        if max_packets and netflow_packets_sent >= max_packets:
            break

    sock.close()
    duration = max(0.001, time.time() - start_wall_time)

    stats = {
        "packets_read_from_pcap": packets_read,
        "netflow_datagrams_sent": netflow_packets_sent,
        "total_flows_identified": total_flows_unpacked,
        "bytes_sent": bytes_sent,
        "duration_seconds": round(duration, 3),
        "rate_pps": round(netflow_packets_sent / duration, 1),
    }

    print("[OK] Reproduccion PCAP finalizada exitosamente:")
    print(f"     - Paquetes totales en PCAP : {stats['packets_read_from_pcap']}")
    print(f"     - Datagramas NetFlow UDP   : {stats['netflow_datagrams_sent']}")
    print(f"     - Flujos NetFlow evaluados : {stats['total_flows_identified']}")
    print(f"     - Bytes transmitidos       : {stats['bytes_sent']} bytes")
    print(f"     - Tiempo transcurrido      : {stats['duration_seconds']}s ({stats['rate_pps']} pkts/s)")

    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NovaFlow PCAP Replay Tool")
    parser.add_argument("pcap_file", help="Ruta al archivo .pcap")
    parser.add_argument("--host", default="127.0.0.1", help="Host destino (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2055, help="Puerto UDP destino (default: 2055)")
    parser.add_argument("--realtime", action="store_true", help="Respetar delays entre paquetes originales")
    parser.add_argument("--limit", type=int, default=None, help="Maximo de paquetes a enviar")

    args = parser.parse_args()
    replay_pcap(
        args.pcap_file,
        target_host=args.host,
        target_port=args.port,
        realtime=args.realtime,
        max_packets=args.limit,
    )
