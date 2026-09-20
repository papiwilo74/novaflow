"""
NovaFlow NDR - Synthetic Enterprise Traffic Generator & Benchmark CLI
Herramienta de simulación de tráfico benigno y adversarial para pruebas de rendimiento,
estrés de throughput y validación de detección en vivo.
"""

import argparse
import random
import socket
import os
import struct
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Asegurar que la raíz del repositorio esté en sys.path al ejecutar como script
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from collector.parser import NetFlowRecord


def build_netflow_v5_packet(flows: List[NetFlowRecord], sys_uptime_ms: int = 1000000) -> bytes:
    """
    Empaqueta una lista de hasta 30 NetFlowRecord en un datagrama binario NetFlow v5 estándar (RFC Cisco).
    Cabecera global de 24 bytes + N registros de 48 bytes.
    """
    count = min(len(flows), 30)
    now_ts = int(time.time())
    now_ns = int((time.time() - now_ts) * 1e9)

    # Cabecera NetFlow v5 (24 bytes): !HHIIIIBBH
    header = struct.pack(
        "!HHIIIIBBH",
        5,                  # Version 5
        count,              # Count
        sys_uptime_ms,      # sys_uptime_ms
        now_ts,             # unix_secs
        now_ns,             # unix_nsecs
        1,                  # flow_sequence
        0,                  # engine_type
        0,                  # engine_id
        0,                  # sampling_interval
    )

    records_bytes = bytearray()
    for f in flows[:count]:
        src_ip_b = socket.inet_aton(f.src_ip)
        dst_ip_b = socket.inet_aton(f.dst_ip)
        next_hop_b = socket.inet_aton(f.next_hop if f.next_hop else "0.0.0.0")

        # Registro NetFlow v5 (48 bytes): !4s4s4sHHIIIIHHBBBBHHBBH
        rec = struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            src_ip_b,
            dst_ip_b,
            next_hop_b,
            int(f.input_snmp) & 0xFFFF,
            int(f.output_snmp) & 0xFFFF,
            int(f.packets) & 0xFFFFFFFF,
            int(f.bytes) & 0xFFFFFFFF,
            int(f.first_switched) & 0xFFFFFFFF,
            int(f.last_switched) & 0xFFFFFFFF,
            int(f.src_port) & 0xFFFF,
            int(f.dst_port) & 0xFFFF,
            0,              # pad1
            int(f.tcp_flags) & 0xFF,
            int(f.protocol) & 0xFF,
            int(f.tos) & 0xFF,
            int(f.src_as) & 0xFFFF,
            int(f.dst_as) & 0xFFFF,
            int(f.src_mask) & 0xFF,
            int(f.dst_mask) & 0xFF,
            0,              # pad2
        )
        records_bytes.extend(rec)

    return header + bytes(records_bytes)


class EnterpriseTrafficGenerator:
    """Generador sintético de telemetría de red corporativa."""

    BENIGN_INTERNAL_SUBNET = "10.0."
    BENIGN_SERVERS = [
        "10.0.0.5",     # Active Directory Domain Controller
        "10.0.0.10",    # Core Database PostgreSQL
        "10.0.0.15",    # Internal ERP Web
        "10.0.0.53",    # Internal Corporate DNS
    ]
    BENIGN_PUBLIC_DESTINATIONS = [
        "8.8.8.8",          # Google Public DNS
        "1.1.1.1",          # Cloudflare DNS
        "142.250.190.46",   # Google Search
        "104.244.42.1",     # Twitter / X
        "13.107.42.14",     # Microsoft Cloud / Office 365
        "151.101.65.140",   # Reddit
    ]

    def __init__(self, seed: Optional[int] = 42):
        if seed is not None:
            random.seed(seed)

    def generate_benign_flow(self) -> NetFlowRecord:
        """Genera un flujo de navegación, DNS o base de datos legítimo."""
        now = datetime.now(timezone.utc)
        now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF

        traffic_type = random.choices(["web_https", "dns", "internal_db", "web_http"], weights=[60, 20, 15, 5])[0]
        workstation_ip = f"10.0.{random.randint(1, 20)}.{random.randint(2, 254)}"

        if traffic_type == "web_https":
            dst_ip = random.choice(self.BENIGN_PUBLIC_DESTINATIONS)
            dst_port = 443
            protocol = 6
            tcp_flags = random.choice([2, 18, 24])  # SYN, SYN-ACK, PSH-ACK
            pkts = random.randint(5, 40)
            bytes_count = pkts * random.randint(300, 1200)
        elif traffic_type == "dns":
            dst_ip = random.choice(["10.0.0.53", "8.8.8.8", "1.1.1.1"])
            dst_port = 53
            protocol = 17
            tcp_flags = 0
            pkts = random.randint(1, 2)
            bytes_count = pkts * random.randint(60, 180)
        elif traffic_type == "internal_db":
            dst_ip = "10.0.0.10"
            dst_port = 5432
            protocol = 6
            tcp_flags = 24
            pkts = random.randint(10, 80)
            bytes_count = pkts * random.randint(200, 1400)
        else:
            dst_ip = random.choice(self.BENIGN_PUBLIC_DESTINATIONS)
            dst_port = 80
            protocol = 6
            tcp_flags = 24
            pkts = random.randint(4, 15)
            bytes_count = pkts * random.randint(200, 800)

        return NetFlowRecord(
            timestamp=now,
            timestamp_ms=now_ms,
            src_ip=workstation_ip,
            dst_ip=dst_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=pkts,
            bytes=bytes_count,
            first_switched=now_ms - 5000,
            last_switched=now_ms,
            src_port=random.randint(49152, 65535),
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            protocol=protocol,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def generate_port_scan_burst(self, attacker_ip: str = "10.0.50.99", target_ip: str = "10.0.0.5") -> List[NetFlowRecord]:
        """Genera una ráfaga de escaneo horizontal SYN."""
        now = datetime.now(timezone.utc)
        now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
        flows = []
        for p in ports:
            flows.append(NetFlowRecord(
                timestamp=now,
                timestamp_ms=now_ms,
                src_ip=attacker_ip,
                dst_ip=target_ip,
                next_hop="10.0.0.1",
                input_snmp=1,
                output_snmp=2,
                packets=1,
                bytes=60,
                first_switched=now_ms,
                last_switched=now_ms,
                src_port=random.randint(50000, 60000),
                dst_port=p,
                tcp_flags=2,  # SYN
                protocol=6,
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
            ))
        return flows

    def generate_c2_beacon_flow(self, infected_ip: str = "10.0.5.25", c2_ip: str = "198.51.100.77") -> NetFlowRecord:
        """Genera una conexión de comando y control saliente a IP hostil."""
        now = datetime.now(timezone.utc)
        now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF
        return NetFlowRecord(
            timestamp=now,
            timestamp_ms=now_ms,
            src_ip=infected_ip,
            dst_ip=c2_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=12,
            bytes=1420,
            first_switched=now_ms - 2000,
            last_switched=now_ms,
            src_port=random.randint(52000, 58000),
            dst_port=443,
            tcp_flags=24,  # PSH, ACK
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def generate_exfiltration_burst(self, infected_ip: str = "10.0.5.25", drop_ip: str = "203.0.113.88") -> NetFlowRecord:
        """Genera un flujo de exfiltración masiva de egreso."""
        now = datetime.now(timezone.utc)
        now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF
        return NetFlowRecord(
            timestamp=now,
            timestamp_ms=now_ms,
            src_ip=infected_ip,
            dst_ip=drop_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=25000,
            bytes=32 * 1024 * 1024,  # 32 MB
            first_switched=now_ms - 15000,
            last_switched=now_ms,
            src_port=54321,
            dst_port=443,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )


def run_benchmark_test(
    total_flows: int = 5000,
    inject_attacks: bool = True,
) -> Dict[str, Any]:
    """
    Ejecuta una prueba de rendimiento pura en memoria midiendo la velocidad
    de procesamiento y latencia de DetectionEngine por flujo.
    """
    from detector.engine import DetectionEngine

    engine = DetectionEngine()
    gen = EnterpriseTrafficGenerator()

    # Preparar lote de flujos
    flows: List[NetFlowRecord] = [gen.generate_benign_flow() for _ in range(total_flows)]

    if inject_attacks:
        # Inyectar ataques en posiciones clave
        scan_flows = gen.generate_port_scan_burst()
        c2_flow = gen.generate_c2_beacon_flow()
        exfil_flow = gen.generate_exfiltration_burst()

        flows.extend(scan_flows)
        flows.append(c2_flow)
        flows.append(exfil_flow)
        random.shuffle(flows)

    start_time = time.perf_counter()
    alerts_triggered = 0
    total_bytes = sum(f.bytes for f in flows)

    for flow in flows:
        alerts = engine.analyze_flow(flow)
        if alerts:
            alerts_triggered += len(alerts)

    elapsed_s = time.perf_counter() - start_time
    flows_per_sec = len(flows) / max(elapsed_s, 0.0001)
    mbps = (total_bytes * 8 / 1_000_000) / max(elapsed_s, 0.0001)
    avg_latency_us = (elapsed_s / len(flows)) * 1_000_000

    return {
        "total_flows": len(flows),
        "total_bytes_mb": round(total_bytes / (1024 * 1024), 2),
        "elapsed_seconds": round(elapsed_s, 3),
        "throughput_flows_per_sec": round(flows_per_sec, 1),
        "throughput_mbps": round(mbps, 2),
        "avg_latency_microseconds": round(avg_latency_us, 2),
        "alerts_triggered": alerts_triggered,
    }


def main():
    parser = argparse.ArgumentParser(description="NovaFlow NDR - Synthetic Traffic Generator & Benchmark CLI")
    parser.add_argument("--mode", choices=["benchmark", "udp"], default="benchmark", help="Modo: benchmark en memoria o transmisión UDP NetFlow v5")
    parser.add_argument("--flows", type=int, default=2000, help="Cantidad de flujos a generar")
    parser.add_argument("--udp-host", type=str, default="127.0.0.1", help="Host UDP de destino para modo NetFlow")
    parser.add_argument("--udp-port", type=int, default=2055, help="Puerto UDP del colector NetFlow")
    parser.add_argument("--inject-attacks", action="store_true", default=True, help="Inyectar vectores de ataque (Scan, C2, Exfiltration)")

    args = parser.parse_args()

    print("=" * 70)
    print("      NOVAFLOW NDR - ENTERPRISE TRAFFIC GENERATOR & BENCHMARK      ")
    print("=" * 70)

    if args.mode == "benchmark":
        print(f"[*] Ejecutando Benchmark en memoria ({args.flows} flujos)...")
        res = run_benchmark_test(total_flows=args.flows, inject_attacks=args.inject_attacks)
        print(f"[+] Tiempo total transcurrido : {res['elapsed_seconds']} s")
        print(f"[+] Flujos evaluados          : {res['total_flows']:,} flujos")
        print(f"[+] Throughput de evaluación  : {res['throughput_flows_per_sec']:,} flujos/segundo")
        print(f"[+] Ancho de banda equivalente: {res['throughput_mbps']:,} Mbps")
        print(f"[+] Latencia media por flujo  : {res['avg_latency_microseconds']} µs")
        print(f"[+] Alertas de seguridad      : {res['alerts_triggered']} disparadas")
        print("=" * 70)
    else:
        print(f"[*] Emitiendo datagramas binarios NetFlow v5 hacia udp://{args.udp_host}:{args.udp_port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        gen = EnterpriseTrafficGenerator()
        batch = [gen.generate_benign_flow() for _ in range(30)]
        pkt_bytes = build_netflow_v5_packet(batch)
        sock.sendto(pkt_bytes, (args.udp_host, args.udp_port))
        print(f"[+] Datagrama NetFlow v5 de 30 flujos transmitido exitosamente ({len(pkt_bytes)} bytes).")
        print("=" * 70)


if __name__ == "__main__":
    main()
