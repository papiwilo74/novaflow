"""
NovaFlow NDR x OmniBreach - Unified Purple Team Demonstration
Simula la interacción de ciberseguridad ofensiva (Red Team) generada por OmniBreach
y su detección, análisis heurístico/ML y exportación SIEM (Blue Team) por NovaFlow NDR.

Uso:
    python scripts/purple_team_demo.py
    python scripts/purple_team_demo.py --live-udp --port 2055
"""

import argparse
import os
import socket
import sys
import time
from datetime import datetime, timezone
from typing import List, Tuple

# Garantizar que la raíz del proyecto esté en sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.parser import NetFlowParser, NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


# Estilos ANSI para terminal
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_banner():
    banner = f"""
{CYAN}{BOLD}================================================================================
           NOVAFLOW NDR  x  OMNIBREACH - PURPLE TEAM SIMULATION ENGINE
      [Red Team Offensive DAST] <---> [Blue Team Network Detection & Response]
================================================================================{RESET}
"""
    print(banner)


def generate_port_scan_flows(scanner_ip: str, victim_ip: str) -> List[NetFlowRecord]:
    """OmniBreach Vector 1: Escaneo de puertos y descubrimiento de servicios (T1046)."""
    now = datetime.now(timezone.utc)
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000]
    flows = []
    for p in ports:
        flows.append(
            NetFlowRecord(
                timestamp=now,
                timestamp_ms=int(now.timestamp() * 1000),
                src_ip=scanner_ip,
                dst_ip=victim_ip,
                next_hop="10.0.0.1",
                input_snmp=1,
                output_snmp=2,
                packets=1,
                bytes=44,
                first_switched=1000,
                last_switched=1010,
                src_port=40000 + p,
                dst_port=p,
                tcp_flags=2,  # SYN
                protocol=6,   # TCP
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
            )
        )
    return flows


def generate_exfiltration_flow(source_ip: str, exfil_ip: str) -> List[NetFlowRecord]:
    """OmniBreach Vector 2: Exfiltración de datos / SSRF Egress (T1048.003)."""
    now = datetime.now(timezone.utc)
    return [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=source_ip,
            dst_ip=exfil_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=22000,
            bytes=32_000_000,  # 32 MB (> 20MB umbral)
            first_switched=2000,
            last_switched=5500,
            src_port=54321,
            dst_port=443,
            tcp_flags=24,  # ACK, PSH
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
    ]


def generate_syn_flood_flows(attacker_ip: str, victim_ip: str) -> List[NetFlowRecord]:
    """OmniBreach Vector 3: SYN Flood / DoS Stress Test (T1498.001)."""
    now = datetime.now(timezone.utc)
    flows = []
    for i in range(60):
        flows.append(
            NetFlowRecord(
                timestamp=now,
                timestamp_ms=int(now.timestamp() * 1000),
                src_ip=attacker_ip,
                dst_ip=victim_ip,
                next_hop="10.0.0.1",
                input_snmp=1,
                output_snmp=2,
                packets=1,
                bytes=40,
                first_switched=3000,
                last_switched=3005,
                src_port=10000 + i,
                dst_port=80,
                tcp_flags=2,  # SYN
                protocol=6,
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
            )
        )
    return flows


def generate_c2_flow(compromised_ip: str, c2_ip: str) -> List[NetFlowRecord]:
    """OmniBreach Vector 4: Conexión saliente a servidor C2 malicioso (T1071)."""
    now = datetime.now(timezone.utc)
    return [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=compromised_ip,
            dst_ip=c2_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=15,
            bytes=1850,
            first_switched=4000,
            last_switched=4200,
            src_port=49999,
            dst_port=443,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
    ]


def run_purple_team_demo(live_udp: bool = False, host: str = "127.0.0.1", port: int = 2055):
    print_banner()

    engine = DetectionEngine()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if live_udp else None

    scenarios = [
        (
            "OB-RECON-01",
            "OmniBreach Port & Service Scan",
            "Mapeo activo de 18 puertos L4 TCP con flags SYN",
            generate_port_scan_flows("10.0.50.15", "10.0.0.10"),
            AlertCategory.PORT_SCAN,
        ),
        (
            "OB-EXFIL-02",
            "OmniBreach SSRF & Data Exfiltration",
            "Descarga masiva de base de datos cifrada (32 MB burst)",
            generate_exfiltration_flow("10.0.0.10", "198.51.100.99"),
            AlertCategory.EXFILTRATION,
        ),
        (
            "OB-DOS-03",
            "OmniBreach SYN Flood Stress Test",
            "Ráfaga de 60 paquetes SYN para agotar sockets del servidor",
            generate_syn_flood_flows("10.0.50.20", "10.0.0.80"),
            AlertCategory.SYN_FLOOD,
        ),
        (
            "OB-C2-04",
            "OmniBreach Reverse Shell Beaconing",
            "Comunicación C2 saliente con servidor malicioso Cobalt Strike",
            generate_c2_flow("10.0.0.15", "198.51.100.77"),
            AlertCategory.MALICIOUS_C2,
        ),
    ]

    total_scenarios = len(scenarios)
    detected_count = 0
    results_summary = []

    print(f"[*] Iniciando ejercicio Purple Team ({total_scenarios} vectores ofensivos simulados)...")
    if live_udp:
        print(f"[*] Modo Live UDP activado: Inyectando datagramas binarios NetFlow en udp://{host}:{port}")
    print("-" * 80)

    for vid, name, desc, flows, expected_cat in scenarios:
        print(f"\n{YELLOW}{BOLD}[RED TEAM - OmniBreach]{RESET} Ejecutando Vector: {BOLD}{name}{RESET} ({vid})")
        print(f"    Detalle técnico: {desc}")
        print(f"    Flujos L3/L4 generados: {len(flows)}")

        # Transmitir a socket UDP si se requiere modo live
        if live_udp and sock:
            packet_bytes = NetFlowParser.pack_packet(flows)
            sock.sendto(packet_bytes, (host, port))

        # Medir latencia de inferencia de NovaFlow NDR
        t0 = time.perf_counter()
        engine.analyze_batch(flows)
        latency_ms = (time.perf_counter() - t0) * 1000

        # Buscar alerta correspondiente
        matched_alert = next((a for a in reversed(engine.alerts_history) if a.category == expected_cat), None)

        if matched_alert:
            detected_count += 1
            status_str = f"{GREEN}{BOLD}[DETECTADO - 100%]{RESET}"
            mitre_id = matched_alert.mitre.get("technique_id", "N/A") if isinstance(matched_alert.mitre, dict) else getattr(matched_alert.mitre, "technique_id", "N/A")
            mitre_tactic = matched_alert.mitre.get("tactic", "N/A") if isinstance(matched_alert.mitre, dict) else getattr(matched_alert.mitre, "tactic", "N/A")

            print(f"{BLUE}{BOLD}[BLUE TEAM - NovaFlow NDR]{RESET} {status_str} en {latency_ms:.2f} ms")
            print(f"    Alerta     : {matched_alert.title}")
            print(f"    Severidad  : {matched_alert.severity.value} | Confianza: {matched_alert.confidence * 100:.0f}%")
            print(f"    MITRE ATT&CK: {mitre_id} ({mitre_tactic})")
            print(f"    SIEM CEF   : {matched_alert.to_cef()}")

            results_summary.append({
                "id": vid,
                "name": name,
                "detected": True,
                "latency_ms": latency_ms,
                "severity": matched_alert.severity.value,
                "mitre": mitre_id,
            })
        else:
            status_str = f"{RED}{BOLD}[NO DETECTADO]{RESET}"
            print(f"{BLUE}{BOLD}[BLUE TEAM - NovaFlow NDR]{RESET} {status_str}")
            results_summary.append({
                "id": vid,
                "name": name,
                "detected": False,
                "latency_ms": latency_ms,
                "severity": "NONE",
                "mitre": "N/A",
            })

    if sock:
        sock.close()

    print("\n" + "=" * 80)
    print(f"{MAGENTA}{BOLD}                    MATRIZ DE CORRELACIÓN PURPLE TEAM{RESET}")
    print("=" * 80)
    print(f"{'Vector ID':<12} | {'Ataque OmniBreach':<32} | {'Estado':<14} | {'MITRE':<8} | {'Latencia':<8}")
    print("-" * 80)
    for r in results_summary:
        st = f"{GREEN}DETECTADO{RESET}" if r["detected"] else f"{RED}FALLIDO{RESET}"
        print(f"{r['id']:<12} | {r['name']:<32} | {st:<23} | {r['mitre']:<8} | {r['latency_ms']:.2f}ms")

    rate_pct = (detected_count / total_scenarios) * 100
    print("-" * 80)
    print(f"{BOLD}Eficacia de Detección Conjunta:{RESET} {GREEN if rate_pct == 100 else YELLOW}{detected_count}/{total_scenarios} ({rate_pct:.1f}%){RESET}")
    print(f"{BOLD}Conclusión:{RESET} NovaFlow NDR complementa a OmniBreach proveyendo visibilidad de red forense L3/L4")
    print("            y telemetría compatible con SIEM (CEF / Syslog) para cada hallazgo de seguridad DAST.\n")

    return detected_count == total_scenarios


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NovaFlow NDR x OmniBreach Purple Team Simulation")
    parser.add_argument("--live-udp", action="store_true", help="Enviar datagramas UDP reales al puerto NetFlow local")
    parser.add_argument("--host", default="127.0.0.1", help="Host colector (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2055, help="Puerto UDP (default: 2055)")
    args = parser.parse_args()

    success = run_purple_team_demo(live_udp=args.live_udp, host=args.host, port=args.port)
    sys.exit(0 if success else 1)
