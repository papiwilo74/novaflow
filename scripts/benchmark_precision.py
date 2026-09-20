"""
NovaFlow NDR - Scientific Precision & Benchmark Suite
Genera conjuntos de datos mixtos (tráfico legítimo masivo + vectores de ataque variados)
y mide formalmente la matriz de confusión (TP, FP, TN, FN), precisión y recall.

Uso:
    python scripts/benchmark_precision.py
"""

import os
import random
import sys
from datetime import datetime, timezone
from typing import List, Tuple

# Garantizar que la raíz del proyecto esté en sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.evaluation import AttackCampaign, PrecisionEvaluator, BenchmarkReport
from detector.models import AlertCategory


def build_benchmark_traffic() -> Tuple[List[NetFlowRecord], List[AttackCampaign]]:
    """
    Construye un dataset representativo con:
    - 400 flujos legítimos (navegación web, DNS estándar, backups internos, SSH)
    - 6 campañas completas de ciberataque con 141 flujos maliciosos
    """
    now = datetime.now(timezone.utc)
    benign_flows: List[NetFlowRecord] = []
    campaigns: List[AttackCampaign] = []

    # -------------------------------------------------------------
    # 1. TRÁFICO BENIGNO / LEGÍTIMO (Meta: Cero Falsos Positivos)
    # -------------------------------------------------------------

    # 1.1 Navegación Web Legítima (150 flujos HTTPS hacia CDNs en puerto 443 con múltiples puertos efímeros)
    cdns = ["151.101.1.69", "104.16.123.96", "172.217.16.206", "13.107.42.14"]
    for i in range(150):
        flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=f"192.168.1.{random.randint(10, 100)}",
            dst_ip=random.choice(cdns),
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=random.randint(15, 80),
            bytes=random.randint(4000, 65000),
            first_switched=1000,
            last_switched=1050,
            src_port=random.randint(49152, 65535),
            dst_port=443,
            tcp_flags=24,  # ACK, PSH (sesión establecida normal)
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        benign_flows.append(flow)

    # 1.2 Tráfico DNS Legítimo (100 consultas cortas hacia 8.8.8.8 y 1.1.1.1)
    resolvers = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]
    for i in range(100):
        flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=f"192.168.1.{random.randint(10, 100)}",
            dst_ip=random.choice(resolvers),
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=random.randint(1, 2),
            bytes=random.randint(60, 140),  # Típico query DNS pequeño
            first_switched=2000,
            last_switched=2010,
            src_port=random.randint(40000, 60000),
            dst_port=53,
            tcp_flags=0,
            protocol=17,  # UDP
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        benign_flows.append(flow)

    # 1.3 Transferencia Interna de Gran Tamaño / Backup Interno (50 flujos entre servidores 10.x.x.x)
    # Debe ser ignorado por exfiltración porque es comunicación inter-red RFC1918
    for i in range(50):
        flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="10.0.1.50",
            dst_ip="10.0.2.200",  # Ambos privados
            next_hop="10.0.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=50000,
            bytes=60_000_000,  # 60 MB interno
            first_switched=3000,
            last_switched=6000,
            src_port=445,
            dst_port=55123,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        benign_flows.append(flow)

    # 1.4 Sesiones SSH Administrativas y API (100 flujos legítimos)
    for i in range(100):
        flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=f"192.168.1.{random.randint(5, 15)}",
            dst_ip="192.168.1.250",
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=random.randint(20, 100),
            bytes=random.randint(2000, 20000),
            first_switched=4000,
            last_switched=4200,
            src_port=random.randint(50000, 60000),
            dst_port=22,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        benign_flows.append(flow)

    # -------------------------------------------------------------
    # 2. CAMPAÑAS DE ATAQUE (Meta: 100% Recall)
    # -------------------------------------------------------------

    # Campaña 1: Escaneo de Puertos SYN (20 puertos desde 192.168.1.99)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000]
    c1_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="192.168.1.99",
            dst_ip="192.168.1.200",
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=44,
            first_switched=5000,
            last_switched=5005,
            src_port=45000 + p,
            dst_port=p,
            tcp_flags=2,  # SYN
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        for p in scan_ports
    ]
    campaigns.append(AttackCampaign(
        campaign_id="CAMP-RECON-SYN",
        name="Barrido de Puertos SYN",
        expected_category=AlertCategory.PORT_SCAN,
        flows=c1_flows,
        description="Sondeo vertical de 20 puertos con bandera SYN",
    ))

    # Campaña 2: Escaneo Sigiloso FIN / NULL / Xmas (18 puertos desde 192.168.1.105)
    c2_flows = []
    for idx, p in enumerate([81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98]):
        flag = 0x01 if idx % 3 == 0 else (0x00 if idx % 3 == 1 else 0x29)  # FIN, NULL, XMAS
        c2_flows.append(NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="192.168.1.105",
            dst_ip="192.168.1.200",
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=40,
            first_switched=5100,
            last_switched=5105,
            src_port=46000 + p,
            dst_port=p,
            tcp_flags=flag,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        ))
    campaigns.append(AttackCampaign(
        campaign_id="CAMP-RECON-STEALTH",
        name="Escaneo Sigiloso (FIN/NULL/Xmas)",
        expected_category=AlertCategory.PORT_SCAN,
        flows=c2_flows,
        description="Escaneo con técnicas de evasión de firewall",
    ))

    # Campaña 3: DoS SYN Flood (65 flujos hacia servicio web 192.168.1.200:80)
    c3_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=f"172.16.50.{i + 1}",
            dst_ip="192.168.1.200",
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=40,
            first_switched=6000,
            last_switched=6005,
            src_port=10000 + i,
            dst_port=80,
            tcp_flags=2,  # SYN puro
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        for i in range(65)
    ]
    campaigns.append(AttackCampaign(
        campaign_id="CAMP-DOS-SYNFLOOD",
        name="Inundación SYN Flood DoS",
        expected_category=AlertCategory.SYN_FLOOD,
        flows=c3_flows,
        description="Ataque volumétrico DoS con IPs spoofeadas",
    ))

    # Campaña 4: Exfiltración de Ancho de Banda Externa (Flujos masivos hacia IP pública)
    c4_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="192.168.1.50",
            dst_ip="203.0.113.88",  # IP pública externa
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=25000,
            bytes=35_000_000,  # 35 MB
            first_switched=7000,
            last_switched=7500,
            src_port=58001,
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
    campaigns.append(AttackCampaign(
        campaign_id="CAMP-EXFIL-EXTERNAL",
        name="Exfiltración Masiva de Datos",
        expected_category=AlertCategory.EXFILTRATION,
        flows=c4_flows,
        description="Fuga de 35MB hacia drop server externo",
    ))

    # Campaña 5: Túnel DNS Encubierto (30 paquetes inflados > 380B/pkt)
    c5_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="192.168.1.75",
            dst_ip="198.51.100.123",  # DNS Server externo sospechoso
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=420,  # 420 bytes por query DNS
            first_switched=8000,
            last_switched=8005,
            src_port=53000 + i,
            dst_port=53,
            tcp_flags=0,
            protocol=17,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        for i in range(30)
    ]
    campaigns.append(AttackCampaign(
        campaign_id="CAMP-DNS-TUNNEL",
        name="Canal Encubierto DNS (Iodine/dnscat)",
        expected_category=AlertCategory.DNS_TUNNEL,
        flows=c5_flows,
        description="Exfiltración por paquetes DNS inflados en UDP/53",
    ))

    # Campaña 6: Conexión C2 a IoC Conocido (Cobalt Strike 198.51.100.77)
    c6_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="192.168.1.20",
            dst_ip="198.51.100.77",
            next_hop="192.168.1.1",
            input_snmp=1,
            output_snmp=2,
            packets=12,
            bytes=1500,
            first_switched=9000,
            last_switched=9100,
            src_port=51000,
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
    campaigns.append(AttackCampaign(
        campaign_id="CAMP-C2-BEACON",
        name="Beaconing C2 Cobalt Strike",
        expected_category=AlertCategory.MALICIOUS_C2,
        flows=c6_flows,
        description="Comunicación reversa saliente con infraestructura de APT29",
    ))

    return benign_flows, campaigns


def run_benchmark():
    print("[*] Generando dataset balanceado de benchmark...")
    benign_flows, campaigns = build_benchmark_traffic()
    total_attack_flows = sum(len(c.flows) for c in campaigns)

    print(f"[*] Dataset compilado:")
    print(f"    - Flujos benignos / legítimos : {len(benign_flows)}")
    print(f"    - Campañas de ataque evaluadas: {len(campaigns)} ({total_attack_flows} flujos maliciosos)")

    engine = DetectionEngine()
    print("[*] Ejecutando evaluación analítica sobre NovaFlow DetectionEngine...")

    report = PrecisionEvaluator.evaluate_benchmark(engine, benign_flows, campaigns)
    report.print_summary()

    # Validar umbrales mínimos de calidad empresarial
    assert report.false_positives == 0, f"Se detectaron {report.false_positives} falsos positivos en tráfico legítimo!"
    assert report.precision >= 0.99, f"Precisión insuficiente: {report.precision * 100:.2f}% (esperado >= 99%)"
    assert report.recall >= 0.98, f"Recall insuficiente: {report.recall * 100:.2f}% (esperado >= 98%)"
    assert report.avg_latency_per_flow_ms < 5.0, f"Latencia excesiva: {report.avg_latency_per_flow_ms:.2f} ms"

    print("[SUCCESS] Todas las pruebas de precisión, recall y latencia superaron los umbrales de producción.")
    return report


if __name__ == "__main__":
    run_benchmark()
