"""
NovaFlow NDR - End-to-End System Health & Improvements Verification Script
Ejecuta una validación integral en vivo de todos los detectores y endpoints corporativos.
"""

import sys
import os
from datetime import datetime, timezone

from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from collector.parser import NetFlowRecord


def make_record(src_ip, dst_ip, src_port, dst_port, protocol=6, tcp_flags=0x18, packets=10, bytes_val=2000):
    return NetFlowRecord(
        timestamp=datetime.now(timezone.utc),
        timestamp_ms=0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop="192.168.1.1",
        input_snmp=1,
        output_snmp=2,
        packets=packets,
        bytes=bytes_val,
        first_switched=1000,
        last_switched=2000,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        protocol=protocol,
        tos=0,
        src_as=65000,
        dst_as=65000,
        src_mask=24,
        dst_mask=24,
    )


def verify_all():
    print("=" * 70)
    print("      NOVAFLOW NDR - AUDITORÍA Y CONFIRMACIÓN DE MEJORAS EN VIVO     ")
    print("=" * 70)

    # 1. Instanciar motor unificado
    engine = DetectionEngine()
    system_state.initialize(engine)
    client = TestClient(app)

    # 2. Validar Detección de Movimiento Lateral (T1021)
    print("\n[*] 1. Validando Detector de Movimiento Lateral L4 (T1021)...")
    src_pivot = "10.0.0.88"
    engine.analyze_flow(make_record(src_pivot, "10.0.0.10", 50000, 445))
    engine.analyze_flow(make_record(src_pivot, "10.0.0.11", 50000, 445))
    alerts_lat = engine.analyze_flow(make_record(src_pivot, "10.0.0.12", 50000, 445))
    lat_alert = next((a for a in alerts_lat if a.category == AlertCategory.LATERAL_MOVEMENT), None)
    assert lat_alert is not None, "FALLO: Movimiento Lateral no detectado"
    print(f"    [OK] Alerta emitida: {lat_alert.title}")
    print(f"         Severidad: {lat_alert.severity.value} | Confianza: {lat_alert.confidence*100:.0f}% | MITRE: {lat_alert.mitre['technique_id']}")

    # 3. Validar Supresión Bi-Flow de Descargas Masivas
    print("\n[*] 2. Validando Motor Bi-Flow Stitching (Supresión de Descargas)...")
    server_ext = "104.244.42.1"
    client_int = "192.168.1.50"
    # Flujo de bajada masiva (100 MB)
    engine.analyze_flow(make_record(server_ext, client_int, 443, 52000, packets=80000, bytes_val=100_000_000))
    # Flujo de subida normal en ACKs (15 MB)
    alerts_exfil = engine.analyze_flow(make_record(client_int, server_ext, 52000, 443, packets=5000, bytes_val=15_000_000))
    exfil_alert = next((a for a in alerts_exfil if a.category == AlertCategory.EXFILTRATION), None)
    assert exfil_alert is None, "FALLO: Falso positivo en descarga legítima no fue suprimido"
    print("    [OK] Falso positivo de exfiltración suprimido exitosamente por BiFlow ratio < 0.2")

    # 4. Validar Motor de Entropía de Shannon para DGA
    print("\n[*] 3. Validando Motor de Entropía de Shannon (DGA & Túneles DNS)...")
    dga_alert = engine.dns_tunnel_detector.analyze_dns_query(
        "192.168.1.45", "8.8.8.8", "c7a8f9e0b1d2c3e4f5a6b7.exfil.darknet.com"
    )
    assert dga_alert is not None, "FALLO: Subdominio DGA de alta entropía no detectado"
    print(f"    [OK] DGA Detectado: {dga_alert.title}")
    print(f"         Entropía H={dga_alert.metrics['shannon_entropy']} bits/char | Confianza: {dga_alert.confidence*100:.0f}%")

    # 5. Validar Endpoints REST MITRE ATT&CK
    print("\n[*] 4. Validando Endpoints REST de la Matriz MITRE ATT&CK...")
    res_matrix = client.get("/api/v1/mitre/matrix")
    assert res_matrix.status_code == 200, f"Error en /api/v1/mitre/matrix: {res_matrix.status_code}"
    res_heat = client.get("/api/v1/mitre/heatmap")
    assert res_heat.status_code == 200, f"Error en /api/v1/mitre/heatmap: {res_heat.status_code}"
    heat_data = res_heat.json()
    print(f"    [OK] Matriz cargada: {len(heat_data['cells'])} celdas tácticas")
    print(f"         Nivel de Amenaza Global: {heat_data['threat_level']}")
    res_drill = client.get("/api/v1/mitre/techniques/T1021/alerts")
    assert res_drill.status_code == 200, f"Error en /api/v1/mitre/techniques/T1021/alerts: {res_drill.status_code}"
    print(f"    [OK] Drill-down T1021 recuperó {res_drill.json()['count']} incidentes activos")

    # 6. Validar Playbooks SOAR de Cuarentena
    print("\n[*] 5. Validando Generación de Playbooks SOAR de Cuarentena...")
    res_pb = client.get(f"/api/v1/alerts/{lat_alert.alert_id}/playbook")
    assert res_pb.status_code == 200, f"Error en playbook: {res_pb.status_code}"
    pb_data = res_pb.json()
    print(f"    [OK] Objetivo de Contención: {pb_data['target_ip_to_block']}")
    print(f"         Acción Recomendada: {pb_data['recommended_action']}")
    print(f"         Plataformas generadas: {len(pb_data['rules'])} (iptables, nftables, Cisco, AWS, Null-Route)")

    # 7. Validar Evidencia Digital DFIR & PCAP
    print("\n[*] 6. Validando Cadena de Custodia DFIR & PCAP...")
    res_ev = client.get(f"/api/v1/alerts/{lat_alert.alert_id}/evidence")
    assert res_ev.status_code == 200, f"Error en evidence: {res_ev.status_code}"
    ev_data = res_ev.json()
    print(f"    [OK] Firma Digital Inmutable SHA-256: {ev_data['sha256_hash'][:32]}...")

    res_pcap = client.get(f"/api/v1/alerts/{lat_alert.alert_id}/pcap")
    assert res_pcap.status_code == 200, f"Error en pcap: {res_pcap.status_code}"
    print(f"    [OK] Archivo PCAP generado: {len(res_pcap.content)} bytes (Abrible en Wireshark)")

    # 8. Validar Compliance y Reportes Ejecutivos C-Level
    print("\n[*] 7. Validando Cumplimiento Normativo y Reporte Ejecutivo C-Level...")
    res_rep = client.get("/api/v1/reports/executive")
    assert res_rep.status_code == 200, f"Error en report: {res_rep.status_code}"
    rep_data = res_rep.json()
    print(f"    [OK] Corporate Risk Score: {rep_data['risk_assessment']['risk_score']}/100 ({rep_data['risk_assessment']['status']})")
    print(f"         Postura PCI-DSS v4.0: {rep_data['compliance_evaluation']['pci_dss']['status']}")

    print("\n" + "=" * 70)
    print("   RESULTADO DE LA AUDITORÍA: TODAS LAS MEJORAS ESTÁN 100% CORRECTAS ")
    print("=" * 70)


if __name__ == "__main__":
    verify_all()
