"""
NovaFlow NDR - Purple Team Integration Router (OmniBreach DAST vs NovaFlow NDR)
Provee endpoints para consultar la matriz de correlación Red/Blue y ejecutar
simulaciones automáticas de ataques de OmniBreach contra los sensores de NovaFlow.
"""

from typing import Any, Dict, List
from fastapi import APIRouter, Security
from pydantic import BaseModel
from datetime import datetime, timezone

from api.state import system_state
from api.security.auth import Identity, get_current_identity
from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.mitre import get_mitre_for_category, MITRE_MAPPING

router = APIRouter(prefix="/purple-team", tags=["Purple Team Integration"])

# Matriz canónica de correlación OmniBreach (Offensive) vs NovaFlow (Defensive)
PURPLE_TEAM_MATRIX = [
    {
        "vector_id": "OB-RECON-01",
        "name": "OmniBreach Port & Service Discovery",
        "phase": "Reconocimiento Activo",
        "description": "Escaneo horizontal/vertical de puertos mediante OmniBreach DAST para mapeo de superficie de ataque.",
        "offensive_tool": "OmniBreach Scanner (Network Prober)",
        "layer": "L4 TCP (SYN flags scan)",
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "novaflow_detector": "PortScanDetector (Heurística de ventana deslizante)",
        "expected_severity": "MEDIUM",
        "alert_category": "PORT_SCAN",
        "cef_device_event_class_id": "PORT_SCAN",
    },
    {
        "vector_id": "OB-EXFIL-02",
        "name": "OmniBreach Data Exfiltration & SSRF Egress",
        "phase": "Exfiltración / Egress",
        "description": "Fuga masiva de datos mediante pivoting SSRF simulado hacia servidor de extracción externo.",
        "offensive_tool": "OmniBreach SSRF & Data Dumper",
        "layer": "L4/L7 TCP/UDP (>20MB burst)",
        "mitre_id": "T1048.003",
        "mitre_name": "Exfiltration Over Unencrypted Non-C2 Protocol",
        "mitre_tactic": "Exfiltration",
        "novaflow_detector": "BandwidthAnomalyDetector (Volumen anómalo por host)",
        "expected_severity": "HIGH",
        "alert_category": "EXFILTRATION",
        "cef_device_event_class_id": "EXFILTRATION",
    },
    {
        "vector_id": "OB-DOS-03",
        "name": "OmniBreach SYN Flood Stress Test",
        "phase": "Impacto / Denegación de Servicio",
        "description": "Ráfaga de paquetes TCP SYN sin completar handshake para saturar la tabla de conexiones.",
        "offensive_tool": "OmniBreach Stresser & Flood Engine",
        "layer": "L4 TCP (Flag 0x02 SYN burst)",
        "mitre_id": "T1498.001",
        "mitre_name": "Direct Network Flood",
        "mitre_tactic": "Impact",
        "novaflow_detector": "SynFloodDetector (Tasa SYN/ACK en ventana temporal)",
        "expected_severity": "HIGH",
        "alert_category": "SYN_FLOOD",
        "cef_device_event_class_id": "SYN_FLOOD",
    },
    {
        "vector_id": "OB-C2-04",
        "name": "OmniBreach Reverse Shell & C2 Callback",
        "phase": "Comando y Control",
        "description": "Establecimiento de canal de comunicación saliente hacia infraestructura maliciosa catalogada.",
        "offensive_tool": "OmniBreach Post-Exploitation Agent",
        "layer": "L4 TCP (Beaconing a IP maliciosa)",
        "mitre_id": "T1071",
        "mitre_name": "Application Layer Protocol",
        "mitre_tactic": "Command and Control",
        "novaflow_detector": "ThreatIntelDetector (Matching O(1) contra listas C2)",
        "expected_severity": "CRITICAL",
        "alert_category": "MALICIOUS_C2",
        "cef_device_event_class_id": "MALICIOUS_C2",
    },
]


@router.get("/matrix")
async def get_correlation_matrix(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Retorna la matriz de correlación Purple Team entre OmniBreach (Red Team) y NovaFlow NDR (Blue Team).
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_vectors": len(PURPLE_TEAM_MATRIX),
        "integration_framework": "MITRE ATT&CK for Enterprise + ArcSight CEF",
        "red_team_tool": "OmniBreach DAST",
        "blue_team_tool": "NovaFlow NDR",
        "correlation_matrix": PURPLE_TEAM_MATRIX,
    }


class SimulationResponse(BaseModel):
    success: bool
    summary: str
    vectors_executed: int
    alerts_triggered: int
    detection_rate_pct: float
    results: List[Dict[str, Any]]


@router.post("/simulate", response_model=SimulationResponse)
async def run_purple_team_simulation(
    identity: Identity = Security(get_current_identity),
) -> SimulationResponse:
    """
    Ejecuta un ejercicio Purple Team en vivo:
    1. Simula telemetría NetFlow de ataques de OmniBreach.
    2. Procesa los flujos en el motor de detección de NovaFlow.
    3. Retorna la correlación en tiempo real con severidades y MITRE ATT&CK.
    """
    engine = system_state.engine
    if not engine:
        return SimulationResponse(
            success=False,
            summary="El motor de detección de NovaFlow no está inicializado",
            vectors_executed=0,
            alerts_triggered=0,
            detection_rate_pct=0.0,
            results=[],
        )

    now = datetime.now(timezone.utc)
    results = []

    # Vector 1: OmniBreach Port Scan (18 puertos diferentes desde 10.0.50.15)
    scanner_ip = "10.0.50.15"
    target_ip = "10.0.0.10"
    v1_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=scanner_ip,
            dst_ip=target_ip,
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
        for p in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000]
    ]
    engine.analyze_batch(v1_flows)
    v1_alert = next((a for a in reversed(engine.alerts_history) if a.category == AlertCategory.PORT_SCAN and a.src_ip == scanner_ip), None)

    results.append({
        "vector_id": "OB-RECON-01",
        "attack_name": "OmniBreach Port & Service Discovery",
        "mitre_id": "T1046",
        "detected": v1_alert is not None,
        "alert_id": v1_alert.alert_id if v1_alert else None,
        "severity": v1_alert.severity.value if v1_alert else None,
        "category": v1_alert.category.value if v1_alert else None,
        "cef_log": v1_alert.to_cef() if v1_alert else None,
    })

    # Vector 2: OmniBreach High-Volume Data Exfiltration (25MB en una sesión)
    exfil_src = "10.0.0.10"
    exfil_dst = "198.51.100.99"
    v2_flow = NetFlowRecord(
        timestamp=now,
        timestamp_ms=int(now.timestamp() * 1000),
        src_ip=exfil_src,
        dst_ip=exfil_dst,
        next_hop="10.0.0.1",
        input_snmp=1,
        output_snmp=2,
        packets=18000,
        bytes=26_000_000,  # 26 MB (> 20MB umbral)
        first_switched=2000,
        last_switched=5000,
        src_port=52344,
        dst_port=443,
        tcp_flags=24,  # ACK, PSH
        protocol=6,
        tos=0,
        src_as=0,
        dst_as=0,
        src_mask=24,
        dst_mask=24,
    )
    engine.analyze_batch([v2_flow])
    v2_alert = next((a for a in reversed(engine.alerts_history) if a.category == AlertCategory.EXFILTRATION and a.src_ip == exfil_src), None)

    results.append({
        "vector_id": "OB-EXFIL-02",
        "attack_name": "OmniBreach Data Exfiltration & SSRF Egress",
        "mitre_id": "T1048.003",
        "detected": v2_alert is not None,
        "alert_id": v2_alert.alert_id if v2_alert else None,
        "severity": v2_alert.severity.value if v2_alert else None,
        "category": v2_alert.category.value if v2_alert else None,
        "cef_log": v2_alert.to_cef() if v2_alert else None,
    })

    # Vector 3: OmniBreach SYN Flood (55 flujos SYN a puerto 80)
    flood_src = "10.0.50.20"
    flood_target = "10.0.0.80"
    v3_flows = [
        NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip=flood_src,
            dst_ip=flood_target,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=1,
            bytes=40,
            first_switched=3000,
            last_switched=3010,
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
        for i in range(55)
    ]
    engine.analyze_batch(v3_flows)
    v3_alert = next((a for a in reversed(engine.alerts_history) if a.category == AlertCategory.SYN_FLOOD and a.dst_ip == flood_target), None)

    results.append({
        "vector_id": "OB-DOS-03",
        "attack_name": "OmniBreach SYN Flood Stress Test",
        "mitre_id": "T1498.001",
        "detected": v3_alert is not None,
        "alert_id": v3_alert.alert_id if v3_alert else None,
        "severity": v3_alert.severity.value if v3_alert else None,
        "category": v3_alert.category.value if v3_alert else None,
        "cef_log": v3_alert.to_cef() if v3_alert else None,
    })

    # Vector 4: OmniBreach C2 Callback (Hacia IP maliciosa Cobalt Strike 198.51.100.77)
    c2_victim = "10.0.0.15"
    c2_server = "198.51.100.77"
    v4_flow = NetFlowRecord(
        timestamp=now,
        timestamp_ms=int(now.timestamp() * 1000),
        src_ip=c2_victim,
        dst_ip=c2_server,
        next_hop="10.0.0.1",
        input_snmp=1,
        output_snmp=2,
        packets=10,
        bytes=1200,
        first_switched=4000,
        last_switched=4100,
        src_port=49888,
        dst_port=443,
        tcp_flags=24,
        protocol=6,
        tos=0,
        src_as=0,
        dst_as=0,
        src_mask=24,
        dst_mask=24,
    )
    engine.analyze_batch([v4_flow])
    v4_alert = next((a for a in reversed(engine.alerts_history) if a.category == AlertCategory.MALICIOUS_C2 and a.dst_ip == c2_server), None)

    results.append({
        "vector_id": "OB-C2-04",
        "attack_name": "OmniBreach Reverse Shell & C2 Callback",
        "mitre_id": "T1071",
        "detected": v4_alert is not None,
        "alert_id": v4_alert.alert_id if v4_alert else None,
        "severity": v4_alert.severity.value if v4_alert else None,
        "category": v4_alert.category.value if v4_alert else None,
        "cef_log": v4_alert.to_cef() if v4_alert else None,
    })

    detected_count = sum(1 for r in results if r["detected"])
    rate_pct = round((detected_count / len(results)) * 100.0, 1)

    return SimulationResponse(
        success=True,
        summary=f"Simulación Purple Team finalizada. Detección exitosa de {detected_count}/{len(results)} vectores de ataque OmniBreach ({rate_pct}%).",
        vectors_executed=len(results),
        alerts_triggered=detected_count,
        detection_rate_pct=rate_pct,
        results=results,
    )


@router.get("/contract")
async def get_purple_team_contract() -> Dict[str, Any]:
    """
    Retorna la especificación formal del contrato Purple Team v1.0.
    Permite a OmniBreach y herramientas externas descubrir el esquema de eventos y vectores soportados.
    """
    from scripts.run_purple_benchmark import build_canonical_campaign
    campaign, _ = build_canonical_campaign("camp_template_v1")
    return {
        "contract_version": "1.0.0",
        "description": "Especificación formal de campaña ofensiva y telemetría de red OmniBreach x NovaFlow NDR",
        "campaign_template": campaign.to_dict(),
        "supported_vectors": PURPLE_TEAM_MATRIX,
    }


class BenchmarkRequest(BaseModel):
    background_flows: int = 500
    seed: int = 42


@router.post("/benchmark")
async def run_purple_team_benchmark(
    req: BenchmarkRequest = BenchmarkRequest(),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Ejecuta el arnés de benchmark cuantitativo en vivo:
    Genera ruido de fondo, evalúa los vectores ofensivos de OmniBreach y computa
    métricas empíricas reales (MTTD, precisión, recall, F1 y falsos positivos).
    """
    from scripts.run_purple_benchmark import run_benchmark
    metrics = run_benchmark(background_count=req.background_flows, seed=req.seed)
    return metrics.to_dict()

