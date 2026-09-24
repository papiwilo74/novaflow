"""
NovaFlow NDR - Live Telemetry Hook & Integration Router
Permite la ingesta directa de flujos y eventos de ataque generados por scripts ofensivos,
agentes locales de telemetría y pipelines DAST sin requerir sockets UDP.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel, Field

from api.state import system_state
from api.security.auth import Identity, get_current_identity
from collector.parser import NetFlowRecord
from detector.models import SecurityAlert

router = APIRouter(prefix="/telemetry", tags=["Live Telemetry & Ingestion Hooks"])


class TelemetryFlowInput(BaseModel):
    src_ip: str = Field(..., example="10.0.50.15")
    dst_ip: str = Field(..., example="10.0.0.10")
    src_port: int = Field(default=45000, example=45000)
    dst_port: int = Field(..., example=80)
    protocol: int = Field(default=6, example=6)  # 6=TCP, 17=UDP, 1=ICMP
    bytes: int = Field(default=1500, example=1500)
    packets: int = Field(default=10, example=10)
    tcp_flags: int = Field(default=24, example=24)  # 2=SYN, 24=PSH+ACK
    attack_label: Optional[str] = Field(None, example="OmniBreach SQLi Scan")
    campaign_id: Optional[str] = Field(None, example="camp_2026_09_ob_01")
    vector_id: Optional[str] = Field(None, example="OB-RECON-01")


class TelemetryBatchInput(BaseModel):
    flows: List[TelemetryFlowInput]


@router.post("/hook")
async def ingest_telemetry_flow(
    flow_in: TelemetryFlowInput,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Hook de telemetría directo: Inyecta un flujo L3/L4 en tiempo real en el motor de detección
    y transmite las alertas correspondientes al SOC Dashboard a través de WebSockets.
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=503, detail="Motor de detección no inicializado")

    now = datetime.now(timezone.utc)
    now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF

    record = NetFlowRecord(
        timestamp=now,
        timestamp_ms=now_ms,
        src_ip=flow_in.src_ip,
        dst_ip=flow_in.dst_ip,
        next_hop="10.0.0.1",
        input_snmp=1,
        output_snmp=2,
        packets=flow_in.packets,
        bytes=flow_in.bytes,
        first_switched=now_ms - 1000,
        last_switched=now_ms,
        src_port=flow_in.src_port,
        dst_port=flow_in.dst_port,
        tcp_flags=flow_in.tcp_flags,
        protocol=flow_in.protocol,
        tos=0,
        src_as=0,
        dst_as=0,
        src_mask=24,
        dst_mask=24,
        campaign_id=flow_in.campaign_id,
        vector_id=flow_in.vector_id,
    )

    # 1. Registrar en el historial de flujos de la API y WebSocket
    system_state.record_flows([record])

    # 2. Analizar en el DetectionEngine
    alerts = engine.analyze_flow(record)
    alert_dicts = [a.to_dict() for a in alerts] if alerts else []

    return {
        "success": True,
        "status": "PROCESSED",
        "timestamp": now.isoformat(),
        "alerts_count": len(alerts),
        "alerts": alert_dicts,
        "source": identity.name,
    }


@router.post("/hook/batch")
async def ingest_telemetry_batch(
    batch: TelemetryBatchInput,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Inyecta un lote de múltiples flujos en una sola llamada atómica."""
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=503, detail="Motor de detección no inicializado")

    now = datetime.now(timezone.utc)
    now_ms = int(now.timestamp() * 1000) & 0x7FFFFFFF

    records = []
    for f in batch.flows:
        records.append(NetFlowRecord(
            timestamp=now,
            timestamp_ms=now_ms,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=f.packets,
            bytes=f.bytes,
            first_switched=now_ms - 1000,
            last_switched=now_ms,
            src_port=f.src_port,
            dst_port=f.dst_port,
            tcp_flags=f.tcp_flags,
            protocol=f.protocol,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id=f.campaign_id,
            vector_id=f.vector_id,
        ))

    system_state.record_flows(records)
    alerts = engine.analyze_batch(records)

    return {
        "success": True,
        "flows_processed": len(records),
        "alerts_triggered": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


@router.get("/status")
async def get_telemetry_status() -> Dict[str, Any]:
    """Retorna el estado del colector y las vías de ingestión activas."""
    engine = system_state.engine
    return {
        "status": "ONLINE",
        "ingestion_modes": {
            "netflow_udp_port": 2055,
            "netflow_versions": ["v5", "v9", "IPFIX"],
            "live_probe_target": "http://localhost:8080 (tools/live_probe.py)",
            "rest_hook_endpoint": "/api/v1/telemetry/hook",
            "pcap_offline_ingest": "Supported",
        },
        "total_flows_in_memory": len(system_state.recent_flows),
        "total_alerts": engine.stats.get("total_alerts", 0) if engine else 0,
    }
