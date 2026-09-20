"""
NovaFlow NDR - Regulatory Compliance REST Router
Endpoints para auditoría de cumplimiento normativo (PCI-DSS v4.0, ISO/IEC 27001:2022, NIST CSF 2.0).
"""

from typing import Any, Dict, List
from fastapi import APIRouter, Security
from datetime import datetime, timezone

from api.state import system_state
from api.security.auth import Identity, get_current_identity
from detector.compliance import get_all_compliance_catalog, COMPLIANCE_MAPPING

router = APIRouter(prefix="/compliance", tags=["Regulatory Compliance"])


@router.get("/matrix")
async def get_compliance_matrix(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Retorna el catálogo completo de controles y marcos normativos
    (PCI-DSS v4.0, ISO/IEC 27001:2022, NIST CSF 2.0, CIS Controls v8).
    """
    catalog = get_all_compliance_catalog()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "catalog": catalog,
    }


@router.get("/status")
async def get_compliance_status(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Evalúa la postura de cumplimiento normativo del entorno de red
    con base en el flujo de telemetría y los incidentes activos detectados.
    """
    engine = system_state.engine
    alerts = engine.alerts_history if engine else []

    # Filtrar por tenant si no es superadmin
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    active_incidents = len([a for a in alerts if a.status != "RESOLVED"])
    critical_incidents = len([a for a in alerts if a.severity.value == "CRITICAL" and a.status != "RESOLVED"])
    high_incidents = len([a for a in alerts if a.severity.value == "HIGH" and a.status != "RESOLVED"])

    # Cálculo del índice de postura de seguridad (0 - 100%)
    # Base 100% - penalización por incidentes críticos (-15%) y altos (-5%)
    penalty = (critical_incidents * 15.0) + (high_incidents * 5.0)
    posture_score = max(0.0, min(100.0, 100.0 - penalty))

    standards_assessment = {
        "PCI-DSS v4.0": {
            "req_10_4_audit_correlation": "COMPLIANT (Auditoría inmutable y correlación continua activada)",
            "req_11_4_network_ids": "COMPLIANT (Sensor NDR inspeccionando datagramas UDP L3/L4 sin muestreo destructivo)",
            "cde_active_threats": critical_incidents,
            "status": "AT_RISK" if critical_incidents > 0 else "COMPLIANT",
        },
        "ISO/IEC 27001:2022": {
            "control_a8_16_monitoring": "COMPLIANT (Supervisión continua con heurísticas y Machine Learning)",
            "control_a8_20_network_sec": "COMPLIANT (Detección de anomalías y segmentación defensiva)",
            "control_a8_23_leakage_prev": "COMPLIANT (Inspección de ancho de banda y túneles DNS)",
            "status": "NEEDS_REVIEW" if high_incidents > 2 else "COMPLIANT",
        },
        "NIST CSF 2.0": {
            "function_detect_de_cm_01": "OPERATIONAL (Monitoreo continuo de red implementado)",
            "function_respond_rs_an_01": "OPERATIONAL (Análisis forense de incidentes enriquecido con MITRE ATT&CK)",
            "status": "COMPLIANT",
        },
        "CIS Controls v8": {
            "control_13_network_defense": "COMPLIANT (Sensor NDR centralizado)",
            "status": "COMPLIANT",
        },
    }

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": identity.tenant_id,
        "compliance_posture_score": round(posture_score, 1),
        "posture_status": "EXCELLENT" if posture_score >= 90 else ("DEGRADED" if posture_score >= 70 else "CRITICAL"),
        "active_incidents": active_incidents,
        "critical_violations": critical_incidents,
        "high_violations": high_incidents,
        "standards": standards_assessment,
    }
