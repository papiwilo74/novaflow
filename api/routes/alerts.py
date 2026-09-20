"""
NovaFlow NDR - Security Alerts REST Router
Endpoints para gestión de incidentes forenses, filtrado y actualización de estado.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Security, Request
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel

from api.state import system_state
from api.security.auth import Identity, Role, get_current_identity, require_role
from api.security.audit import audit_logger
from detector.models import AlertCategory, AlertSeverity

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


class AlertStatusUpdate(BaseModel):
    status: str  # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE


@router.get("")
async def list_alerts(
    severity: Optional[str] = Query(None, description="Filtrar por severidad (LOW, MEDIUM, HIGH, CRITICAL)"),
    category: Optional[str] = Query(None, description="Filtrar por categoría de ataque"),
    src_ip: Optional[str] = Query(None, description="Filtrar por IP origen"),
    status: Optional[str] = Query(None, description="Filtrar por estado del incidente"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna listado paginado de alertas de seguridad con filtros avanzados y aislamiento multi-tenant."""
    engine = system_state.engine
    if not engine:
        return {"total": 0, "alerts": []}

    filtered = engine.alerts_history

    # Aislamiento Multi-Tenancy: usuarios no-admin solo ven su propio tenant
    if identity.tenant_id != "*":
        filtered = [a for a in filtered if getattr(a, "tenant_id", "default") == identity.tenant_id]

    if severity:
        sev_upper = severity.upper()
        filtered = [a for a in filtered if a.severity.value == sev_upper]

    if category:
        cat_upper = category.upper()
        filtered = [a for a in filtered if a.category.value == cat_upper]

    if src_ip:
        filtered = [a for a in filtered if a.src_ip == src_ip]

    if status:
        stat_upper = status.upper()
        filtered = [a for a in filtered if a.status == stat_upper]

    # Orden descendente (más reciente primero)
    sorted_alerts = list(reversed(filtered))
    paginated = sorted_alerts[offset : offset + limit]

    return {
        "total": len(filtered),
        "offset": offset,
        "limit": limit,
        "tenant_id": identity.tenant_id,
        "alerts": [a.to_dict() for a in paginated],
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Obtiene el registro forense detallado de un incidente específico respetando el aislamiento por tenant."""
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")

    for a in engine.alerts_history:
        if a.alert_id == alert_id:
            # Validar permisos de acceso por tenant
            if not identity.can_access_tenant(getattr(a, "tenant_id", "default")):
                raise HTTPException(status_code=403, detail="Acceso denegado a alerta de otro tenant")
            return a.to_dict()

    raise HTTPException(status_code=404, detail=f"Alerta con ID {alert_id} no encontrada")


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    request: Request,
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Actualiza el estado operativo de un incidente (requiere rol ADMIN o ANALYST) y registra auditoría inmutable."""
    valid_statuses = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    new_stat = update.status.upper()
    if new_stat not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Estado inválido. Opciones válidas: {list(valid_statuses)}",
        )

    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")

    for a in engine.alerts_history:
        if a.alert_id == alert_id:
            if not identity.can_access_tenant(getattr(a, "tenant_id", "default")):
                raise HTTPException(status_code=403, detail="Acceso denegado: alerta pertenece a otro tenant")

            old_stat = a.status
            a.status = new_stat

            # Registrar en log de auditoría inmutable
            client_ip = request.client.host if request.client else "127.0.0.1"
            audit_logger.log(
                user_id=identity.identity_id,
                role=identity.role,
                tenant_id=identity.tenant_id,
                action="ALERT_STATUS_UPDATE",
                resource_id=alert_id,
                client_ip=client_ip,
                details={"old_status": old_stat, "new_status": new_stat},
                status="SUCCESS",
            )

            return {
                "message": f"Estado de la alerta {alert_id} actualizado a {new_stat}",
                "alert": a.to_dict(),
            }

    raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")


@router.get("/{alert_id}/playbook")
async def get_alert_mitigation_playbook(
    alert_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Genera el Playbook SOAR de mitigación y comandos de bloqueo de firewall
    (iptables, nftables, Cisco ACL, AWS NACL) específicos para este incidente.
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor no inicializado")

    for a in engine.alerts_history:
        if a.alert_id == alert_id:
            if identity.tenant_id != "*" and getattr(a, "tenant_id", "default") != identity.tenant_id:
                raise HTTPException(status_code=403, detail="Acceso denegado: alerta pertenece a otro tenant")

            from detector.playbooks import MitigationPlaybookGenerator
            playbook = MitigationPlaybookGenerator.generate_playbook(a)
            return playbook.to_dict()

    raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")


@router.get("/{alert_id}/pcap")
async def download_alert_pcap(
    alert_id: str,
    identity: Identity = Security(get_current_identity),
):
    """
    Descarga el archivo PCAP (formato libpcap estándar de Wireshark/tcpdump)
    con los paquetes del incidente y evidencia digital sintetizada.
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor no inicializado")

    for a in engine.alerts_history:
        if a.alert_id == alert_id:
            if identity.tenant_id != "*" and getattr(a, "tenant_id", "default") != identity.tenant_id:
                raise HTTPException(status_code=403, detail="Acceso denegado: alerta pertenece a otro tenant")

            from collector.forensics import ForensicEvidenceCollector
            # Filtrar flujos asociados en memoria si existen
            flows = [f for f in system_state.recent_flows if f.get("src_ip") == a.src_ip or f.get("dst_ip") == a.dst_ip]
            pcap_bytes, evidence = ForensicEvidenceCollector.generate_incident_pcap(a, associated_flows=flows if flows else None)

            return Response(
                content=pcap_bytes,
                media_type="application/vnd.tcpdump.pcap",
                headers={
                    "Content-Disposition": f'attachment; filename="incident_{alert_id}.pcap"',
                    "X-Forensic-SHA256": evidence.sha256_hash,
                },
            )

    raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")


@router.get("/{alert_id}/evidence")
async def get_alert_evidence_metadata(
    alert_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Retorna los metadatos de cadena de custodia, hash criptográfico SHA-256
    y detalles forenses del archivo de captura de red.
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor no inicializado")

    for a in engine.alerts_history:
        if a.alert_id == alert_id:
            if identity.tenant_id != "*" and getattr(a, "tenant_id", "default") != identity.tenant_id:
                raise HTTPException(status_code=403, detail="Acceso denegado: alerta pertenece a otro tenant")

            from collector.forensics import ForensicEvidenceCollector
            flows = [f for f in system_state.recent_flows if f.get("src_ip") == a.src_ip or f.get("dst_ip") == a.dst_ip]
            _, evidence = ForensicEvidenceCollector.generate_incident_pcap(a, associated_flows=flows if flows else None)
            return evidence.to_dict()

    raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")


@router.get("/export/cef", response_class=PlainTextResponse)
async def export_alerts_cef(
    limit: int = Query(100, ge=1, le=1000),
    identity: Identity = Security(get_current_identity),
) -> str:
    """
    Exporta incidentes en formato estándar ArcSight Common Event Format (CEF).
    Compatible con SIEMs corporativos (Splunk, Elastic SIEM, Wazuh, QRadar).
    """
    engine = system_state.engine
    if not engine:
        return ""

    alerts = engine.alerts_history
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    lines = [a.to_cef() for a in list(reversed(alerts))[:limit]]
    return "\n".join(lines) + ("\n" if lines else "")


@router.get("/export/syslog", response_class=PlainTextResponse)
async def export_alerts_syslog(
    limit: int = Query(100, ge=1, le=1000),
    identity: Identity = Security(get_current_identity),
) -> str:
    """
    Exporta incidentes en formato estándar Syslog RFC 5424.
    Permite ingesta directa en collectors de syslog y servidores rsyslog/syslog-ng.
    """
    engine = system_state.engine
    if not engine:
        return ""

    alerts = engine.alerts_history
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    lines = [a.to_syslog_rfc5424() for a in list(reversed(alerts))[:limit]]
    return "\n".join(lines) + ("\n" if lines else "")


@router.get("/export/ocsf")
async def export_alerts_ocsf(
    limit: int = Query(100, ge=1, le=1000),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Exporta incidentes bajo el estándar OCSF v1.1.0 (Open Cybersecurity Schema Framework).
    Compatible con AWS Security Lake, Snowflake y Splunk.
    """
    engine = system_state.engine
    if not engine:
        return {"ocsf_version": "1.1.0", "total": 0, "findings": []}

    alerts = engine.alerts_history
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    selected = list(reversed(alerts))[:limit]
    findings = [a.to_ocsf() for a in selected]
    return {
        "ocsf_version": "1.1.0",
        "version": "1.1.0",
        "class_uid": 2001,
        "total": len(findings),
        "findings_count": len(findings),
        "findings": findings,
    }


@router.get("/{alert_id}/ocsf")
async def get_alert_ocsf(
    alert_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Exporta un incidente específico en formato individual OCSF v1.1.0."""
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor no inicializado")

    for a in engine.alerts_history:
        if a.alert_id == alert_id:
            if identity.tenant_id != "*" and getattr(a, "tenant_id", "default") != identity.tenant_id:
                raise HTTPException(status_code=403, detail="Acceso denegado: alerta pertenece a otro tenant")
            return a.to_ocsf()

    raise HTTPException(status_code=404, detail=f"Alerta {alert_id} no encontrada")
