"""
NovaFlow NDR - Executive & Compliance Reports REST Router
Endpoints para generación y descarga de informes ejecutivos (JSON e HTML imprimible).
"""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Query, Security
from fastapi.responses import HTMLResponse

from api.security.auth import Identity, Role, get_current_identity, require_role
from api.state import system_state
from reports.executive_report import ExecutiveReportGenerator

router = APIRouter(prefix="/reports", tags=["Executive Reports"])


@router.get("/executive")
async def get_executive_report_json(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Genera el informe ejecutivo en formato JSON estructurado con Risk Score (0-100),
    postura frente a PCI-DSS v4.0 / ISO 27001 y desglose de incidentes forenses.
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor de detección no inicializado")

    alerts = engine.alerts_history
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    flows = list(system_state.recent_flows)
    return ExecutiveReportGenerator.generate_report_data(
        alerts=alerts,
        recent_flows=flows,
        tenant_id=identity.tenant_id,
    )


@router.get("/executive/html", response_class=HTMLResponse)
async def get_executive_report_html(
    identity: Identity = Security(get_current_identity),
) -> str:
    """
    Renderiza el informe ejecutivo interactivo e imprimible en el navegador
    con soporte directo para exportar a PDF (Ctrl+P / Command+P).
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor de detección no inicializado")

    alerts = engine.alerts_history
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    flows = list(system_state.recent_flows)
    return ExecutiveReportGenerator.generate_html_report(
        alerts=alerts,
        recent_flows=flows,
        tenant_id=identity.tenant_id,
    )


@router.get("/pci-dss")
async def get_pci_dss_report(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Genera un informe especializado enfocado estrictamente en los requisitos
    PCI-DSS v4.0 (Req 10.4 y Req 11.4) para auditores QSA bancarios.
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=404, detail="Motor de detección no inicializado")

    alerts = engine.alerts_history
    if identity.tenant_id != "*":
        alerts = [a for a in alerts if getattr(a, "tenant_id", "default") == identity.tenant_id]

    data = ExecutiveReportGenerator.generate_report_data(alerts=alerts, recent_flows=list(system_state.recent_flows), tenant_id=identity.tenant_id)
    return {
        "standard": "PCI-DSS v4.0",
        "scope": "Cardholder Data Environment (CDE) & Network Perimeter",
        "evaluation_timestamp": data["generated_at"],
        "compliance_status": data["compliance_evaluation"]["pci_dss"]["status"],
        "evaluated_requirements": [
            {
                "requirement_id": "10.4",
                "title": "Registro y retención de pistas de auditoría de red",
                "status": "COMPLIANT",
                "details": "NovaFlow NDR captura flujos NetFlow v5/v9 y genera bitácoras en formato CEF / Syslog RFC 5424.",
            },
            {
                "requirement_id": "11.4",
                "title": "Detección e inspección de intrusiones en el perímetro y CDE",
                "status": data["compliance_evaluation"]["pci_dss"]["status"],
                "active_breaches_detected": data["compliance_evaluation"]["pci_dss"]["active_breaches"],
            },
        ],
        "risk_score": data["risk_assessment"]["risk_score"],
        "recommendations": [
            "Revisar y mitigar inmediatamente los incidentes de severidad CRITICAL y HIGH identificados.",
            "Aplicar los playbooks de contención SOAR en los firewalls de frontera perimetral.",
        ],
    }
