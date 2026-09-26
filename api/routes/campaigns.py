"""
NovaFlow NDR - Campaign Correlator REST Router
Endpoints para visualización y triaje de campañas de intrusión multi-etapa
consolidadas mediante correlación causal bayesiana.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Security
from pydantic import BaseModel

from api.security.auth import Identity, Role, get_current_identity, require_role
from api.state import system_state

router = APIRouter(prefix="/campaigns", tags=["Bayesian Campaign Correlator"])


class UpdateStatusRequest(BaseModel):
    status: str


@router.get("")
async def list_campaigns(
    status: Optional[str] = Query(None, description="Filtro por estado (ACTIVE, ESCALATED, RESOLVED)"),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna los casos de intrusión consolidados clasificados por certeza bayesiana decreciente."""
    engine = getattr(system_state, "campaign_engine", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Motor de correlación de campañas no inicializado")

    cases = engine.list_cases(status=status)
    return {
        "total_campaigns": len(cases),
        "campaigns": [c.to_dict() for c in cases],
    }


@router.get("/{campaign_id}")
async def get_campaign_detail(
    campaign_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Obtiene el informe causal completo de una campaña multi-etapa."""
    engine = getattr(system_state, "campaign_engine", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Motor de correlación de campañas no inicializado")

    case = engine.get_case(campaign_id)
    if not case:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")

    return case.to_dict()


@router.post("/{campaign_id}/status")
async def update_campaign_status(
    campaign_id: str,
    req: UpdateStatusRequest,
    identity: Identity = Security(require_role(Role.ADMIN)),
) -> Dict[str, Any]:
    """Actualiza el estado de contención o resolución de una campaña."""
    engine = getattr(system_state, "campaign_engine", None)
    if not engine:
        raise HTTPException(status_code=503, detail="Motor de correlación de campañas no inicializado")

    case = engine.get_case(campaign_id)
    if not case:
        raise HTTPException(status_code=404, detail="Campaña no encontrada")

    case.status = req.status.upper()
    return {
        "campaign_id": case.campaign_id,
        "new_status": case.status,
    }
