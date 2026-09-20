"""
NovaFlow NDR - Threat Hunting REST Router
Endpoints para ejecución de búsquedas proactivas en flujos y catálogo de playbooks de caza.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Security
from pydantic import BaseModel

from api.state import system_state
from api.security.auth import Identity, get_current_identity
from detector.hunting import ThreatHuntingParser, execute_flow_hunt, HUNTING_PLAYBOOKS

router = APIRouter(prefix="/flows/hunt", tags=["Threat Hunting Engine"])


class FlowHuntRequest(BaseModel):
    query: str
    limit: Optional[int] = 100


@router.get("/playbooks")
async def get_hunting_playbooks(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna el catálogo canónico de playbooks de Threat Hunting para el SOC."""
    return {
        "total_playbooks": len(HUNTING_PLAYBOOKS),
        "playbooks": HUNTING_PLAYBOOKS,
    }


@router.post("")
async def execute_hunt(
    req: FlowHuntRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Ejecuta una consulta booleana DSL de Threat Hunting sobre el histórico de flujos en memoria.
    Ejemplo: proto == TCP AND dst_port IN [445, 3389] AND bytes > 50K
    """
    engine = system_state.engine
    if not engine:
        raise HTTPException(status_code=503, detail="Motor de telemetría no inicializado")

    # Recuperar flujos de la ventana histórica
    flows = list(system_state.recent_flows) if hasattr(system_state, "recent_flows") else []

    try:
        res = execute_flow_hunt(query=req.query, flows=flows, limit=req.limit or 100)
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Error sintáctico en consulta Threat Hunting: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante la ejecución del hunt: {str(e)}")
