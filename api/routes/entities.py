"""
NovaFlow NDR - Asset Entity Ledger REST Router
Endpoints para gestión del inventario dinámico de activos, consulta de identidades
y visualización del puntaje de riesgo (Threat Score) en tiempo real.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Security
from pydantic import BaseModel, Field

from api.security.auth import Identity, Role, get_current_identity, require_role
from api.state import system_state
from detector.entity import AssetRole

router = APIRouter(prefix="/entities", tags=["Asset Identity Ledger"])


class UpdateRoleRequest(BaseModel):
    role: AssetRole


class DHCPLeaseRequest(BaseModel):
    mac: str
    ip: str
    hostname: Optional[str] = None
    event_type: Optional[str] = "ACK"


@router.get("")
async def list_entities(
    role: Optional[AssetRole] = None,
    min_score: float = Query(0.0, ge=0.0, le=100.0),
    limit: int = Query(50, ge=1, le=200),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna la lista de activos corporativos clasificados por puntaje de riesgo decreciente."""
    ledger = getattr(system_state, "entity_ledger", None)
    if not ledger:
        raise HTTPException(status_code=503, detail="Libro mayor de activos no inicializado")

    entities = ledger.list_entities(role=role, min_score=min_score, limit=limit)
    return {
        "total_tracked": ledger.total_entities(),
        "returned": len(entities),
        "entities": [e.to_dict() for e in entities],
    }


@router.get("/{entity_id}")
async def get_entity_details(
    entity_id: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Obtiene los detalles forenses completos de una entidad de activo."""
    ledger = getattr(system_state, "entity_ledger", None)
    if not ledger:
        raise HTTPException(status_code=503, detail="Libro mayor de activos no inicializado")

    entity = ledger.get_by_id(entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entidad no encontrada en el libro mayor")

    return entity.to_dict()


@router.patch("/{entity_id}/role")
async def update_entity_role(
    entity_id: str,
    req: UpdateRoleRequest,
    identity: Identity = Security(require_role(Role.ADMIN)),
) -> Dict[str, Any]:
    """Actualiza el rol corporativo de un activo para recalibrar su multiplicador de riesgo."""
    ledger = getattr(system_state, "entity_ledger", None)
    if not ledger:
        raise HTTPException(status_code=503, detail="Libro mayor de activos no inicializado")

    entity = ledger.get_by_id(entity_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Entidad no encontrada en el libro mayor")

    entity.role = req.role
    return {
        "status": "UPDATED",
        "entity_id": entity.entity_id,
        "new_role": entity.role.value,
        "new_role_multiplier": entity.to_dict()["role_multiplier"],
        "threat_score": entity.calculate_dynamic_threat_score(),
    }


@router.get("/lookup/by-ip/{ip}")
async def lookup_entity_by_ip(
    ip: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Resuelve la entidad persistente que actualmente posee una dirección IP dada."""
    ledger = getattr(system_state, "entity_ledger", None)
    if not ledger:
        raise HTTPException(status_code=503, detail="Libro mayor de activos no inicializado")

    entity = ledger.get_by_ip(ip)
    if not entity:
        raise HTTPException(status_code=404, detail=f"No existe entidad activa para la IP {ip}")

    return entity.to_dict()


@router.post("/dhcp/lease")
async def process_dhcp_lease(
    req: DHCPLeaseRequest,
    identity: Identity = Security(require_role(Role.ADMIN)),
) -> Dict[str, Any]:
    """Inyecta un evento DHCP para actualizar el lease de una máquina."""
    tracker = getattr(system_state, "dhcp_tracker", None)
    if not tracker:
        raise HTTPException(status_code=503, detail="Rastreador DHCP no inicializado")

    result = tracker.process_lease_event(
        mac=req.mac,
        ip=req.ip,
        hostname=req.hostname,
        event_type=req.event_type or "ACK",
    )
    return result
