"""
NovaFlow NDR - Threat Intelligence REST Router
Endpoints para gestión del Filtro de Bloom Contable, consulta de estado de feeds y sincronización en vivo.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel

from api.state import system_state
from api.security.auth import Identity, Role, get_current_identity, require_role

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


class SyncFeedRequest(BaseModel):
    custom_feed_text: Optional[str] = None


class AddIocRequest(BaseModel):
    ip: str
    threat_name: str
    threat_actor: Optional[str] = "Unknown"
    confidence: Optional[float] = 0.90


@router.get("/status")
async def get_threat_intel_status(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna el estado de salud, memoria utilizada por el Bloom Filter y último sincronizado."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "bloom_intel"):
        raise HTTPException(status_code=503, detail="Motor de Threat Intel no inicializado")

    return engine.bloom_intel.get_status()


@router.post("/sync")
async def trigger_threat_intel_sync(
    req: Optional[SyncFeedRequest] = None,
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Dispara la sincronización de feeds de reputación de C2 (Feodo Tracker) en caliente."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "bloom_intel"):
        raise HTTPException(status_code=503, detail="Motor de Threat Intel no inicializado")

    custom_text = req.custom_feed_text if req else None
    res = engine.bloom_intel.sync_public_feeds(custom_feed_text=custom_text)
    return res


@router.post("/iocs")
async def add_custom_ioc(
    req: AddIocRequest,
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Inserta manualmente un nuevo indicador de compromiso (IOC) en el Bloom Filter."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "bloom_intel"):
        raise HTTPException(status_code=503, detail="Motor de Threat Intel no inicializado")

    engine.bloom_intel.add_ioc(
        ip=req.ip,
        threat_name=req.threat_name,
        threat_actor=req.threat_actor or "Custom",
        confidence=req.confidence if req.confidence is not None else 0.90,
        source="SOC_MANUAL",
    )
    return {"status": "SUCCESS", "ip": req.ip, "threat_name": req.threat_name}


@router.delete("/iocs/{ip}")
async def remove_custom_ioc(
    ip: str,
    identity: Identity = Security(require_role([Role.ADMIN])),
) -> Dict[str, Any]:
    """Elimina o expira un indicador del Bloom Filter en tiempo real."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "bloom_intel"):
        raise HTTPException(status_code=503, detail="Motor de Threat Intel no inicializado")

    removed = engine.bloom_intel.remove_ioc(ip)
    if not removed:
        raise HTTPException(status_code=404, detail=f"IOC {ip} no encontrado")

    return {"status": "REMOVED", "ip": ip}
