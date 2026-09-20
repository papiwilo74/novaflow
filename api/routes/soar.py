"""
NovaFlow NDR - SOAR Active Dispatcher & Webhooks REST Router
Endpoints para gestión de webhooks externos, inspección de Dead-Letter Queue (DLQ) y reintentos.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Security
from pydantic import BaseModel, HttpUrl

from api.state import system_state
from api.security.auth import Identity, Role, get_current_identity, require_role

router = APIRouter(prefix="/soar", tags=["SOAR Active Dispatcher"])


class WebhookRegisterRequest(BaseModel):
    name: str
    url: str
    secret: Optional[str] = ""
    min_severity: Optional[str] = "HIGH"
    enabled: Optional[bool] = True


@router.post("/webhooks/register")
async def register_webhook(
    req: WebhookRegisterRequest,
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Registra un nuevo webhook receptor de alertas con firma HMAC-SHA256."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "soar_dispatcher"):
        raise HTTPException(status_code=503, detail="Despachador SOAR no inicializado")

    sub = engine.soar_dispatcher.register_webhook(
        name=req.name,
        url=req.url,
        secret=req.secret or "",
        min_severity=req.min_severity or "HIGH",
        enabled=req.enabled if req.enabled is not None else True,
    )
    return {"status": "SUCCESS", "webhook": sub.to_dict()}


@router.get("/webhooks")
async def list_webhooks(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Lista todos los webhooks registrados."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "soar_dispatcher"):
        return {"webhooks": []}

    return {"webhooks": engine.soar_dispatcher.list_webhooks()}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    identity: Identity = Security(require_role([Role.ADMIN])),
) -> Dict[str, Any]:
    """Elimina una suscripción de webhook por su ID."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "soar_dispatcher"):
        raise HTTPException(status_code=503, detail="Despachador SOAR no inicializado")

    success = engine.soar_dispatcher.delete_webhook(webhook_id)
    if not success:
        raise HTTPException(status_code=404, detail="Webhook no encontrado")

    return {"status": "DELETED", "webhook_id": webhook_id}


@router.get("/dlq")
async def get_dead_letter_queue(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Inspecciona los incidentes que no pudieron ser entregados tras agotar reintentos."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "soar_dispatcher"):
        return {"total": 0, "dlq": []}

    items = engine.soar_dispatcher.get_dlq()
    return {"total": len(items), "dlq": items}


@router.post("/dlq/retry")
async def retry_dead_letter_queue(
    dlq_id: Optional[str] = None,
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Reintenta el despacho de mensajes pendientes en la Dead-Letter Queue."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "soar_dispatcher"):
        raise HTTPException(status_code=503, detail="Despachador SOAR no inicializado")

    return engine.soar_dispatcher.retry_dlq(dlq_id=dlq_id)


@router.get("/containments")
async def list_containments(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Lista las acciones de aislamiento automático disparadas por el motor de auto-contención."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "soar_dispatcher"):
        return {"total": 0, "containments": []}

    actions = engine.soar_dispatcher.get_containments()
    return {"total": len(actions), "containments": actions}
