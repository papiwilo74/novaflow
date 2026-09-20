"""
NovaFlow NDR - Multi-Cluster Federation REST Router
Endpoints para visualización centralizada de clusters en diferentes regiones.
"""

from typing import Any, Dict
from fastapi import APIRouter, Security

from api.federation.manager import federation_manager
from api.security.auth import Identity, Role, require_role

router = APIRouter(prefix="/federation", tags=["Multi-Cluster Federation"])


@router.get("/clusters")
async def get_federated_clusters(
    identity: Identity = Security(require_role([Role.ADMIN, Role.ANALYST])),
) -> Dict[str, Any]:
    """Retorna el estado y métricas agregadas de todos los clusters NovaFlow federados."""
    return federation_manager.get_global_telemetry()
