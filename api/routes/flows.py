"""
NovaFlow NDR - Forensic Flows Explorer Router
Buscador de flujos de red estilo Wireshark/Kibana para análisis forense detallado.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query, Security

from api.state import system_state
from api.security.auth import Identity, get_current_identity

router = APIRouter(prefix="/flows", tags=["Forensic Flows Explorer"])


@router.get("")
async def search_flows(
    src_ip: Optional[str] = Query(None, description="Filtrar por IP origen"),
    dst_ip: Optional[str] = Query(None, description="Filtrar por IP destino"),
    port: Optional[int] = Query(None, description="Filtrar por puerto (origen o destino)"),
    protocol: Optional[int] = Query(None, description="Filtrar por protocolo L4 (6=TCP, 17=UDP, 1=ICMP)"),
    limit: int = Query(50, ge=1, le=200),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Explorador forense de flujos de red con filtros multicriterio y aislamiento multi-tenant."""
    flows = system_state.recent_flows

    # Filtrar por tenant si no es superusuario/global
    if identity.tenant_id != "*":
        flows = [f for f in flows if f.get("tenant_id", "default") == identity.tenant_id]

    if src_ip:
        flows = [f for f in flows if f["src_ip"] == src_ip]

    if dst_ip:
        flows = [f for f in flows if f["dst_ip"] == dst_ip]

    if port:
        flows = [f for f in flows if f["src_port"] == port or f["dst_port"] == port]

    if protocol:
        flows = [f for f in flows if f["protocol"] == protocol]

    # Mostrar los más recientes primero
    reversed_flows = list(reversed(flows))
    sliced = reversed_flows[:limit]

    return {
        "tenant_id": identity.tenant_id,
        "total_matched": len(flows),
        "returned": len(sliced),
        "flows": sliced,
    }
