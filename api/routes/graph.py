"""
NovaFlow NDR - Attack Graph & Blast Radius REST Router
Endpoints para visualización de topología Cytoscape/D3, análisis de Patient Zero y cálculo de Blast Radius.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Security

from api.state import system_state
from api.security.auth import Identity, get_current_identity

router = APIRouter(prefix="/graph", tags=["Attack Graph & Blast Radius"])


@router.get("/topology")
async def get_topology(
    compromised_only: bool = Query(False, description="Filtrar únicamente nodos y conexiones comprometidas"),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna la topología completa o filtrada en formato estándar JSON Cytoscape/D3."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "attack_graph"):
        return {"nodes": [], "edges": [], "summary": {"total_nodes": 0, "total_edges": 0, "compromised_nodes": 0}}

    return engine.attack_graph.export_topology_json(filter_compromised_only=compromised_only)


@router.get("/blast-radius/{host_ip}")
async def get_blast_radius(
    host_ip: str,
    max_depth: int = Query(3, ge=1, le=6, description="Profundidad máxima de saltos de red"),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Calcula el radio de explosión (Blast Radius) y Blast Score (0-100) para un host específico."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "attack_graph"):
        raise HTTPException(status_code=503, detail="Motor de grafos no inicializado")

    return engine.attack_graph.calculate_blast_radius(host_ip=host_ip, max_depth=max_depth)


@router.get("/patient-zero/{target_ip}")
async def get_patient_zero(
    target_ip: str,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Rastrea la cadena causal de intrusión hacia atrás para descubrir el Patient Zero de un host."""
    engine = system_state.engine
    if not engine or not hasattr(engine, "attack_graph"):
        raise HTTPException(status_code=503, detail="Motor de grafos no inicializado")

    result = engine.attack_graph.find_patient_zero(target_ip=target_ip)
    if not result:
        raise HTTPException(status_code=404, detail=f"Host {target_ip} no encontrado en la topología")

    return result
