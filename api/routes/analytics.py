"""
NovaFlow NDR - Columnar Analytics REST Router
Endpoints analíticos de alta velocidad para agregaciones masivas y consultas
sobre el motor de almacenamiento columnar (.nfc / ClickHouse).
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Security
from pydantic import BaseModel, Field

from api.security.auth import Identity, get_current_identity
from api.state import system_state
from storage.clickhouse_adapter import ClickHouseAdapter

router = APIRouter(prefix="/analytics", tags=["Columnar Analytics Engine"])


class AnalyticsQueryRequest(BaseModel):
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    columns: Optional[List[str]] = None
    limit: Optional[int] = 100


@router.post("/query")
async def execute_columnar_query(
    req: AnalyticsQueryRequest,
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """
    Ejecuta una consulta analítica vectorizada sobre los bloques columnares indexados.
    Permite poda de bloques por ZoneMap (min/max time, puertos, IPs).
    """
    storage = getattr(system_state, "columnar_storage", None)
    if not storage:
        raise HTTPException(status_code=503, detail="Motor analítico columnar no inicializado")

    results = storage.query(
        filters=req.filters,
        columns=req.columns,
        limit=req.limit or 100,
    )
    return {
        "total_returned": len(results),
        "limit": req.limit,
        "results": results,
    }


@router.get("/top-talkers")
async def get_top_talkers(
    limit: int = Query(10, ge=1, le=100),
    by: str = Query("bytes", pattern="^(bytes|packets)$"),
    direction: str = Query("src", pattern="^(src|dst)$"),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Calcula los principales comunicadores de la red usando el almacén columnar."""
    storage = getattr(system_state, "columnar_storage", None)
    if not storage:
        raise HTTPException(status_code=503, detail="Motor analítico columnar no inicializado")

    by_bytes = by == "bytes"
    talkers = storage.aggregate_top_talkers(limit=limit, by_bytes=by_bytes, direction=direction)
    return {
        "metric": by,
        "direction": direction,
        "count": len(talkers),
        "top_talkers": talkers,
    }


@router.get("/protocols")
async def get_protocols_breakdown(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Retorna la distribución institucional de protocolos observados."""
    storage = getattr(system_state, "columnar_storage", None)
    if not storage:
        raise HTTPException(status_code=503, detail="Motor analítico columnar no inicializado")

    breakdown = storage.aggregate_protocols()
    return {
        "protocols": breakdown,
    }


@router.get("/timeline")
async def get_traffic_timeline(
    bucket_seconds: int = Query(60, ge=1, le=3600),
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Genera series temporales agregadas por cubeta para visualizaciones en dashboards."""
    storage = getattr(system_state, "columnar_storage", None)
    if not storage:
        raise HTTPException(status_code=503, detail="Motor analítico columnar no inicializado")

    timeline = storage.aggregate_timeline(bucket_seconds=bucket_seconds)
    return {
        "bucket_seconds": bucket_seconds,
        "points": len(timeline),
        "timeline": timeline,
    }


@router.get("/status")
async def get_storage_status(
    identity: Identity = Security(get_current_identity),
) -> Dict[str, Any]:
    """Informa del estado del almacenamiento columnar y esquema ClickHouse."""
    storage = getattr(system_state, "columnar_storage", None)
    total_flows = storage.total_flows() if storage else 0
    frozen_blocks = len(storage.frozen_blocks) if storage else 0

    return {
        "engine": "NovaFlow Columnar Engine (.nfc)",
        "clickhouse_compatible": True,
        "total_indexed_flows": total_flows,
        "active_blocks": frozen_blocks + 1,
        "clickhouse_ddl_available": True,
    }
