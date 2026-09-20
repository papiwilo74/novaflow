"""
NovaFlow NDR - Metrics REST Router
Endpoints para telemetría de red, Top Talkers y distribución de protocolos.
"""

import time
from collections import defaultdict
from typing import Any, Dict, List
from fastapi import APIRouter

from api.state import system_state

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("/overview")
async def get_overview() -> Dict[str, Any]:
    """Retorna el pulso general de la red y el estado del motor NDR."""
    uptime = time.time() - system_state.start_time
    engine = system_state.engine

    return {
        "status": "HEALTHY",
        "uptime_seconds": int(uptime),
        "network_pulse": {
            "current_mbps": system_state.current_mbps,
            "current_pps": system_state.current_pps,
            "current_fps": system_state.current_fps,
        },
        "stats": {
            "total_flows_analyzed": engine.stats["flows_analyzed"] if engine else 0,
            "total_alerts": engine.stats["total_alerts"] if engine else 0,
            "severity_breakdown": engine.stats["by_severity"] if engine else {},
            "category_breakdown": engine.stats["by_category"] if engine else {},
        },
        "realtime": {
            "active_websockets": len(system_state.ws_manager.active_connections),
            "recent_flows_cached": len(system_state.recent_flows),
        },
    }


@router.get("/top-talkers")
async def get_top_talkers(limit: int = 10) -> List[Dict[str, Any]]:
    """Calcula los mayores consumidores de ancho de banda a partir de los flujos analizados."""
    ip_stats = defaultdict(lambda: {"bytes_sent": 0, "bytes_received": 0, "flows": 0, "packets": 0})

    for f in system_state.recent_flows:
        src = f["src_ip"]
        dst = f["dst_ip"]
        b = f["bytes"]
        p = f["packets"]

        ip_stats[src]["bytes_sent"] += b
        ip_stats[src]["packets"] += p
        ip_stats[src]["flows"] += 1

        ip_stats[dst]["bytes_received"] += b
        ip_stats[dst]["packets"] += p
        ip_stats[dst]["flows"] += 1

    top_list = []
    for ip, data in ip_stats.items():
        total_b = data["bytes_sent"] + data["bytes_received"]
        top_list.append({
            "ip": ip,
            "bytes_sent": data["bytes_sent"],
            "bytes_received": data["bytes_received"],
            "total_bytes": total_b,
            "total_mb": round(total_b / (1024 * 1024), 2),
            "packets": data["packets"],
            "flow_count": data["flows"],
        })

    top_list.sort(key=lambda x: x["total_bytes"], reverse=True)
    return top_list[:limit]


@router.get("/protocols")
async def get_protocols() -> List[Dict[str, Any]]:
    """Retorna la distribución de protocolos de transporte y volumetría."""
    proto_counts = defaultdict(lambda: {"flows": 0, "bytes": 0, "packets": 0})

    for f in system_state.recent_flows:
        p_name = f.get("protocol_name", str(f.get("protocol", "OTHER")))
        proto_counts[p_name]["flows"] += 1
        proto_counts[p_name]["bytes"] += f["bytes"]
        proto_counts[p_name]["packets"] += f["packets"]

    results = []
    total_f = max(1, len(system_state.recent_flows))
    for p_name, data in proto_counts.items():
        results.append({
            "protocol": p_name,
            "flow_count": data["flows"],
            "percentage": round((data["flows"] / total_f) * 100, 1),
            "bytes": data["bytes"],
            "packets": data["packets"],
        })

    results.sort(key=lambda x: x["flow_count"], reverse=True)
    return results
