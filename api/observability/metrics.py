"""
NovaFlow NDR - Prometheus Observability & Metrics Exporter
Exposición de métricas en formato estándar Prometheus (/metrics) para Grafana y alertas de infraestructura.
"""

import time
from typing import Dict
from fastapi import APIRouter, Response

from api.state import system_state
from detector.models import AlertCategory, AlertSeverity

router = APIRouter(tags=["Observability & Prometheus"])


def generate_prometheus_metrics() -> str:
    """Genera el payload en formato estándar de Prometheus (text/plain)."""
    now = time.time()
    uptime = now - system_state.start_time
    engine = system_state.engine

    lines = []

    # 1. HELP & TYPE Uptime
    lines.append("# HELP novaflow_uptime_seconds Tiempo total de actividad del servicio NDR en segundos.")
    lines.append("# TYPE novaflow_uptime_seconds gauge")
    lines.append(f"novaflow_uptime_seconds {int(uptime)}")

    # 2. Throughput Gauges
    lines.append("# HELP novaflow_throughput_mbps Consumo instantáneo de ancho de banda en megabits por segundo.")
    lines.append("# TYPE novaflow_throughput_mbps gauge")
    lines.append(f"novaflow_throughput_mbps {system_state.current_mbps:.2f}")

    lines.append("# HELP novaflow_flows_per_second Tasa de flujos NetFlow procesados por segundo.")
    lines.append("# TYPE novaflow_flows_per_second gauge")
    lines.append(f"novaflow_flows_per_second {system_state.current_fps:.1f}")

    lines.append("# HELP novaflow_packets_per_second Tasa de paquetes por segundo.")
    lines.append("# TYPE novaflow_packets_per_second gauge")
    lines.append(f"novaflow_packets_per_second {system_state.current_pps:.1f}")

    # 3. Queue & Ingestion Counters
    total_flows = engine.stats["flows_analyzed"] if engine else 0
    lines.append("# HELP novaflow_flows_ingested_total Contador acumulado de flujos analizados desde el inicio.")
    lines.append("# TYPE novaflow_flows_ingested_total counter")
    lines.append(f"novaflow_flows_ingested_total {total_flows}")

    # 4. WebSocket Active Clients
    ws_count = len(system_state.ws_manager.active_connections)
    lines.append("# HELP novaflow_active_ws_clients Cantidad de dashboards o clientes conectados por WebSocket.")
    lines.append("# TYPE novaflow_active_ws_clients gauge")
    lines.append(f"novaflow_active_ws_clients {ws_count}")

    # 5. Security Alerts Counters por Severidad y Categoría
    lines.append("# HELP novaflow_alerts_total Contador acumulado de alertas emitidas por severidad y categoría.")
    lines.append("# TYPE novaflow_alerts_total counter")

    if engine:
        for sev in AlertSeverity:
            cnt = engine.stats["by_severity"].get(sev.value, 0)
            lines.append(f'novaflow_alerts_total{{severity="{sev.value}",dimension="severity"}} {cnt}')

        for cat in AlertCategory:
            cnt = engine.stats["by_category"].get(cat.value, 0)
            lines.append(f'novaflow_alerts_total{{category="{cat.value}",dimension="category"}} {cnt}')
    else:
        lines.append('novaflow_alerts_total{severity="TOTAL"} 0')

    return "\n".join(lines) + "\n"


@router.get("/metrics")
async def prometheus_metrics_endpoint():
    """Endpoint oficial para scraping de Prometheus / OpenTelemetry Collector."""
    metrics_text = generate_prometheus_metrics()
    return Response(content=metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
