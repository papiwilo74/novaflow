"""
NovaFlow NDR - API Shared State & WebSocket Connection Manager
Gestiona la memoria compartida entre el colector UDP, motor de detección y clientes WebSockets.
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set
from fastapi import WebSocket

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import SecurityAlert

logger = logging.getLogger("NovaFlow.API.State")


class ConnectionManager:
    """Administrador de conexiones WebSocket para streaming en tiempo real."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Cliente WebSocket conectado. Total activos: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"Cliente WebSocket desconectado. Restantes: {len(self.active_connections)}")

    async def broadcast_json(self, data: Dict[str, Any]):
        """Transmite un mensaje JSON a todos los navegadores/dashboards conectados."""
        if not self.active_connections:
            return

        dead_connections = set()
        for conn in list(self.active_connections):
            try:
                await conn.send_json(data)
            except Exception:
                dead_connections.add(conn)

        for dead in dead_connections:
            self.active_connections.discard(dead)


class SystemState:
    """Estado global del sistema accesible por los controladores REST y WebSockets."""

    def __init__(self):
        self.ws_manager = ConnectionManager()
        self.engine: Optional[DetectionEngine] = None
        self.recent_flows: List[Dict[str, Any]] = []
        self.max_recent_flows = 2000

        # Métricas en tiempo real
        self.start_time = time.time()
        self.last_sample_time = time.time()
        self.period_bytes = 0
        self.period_packets = 0
        self.period_flows = 0

        self.current_mbps = 0.0
        self.current_pps = 0.0
        self.current_fps = 0.0

        # Tarea en background de telemetría por WebSocket
        self._telemetry_task: Optional[asyncio.Task] = None

    def initialize(self, engine: DetectionEngine):
        self.engine = engine

        # Conectar callback del motor de detección para retransmitir alertas en tiempo real por WebSocket
        self.engine.register_listener(self.on_security_alert)

    def record_flows(self, records: List[NetFlowRecord]):
        """Almacena muestras de flujos recientes y actualiza contadores para throughput."""
        now = time.time()
        batch_bytes = sum(r.bytes for r in records)
        batch_packets = sum(r.packets for r in records)
        batch_count = len(records)

        self.period_bytes += batch_bytes
        self.period_packets += batch_packets
        self.period_flows += batch_count

        # Agregar al buffer circular de flujos forenses
        for r in records[:50]:  # muestra representativa para UI
            flow_dict = {
                "timestamp": r.timestamp.isoformat(),
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "protocol": r.protocol,
                "protocol_name": "TCP" if r.protocol == 6 else ("UDP" if r.protocol == 17 else "ICMP"),
                "packets": r.packets,
                "bytes": r.bytes,
                "tcp_flags": r.tcp_flags,
            }
            self.recent_flows.append(flow_dict)

        if len(self.recent_flows) > self.max_recent_flows:
            self.recent_flows = self.recent_flows[-self.max_recent_flows:]

    def on_security_alert(self, alert: SecurityAlert):
        """Callback invocado cuando el motor de detección genera una alerta."""
        # Enviar inmediatamente por WebSocket de forma asíncrona
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(
                    self.ws_manager.broadcast_json({
                        "type": "SECURITY_ALERT",
                        "data": alert.to_dict(),
                    })
                )
        except Exception as e:
            logger.debug(f"Error despachando alerta por websocket: {e}")

    async def start_telemetry_broadcast(self, interval_seconds: float = 1.0):
        """Emite periódicamente el pulso de ancho de banda y métricas vía WebSocket."""
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                now = time.time()
                elapsed = max(0.1, now - self.last_sample_time)

                self.current_mbps = round((self.period_bytes * 8) / (elapsed * 1_000_000), 2)
                self.current_pps = round(self.period_packets / elapsed, 1)
                self.current_fps = round(self.period_flows / elapsed, 1)

                self.last_sample_time = now
                self.period_bytes = 0
                self.period_packets = 0
                self.period_flows = 0

                telemetry_payload = {
                    "type": "NETWORK_PULSE",
                    "data": {
                        "timestamp": now,
                        "mbps": self.current_mbps,
                        "pps": self.current_pps,
                        "fps": self.current_fps,
                        "total_flows": self.engine.stats["flows_analyzed"] if self.engine else 0,
                        "total_alerts": self.engine.stats["total_alerts"] if self.engine else 0,
                        "active_ws_clients": len(self.ws_manager.active_connections),
                    },
                }
                await self.ws_manager.broadcast_json(telemetry_payload)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error en broadcast de telemetría: {e}")


# Singleton de estado global
system_state = SystemState()
