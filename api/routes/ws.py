"""
NovaFlow NDR - Real-Time WebSocket Streaming Router
Canal bidireccional para transmisión en vivo de throughput, flujos y alertas críticas.
"""

import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.state import system_state

logger = logging.getLogger("NovaFlow.API.WebSocket")
router = APIRouter(tags=["Real-Time WebSockets"])


@router.websocket("/ws/stream")
async def websocket_stream_endpoint(websocket: WebSocket):
    """
    Endpoint WebSocket de alta concurrencia para el Dashboard Frontend.
    Transmite:
    1. NETWORK_PULSE: Rendimiento de red en vivo (Mbps, PPS, FPS).
    2. SECURITY_ALERT: Eventos de seguridad empujados al instante en que se detectan.
    """
    await system_state.ws_manager.connect(websocket)

    # Enviar estado inicial inmediato al cliente recién conectado
    try:
        engine = system_state.engine
        await websocket.send_json({
            "type": "CONNECTION_ESTABLISHED",
            "data": {
                "message": "Conectado al bus de telemetría de NovaFlow NDR",
                "current_mbps": system_state.current_mbps,
                "current_fps": system_state.current_fps,
                "total_alerts": engine.stats["total_alerts"] if engine else 0,
                "alerts_summary": engine.stats["by_severity"] if engine else {},
            },
        })

        while True:
            # Esperar mensajes del cliente (p. ej. pings o comandos)
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        system_state.ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"Excepción en websocket loop: {e}")
        system_state.ws_manager.disconnect(websocket)
