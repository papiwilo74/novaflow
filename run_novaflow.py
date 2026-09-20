"""
NovaFlow NDR - Master Enterprise Platform Runner
Inicia de forma concurrente el Colector UDP (2055), el Motor de Detección Heurístico/ML
y el Servidor API Gateway & Dashboard Web (8000).
"""

import argparse
import asyncio
import logging
import os
import sys
import uvicorn

# Garantizar sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from api.main import app
from api.state import system_state
from collector.server import NetFlowUDPServerProtocol
from collector.storage import ClickHouseBatchFlusher
from detector.engine import DetectionEngine
from generator.scenarios import TrafficScenarioGenerator
from generator.generator import NetFlowSender

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("NovaFlow.Master")


async def run_platform(
    udp_port: int = 2055,
    http_port: int = 8000,
    ch_host: str = "localhost",
    ch_port: int = 8123,
    auto_simulate: bool = False,
):
    print("=" * 80)
    print("                 NOVAFLOW NDR - ENTERPRISE PLATFORM                  ")
    print("                 NovaSec Technologies &bull; Cyber Operations        ")
    print("=" * 80)
    print(f"  [>] Web Dashboard UI  : http://localhost:{http_port}/dashboard")
    print(f"  [>] API Documentation : http://localhost:{http_port}/docs")
    print(f"  [>] NetFlow UDP Ingest: udp://0.0.0.0:{udp_port}")
    print(f"  [>] WebSocket Stream  : ws://localhost:{http_port}/ws/stream")
    print(f"  [>] ClickHouse Storage: http://{ch_host}:{ch_port}")
    print("=" * 80)

    # 1. Iniciar Storage Flusher
    flusher = ClickHouseBatchFlusher(
        host=ch_host,
        port=ch_port,
        batch_size=2000,
        flush_interval_secs=1.0,
    )
    await flusher.start()

    # 2. Iniciar Motor de Detección y conectar al estado global de la API
    engine = DetectionEngine(ch_host=ch_host, ch_port=ch_port)
    system_state.initialize(engine)

    # 3. Iniciar Colector UDP
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NetFlowUDPServerProtocol(flusher, engine=engine, stats_interval=5.0),
        local_addr=("0.0.0.0", udp_port),
    )
    logger.info(f"Colector UDP activo en 0.0.0.0:{udp_port}")

    # 4. Iniciar Servidor Web / API FastAPI con Uvicorn
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=http_port,
        log_level="warning",
        loop="asyncio",
    )
    server = uvicorn.Server(config)

    # Tarea de simulación opcional en background
    sim_task = None
    if auto_simulate:
        async def background_simulator():
            await asyncio.sleep(2.0)
            sender = NetFlowSender("127.0.0.1", udp_port)
            logger.info("[SIMULADOR] Inyectando tráfico normal y ataques periódicos...")
            while True:
                try:
                    # Ráfaga normal
                    sender.send_flows(TrafficScenarioGenerator.normal_traffic(count=30))
                    await asyncio.sleep(2.0)

                    # Ráfaga de ataque esporádico
                    sender.send_flows(TrafficScenarioGenerator.port_scan_attack(count=20))
                    sender.send_flows(TrafficScenarioGenerator.data_exfiltration_attack())
                    await asyncio.sleep(5.0)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug(f"Error en simulador continuo: {e}")
                    await asyncio.sleep(2.0)
            sender.close()

        sim_task = asyncio.create_task(background_simulator())

    try:
        await server.serve()
    finally:
        if sim_task:
            sim_task.cancel()
        transport.close()
        await flusher.stop()
        logger.info("Plataforma NovaFlow NDR detenida.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NovaFlow NDR Master Runner")
    parser.add_argument("--udp-port", type=int, default=2055, help="UDP NetFlow Port")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP API/Web Port")
    parser.add_argument("--simulate", action="store_true", help="Auto-generate background traffic and attacks")
    args = parser.parse_args()

    try:
        asyncio.run(run_platform(udp_port=args.udp_port, http_port=args.http_port, auto_simulate=args.simulate))
    except KeyboardInterrupt:
        print("\n[!] Proceso interrumpido por el usuario.")
        sys.exit(0)
