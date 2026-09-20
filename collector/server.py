"""
NovaFlow NDR - Asynchronous UDP NetFlow Collector
Servidor UDP de alta concurrencia en puerto 2055 con procesamiento no bloqueante.
"""

import asyncio
import logging
import os
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from collector.parser import NetFlowParser
    from collector.storage import ClickHouseBatchFlusher
    from detector.engine import DetectionEngine
    from api.state import system_state
except ImportError:
    from parser import NetFlowParser
    from storage import ClickHouseBatchFlusher
    from detector.engine import DetectionEngine
    try:
        from api.state import system_state
    except ImportError:
        system_state = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("NovaFlow.Collector")


class NetFlowUDPServerProtocol(asyncio.DatagramProtocol):
    """Protocolo UDP de baja latencia para datagramas NetFlow."""

    def __init__(
        self,
        flusher: ClickHouseBatchFlusher,
        engine: Optional[DetectionEngine] = None,
        stats_interval: float = 5.0,
    ):
        self.flusher = flusher
        self.engine = engine
        self.stats_interval = stats_interval
        self.transport: Optional[asyncio.DatagramTransport] = None

        # Contadores de rendimiento
        self.packets_received = 0
        self.flows_decoded = 0
        self.bytes_received = 0
        self.last_stats_time = time.time()
        self.period_packets = 0
        self.period_flows = 0

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        logger.info("Socket UDP abierto y listo para recibir flujos.")

    def datagram_received(self, data: bytes, addr):
        data_len = len(data)
        self.packets_received += 1
        self.bytes_received += data_len
        self.period_packets += 1

        # Decodificar paquete binario
        header, records = NetFlowParser.parse_packet(data)
        if records:
            rec_count = len(records)
            self.flows_decoded += rec_count
            self.period_flows += rec_count

            # Encolar en memoria para inserción asíncrona por lotes
            asyncio.create_task(self.flusher.enqueue(records))

            # Analizar en tiempo real con el motor de detección de amenazas (Fase 2)
            if self.engine:
                self.engine.analyze_batch(records)

            # Registrar en el estado global para API y WebSockets (Fase 3)
            if system_state:
                system_state.record_flows(records)

        # Registro periódico de métricas
        now = time.time()
        elapsed = now - self.last_stats_time
        if elapsed >= self.stats_interval:
            pps = self.period_packets / elapsed
            fps = self.period_flows / elapsed
            queue_len = self.flusher._queue.qsize()
            conn_status = "ONLINE" if self.flusher.is_connected else "OFFLINE (buffering)"
            alerts_count = self.engine.stats["total_alerts"] if self.engine else 0
            logger.info(
                f"[TELEMETRÍA] {pps:.1f} UDP pkt/s | {fps:.1f} flows/s | "
                f"Total Flujos: {self.flows_decoded:,} | Cola: {queue_len} | Alertas: {alerts_count} | ClickHouse: {conn_status}"
            )
            self.last_stats_time = now
            self.period_packets = 0
            self.period_flows = 0

    def error_received(self, exc):
        logger.error(f"Error en socket UDP: {exc}")


async def run_collector(
    host: str = "0.0.0.0",
    port: int = 2055,
    ch_host: str = "localhost",
    ch_port: int = 8123,
    batch_size: int = 5000,
    flush_interval: float = 1.0,
    enable_detection: bool = True,
):
    """Inicia el colector UDP, el motor de almacenamiento y el motor de detección."""
    flusher = ClickHouseBatchFlusher(
        host=ch_host,
        port=ch_port,
        batch_size=batch_size,
        flush_interval_secs=flush_interval,
    )
    await flusher.start()

    engine = DetectionEngine(ch_host=ch_host, ch_port=ch_port) if enable_detection else None

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: NetFlowUDPServerProtocol(flusher, engine=engine),
        local_addr=(host, port),
    )

    logger.info(f"=== NovaFlow NDR Ingestion Engine iniciado en UDP {host}:{port} ===")
    logger.info("Esperando datagramas NetFlow v5/v9 de routers o generador sintético...")

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        logger.info("Deteniendo colector...")
    finally:
        transport.close()
        await flusher.stop()
        logger.info("Colector detenido limpiamente.")


if __name__ == "__main__":
    import sys
    try:
        asyncio.run(run_collector())
    except KeyboardInterrupt:
        logger.info("Interrumpido por el usuario.")
        sys.exit(0)
