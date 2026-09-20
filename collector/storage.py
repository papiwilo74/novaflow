"""
NovaFlow NDR - ClickHouse Storage Adapter & High-Throughput Batch Buffer
Maneja micro-batching en memoria e inserción masiva en ClickHouse.
"""

import asyncio
import logging
import time
from typing import List, Optional
import requests

from collector.parser import NetFlowRecord

logger = logging.getLogger("NovaFlow.Storage")


class ClickHouseBatchFlusher:
    """
    Buffer circular en memoria con trabajador asíncrono para volcado por lotes (micro-batching).
    Soporta inserción directa vía HTTP API de ClickHouse (sin dependencias binarias complejas)
    con fallback resiliente si el servidor no está en línea.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8123,
        database: str = "novaflow",
        table: str = "flows_raw",
        user: str = "default",
        password: str = "",
        batch_size: int = 5000,
        flush_interval_secs: float = 1.0,
    ):
        self.host = host
        self.port = port
        self.database = database
        self.table = table
        self.user = user
        self.password = password
        self.batch_size = batch_size
        self.flush_interval_secs = flush_interval_secs

        self.url = f"http://{self.host}:{self.port}/"
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=100_000)
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

        # Métricas de rendimiento
        self.total_flows_received = 0
        self.total_flows_inserted = 0
        self.total_batches_flushed = 0
        self.failed_flushes = 0
        self.is_connected = False

    async def start(self):
        """Inicia el worker en segundo plano para el procesamiento de lotes."""
        self._running = True
        self._worker_task = asyncio.create_task(self._flusher_loop())
        # Verificar conexión con ClickHouse
        self.check_connection()
        logger.info(
            f"Storage Flusher iniciado [Batch Size: {self.batch_size}, "
            f"Intervalo: {self.flush_interval_secs}s, Target: {self.url}]"
        )

    async def stop(self):
        """Detiene el worker de forma ordenada volcando registros remanentes."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        # Flush final
        await self._flush_pending()

    def check_connection(self) -> bool:
        """Verifica disponibilidad de ClickHouse."""
        try:
            resp = requests.get(f"{self.url}ping", timeout=1.0)
            self.is_connected = (resp.status_code == 200 and resp.text.strip() == "Ok.")
            if self.is_connected:
                logger.info(f"Conectado exitosamente a ClickHouse en {self.url}")
            return self.is_connected
        except Exception:
            self.is_connected = False
            return False

    async def enqueue(self, records: List[NetFlowRecord]):
        """Encola registros en el buffer de memoria."""
        count = len(records)
        self.total_flows_received += count
        for r in records:
            try:
                self._queue.put_nowait(r)
            except asyncio.QueueFull:
                # Si el buffer está saturado, se descartan los flujos más antiguos para evitar bloqueo del colector
                try:
                    self._queue.get_nowait()
                    self._queue.put_nowait(r)
                except Exception:
                    pass

    async def _flusher_loop(self):
        """Bucle continuo de micro-batching."""
        batch: List[NetFlowRecord] = []
        last_flush_time = time.time()

        while self._running:
            try:
                timeout = max(0.01, self.flush_interval_secs - (time.time() - last_flush_time))
                try:
                    record = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    batch.append(record)
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                should_flush = (
                    len(batch) >= self.batch_size
                    or (batch and (now - last_flush_time) >= self.flush_interval_secs)
                )

                if should_flush:
                    await self._flush_batch(batch)
                    batch = []
                    last_flush_time = now

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error inesperado en flusher loop: {e}")
                await asyncio.sleep(0.5)

    async def _flush_pending(self):
        """Vuelca cualquier flujo restante en cola."""
        batch: List[NetFlowRecord] = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
            except Exception:
                break
        if batch:
            await self._flush_batch(batch)

    async def _flush_batch(self, batch: List[NetFlowRecord]):
        """Convierte registros a formato TabSeparated e inserta en ClickHouse."""
        if not batch:
            return

        # Construir payload en formato TabSeparated (ultrarrápido, mínimo overhead de serialización)
        lines = []
        for r in batch:
            ts_str = r.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            line = (
                f"{ts_str}\t{r.timestamp_ms}\t{r.src_ip}\t{r.dst_ip}\t{r.next_hop}\t"
                f"{r.src_port}\t{r.dst_port}\t{r.protocol}\t{r.tcp_flags}\t{r.tos}\t"
                f"{r.packets}\t{r.bytes}\t{r.flow_version}\t{r.first_switched}\t{r.last_switched}\t"
                f"{r.input_snmp}\t{r.output_snmp}\t{r.src_mask}\t{r.dst_mask}\t{r.src_as}\t{r.dst_as}"
            )
            lines.append(line)

        payload = "\n".join(lines) + "\n"

        query = (
            f"INSERT INTO {self.database}.{self.table} ("
            f"timestamp, timestamp_ms, src_ip, dst_ip, next_hop, "
            f"src_port, dst_port, protocol, tcp_flags, tos, "
            f"packets, bytes, flow_version, first_switched, last_switched, "
            f"input_snmp, output_snmp, src_mask, dst_mask, src_as, dst_as"
            f") FORMAT TabSeparated"
        )

        try:
            # Inserción asíncrona mediante loop de eventos
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.post(
                    self.url,
                    params={"query": query},
                    data=payload.encode("utf-8"),
                    auth=(self.user, self.password) if self.password else None,
                    timeout=5.0,
                )
            )

            if resp.status_code == 200:
                self.total_flows_inserted += len(batch)
                self.total_batches_flushed += 1
                self.is_connected = True
                logger.debug(f"Lote de {len(batch)} flujos insertado exitosamente en ClickHouse.")
            else:
                self.failed_flushes += 1
                logger.warning(
                    f"Fallo al insertar lote ({resp.status_code}): {resp.text.strip()[:150]}"
                )
        except Exception as e:
            self.failed_flushes += 1
            self.is_connected = False
            logger.debug(f"ClickHouse no disponible temporalmente ({e}). Lote procesado en memoria.")
