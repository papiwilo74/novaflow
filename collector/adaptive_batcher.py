"""
NovaFlow NDR - Dynamic Adaptive Batcher with Backpressure Monitoring
Ajusta dinámicamente el tamaño de lote y frecuencia de volcado según la saturación de memoria.
"""

import asyncio
import logging
import time
from typing import Any, Callable, List, Optional

from collector.parser import NetFlowRecord

logger = logging.getLogger("NovaFlow.AdaptiveBatcher")


class AdaptiveBatcher:
    """
    Controlador de contrapresión y micro-batching adaptativo.
    Evita la saturación del colector UDP bajo ráfagas masivas (DDoS o picos de tráfico)
    escalando el tamaño del lote y reduciendo el intervalo de volcado cuando la cola se satura.
    """

    def __init__(
        self,
        flush_callback: Callable[[List[NetFlowRecord]], Any],
        min_batch_size: int = 1000,
        max_batch_size: int = 20000,
        base_interval_secs: float = 1.0,
        high_watermark: int = 5000,
        critical_watermark: int = 25000,
        queue_max_size: int = 100000,
    ):
        self.flush_callback = flush_callback
        self.min_batch_size = min_batch_size
        self.max_batch_size = max_batch_size
        self.base_interval_secs = base_interval_secs
        self.high_watermark = high_watermark
        self.critical_watermark = critical_watermark

        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_max_size)
        self.is_running = False
        self._worker_task: Optional[asyncio.Task] = None

        # Estado adaptativo actual
        self.current_batch_size = min_batch_size
        self.current_interval_secs = base_interval_secs
        self.total_enqueued = 0
        self.total_flushed = 0
        self.total_batches = 0
        self.dropped_records = 0

    async def start(self):
        self.is_running = True
        self._worker_task = asyncio.create_task(self._adaptive_loop())
        logger.info(
            f"Adaptive Batcher activo [Min Batch: {self.min_batch_size}, "
            f"Max Batch: {self.max_batch_size}, High Watermark: {self.high_watermark}]"
        )

    async def stop(self):
        self.is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        # Flush final
        await self._flush_all_pending()

    async def enqueue_batch(self, records: List[NetFlowRecord]):
        """Encola registros monitoreando la contrapresión."""
        for r in records:
            try:
                self.queue.put_nowait(r)
                self.total_enqueued += 1
            except asyncio.QueueFull:
                self.dropped_records += 1
                try:
                    self.queue.get_nowait()
                    self.queue.put_nowait(r)
                except Exception:
                    pass

    def _adjust_parameters(self, qsize: int):
        """Ajusta dinámicamente batch_size e interval según la profundidad de la cola."""
        if qsize >= self.critical_watermark:
            # Modo emergencia: lotes máximos, volcado instantáneo
            self.current_batch_size = self.max_batch_size
            self.current_interval_secs = 0.1
        elif qsize >= self.high_watermark:
            # Contrapresión alta: escalar proporcionalmente
            scale = min(1.0, (qsize - self.high_watermark) / (self.critical_watermark - self.high_watermark))
            self.current_batch_size = int(self.min_batch_size + scale * (self.max_batch_size - self.min_batch_size))
            self.current_interval_secs = max(0.2, self.base_interval_secs * (1.0 - (scale * 0.7)))
        else:
            # Modo normal de baja latencia
            self.current_batch_size = self.min_batch_size
            self.current_interval_secs = self.base_interval_secs

    async def _adaptive_loop(self):
        batch: List[NetFlowRecord] = []
        last_flush_time = time.time()

        while self.is_running:
            try:
                qsize = self.queue.qsize()
                self._adjust_parameters(qsize)

                timeout = max(0.01, self.current_interval_secs - (time.time() - last_flush_time))
                try:
                    record = await asyncio.wait_for(self.queue.get(), timeout=timeout)
                    batch.append(record)
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                should_flush = (
                    len(batch) >= self.current_batch_size
                    or (batch and (now - last_flush_time) >= self.current_interval_secs)
                )

                if should_flush:
                    await self._dispatch_flush(batch)
                    batch = []
                    last_flush_time = now

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error en Adaptive Batcher loop: {e}")
                await asyncio.sleep(0.1)

    async def _dispatch_flush(self, batch: List[NetFlowRecord]):
        if not batch:
            return
        self.total_flushed += len(batch)
        self.total_batches += 1
        try:
            if asyncio.iscoroutinefunction(self.flush_callback):
                await self.flush_callback(batch)
            else:
                self.flush_callback(batch)
        except Exception as e:
            logger.error(f"Error en flush_callback del batcher: {e}")

    async def _flush_all_pending(self):
        batch = []
        while not self.queue.empty():
            try:
                batch.append(self.queue.get_nowait())
            except Exception:
                break
        if batch:
            await self._dispatch_flush(batch)
