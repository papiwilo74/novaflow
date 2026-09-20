"""
NovaFlow NDR - Parallel UDP Ingestion Worker Pool
Distribuye el procesamiento de datagramas binarios entre múltiples workers asíncronos.
"""

import asyncio
import logging
from typing import Any, Callable, List, Optional, Tuple

from collector.parser import NetFlowParser, NetFlowRecord

logger = logging.getLogger("NovaFlow.WorkerPool")


class UDPWorkerPool:
    """Pool de tareas concurrentes para desempaquetar datagramas NetFlow sin saturar el socket UDP."""

    def __init__(
        self,
        output_handler: Callable[[List[NetFlowRecord]], Any],
        num_workers: int = 4,
        max_incoming_queue: int = 50000,
    ):
        self.output_handler = output_handler
        self.num_workers = num_workers
        self.incoming_queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=max_incoming_queue)
        self._workers: List[asyncio.Task] = []
        self.is_running = False

        self.total_packets_processed = 0
        self.total_flows_decoded = 0

    async def start(self):
        self.is_running = True
        for i in range(self.num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self._workers.append(task)
        logger.info(f"Worker Pool iniciado con {self.num_workers} workers paralelos.")

    async def stop(self):
        self.is_running = False
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    def submit_packet(self, data: bytes) -> bool:
        """Encola el datagrama UDP en el buffer de trabajo. No bloqueante."""
        try:
            self.incoming_queue.put_nowait(data)
            return True
        except asyncio.QueueFull:
            return False

    async def _worker_loop(self, worker_id: int):
        while self.is_running:
            try:
                data = await self.incoming_queue.get()
                self.total_packets_processed += 1

                header, records = NetFlowParser.parse_packet(data)
                if records:
                    self.total_flows_decoded += len(records)
                    if asyncio.iscoroutinefunction(self.output_handler):
                        await self.output_handler(records)
                    else:
                        self.output_handler(records)

                self.incoming_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Worker {worker_id} error: {e}")
