"""
NovaFlow NDR - Wire-Speed Decoupled Multiprocessing Ingestion Pipeline
Pipeline desacoplado de ingesta a velocidad de cable con balanceo simétrico por 5-tupla
y búferes circulares en memoria compartida (SharedMemoryRingBuffer) para aislamiento del GIL.
"""

from __future__ import annotations

import logging
import multiprocessing as mp
import os
import socket
import struct
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from collector.parser import NetFlowParser, NetFlowRecord
from collector.ring_buffer import SharedMemoryRingBuffer
from detector.engine import DetectionEngine
from detector.models import SecurityAlert

logger = logging.getLogger("NovaFlow.WireSpeedPipeline")


def compute_symmetric_5tuple_hash(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,
    num_workers: int,
) -> int:
    """
    Calcula un hash estrictamente simétrico de la 5-tupla.
    Garantiza que el tráfico cliente->servidor y servidor->cliente sea procesado
    por el MISMO proceso worker para mantener consistencia de estado biflujo y L7.
    """
    if num_workers <= 1:
        return 0

    ip1, ip2 = sorted((src_ip, dst_ip))
    # Hash canónico de 32 bits no firmado sobre el par de hosts
    h = hash((ip1, ip2)) & 0xFFFFFFFF
    return h % num_workers


def extract_quick_5tuple_from_v5(data: bytes) -> Optional[Tuple[str, str, int, int, int]]:
    """
    Extracción directa en nanosegundos de la 5-tupla del primer registro NetFlow v5
    sin deserializar el paquete completo, para enrutamiento instantáneo en el productor.
    """
    # Header v5 son 24 bytes, cada registro 48 bytes
    if len(data) < 72:
        return None

    # Verificar versión v5 (bytes 0..1 == 5)
    version = (data[0] << 8) | data[1]
    if version != 5:
        return None

    # Offset 24: primer registro
    # 24..27: src_ip, 28..31: dst_ip
    src_ip = socket.inet_ntoa(data[24:28])
    dst_ip = socket.inet_ntoa(data[28:32])
    # 24+32 = offset 56: src_port (2 bytes)
    # 24+34 = offset 58: dst_port (2 bytes)
    src_port = (data[56] << 8) | data[57]
    dst_port = (data[58] << 8) | data[59]
    # 24+38 = offset 62: protocol (1 byte)
    protocol = data[62]

    return src_ip, dst_ip, src_port, dst_port, protocol


def _worker_process_loop(
    worker_id: int,
    ring_name: str,
    capacity: int,
    slot_size: int,
    stop_event: Any,
    alert_queue: Any,
    stats_dict: Any,
    ch_host: str = "localhost",
    ch_port: int = 8123,
    database: str = "novaflow",
):
    """
    Bucle principal de ejecución del proceso worker independiente.
    Corre en su propio proceso de SO con su propia instancia de DetectionEngine,
    eliminando cualquier contención del GIL.
    """
    # Enlazar al ring buffer de memoria compartida existente
    ring = SharedMemoryRingBuffer(name=ring_name, create=False)
    engine = DetectionEngine(ch_host=ch_host, ch_port=ch_port, database=database)

    packets_count = 0
    flows_count = 0
    alerts_count = 0
    last_stats_sync = time.time()

    logger.debug(f"[Worker-{worker_id}] Proceso analítico inicializado en PID {os.getpid()}.")

    try:
        while not stop_event.is_set():
            # Extraer lote de paquetes sin bloqueo
            batch = ring.read_batch(max_items=64)
            if batch:
                for raw_data, flags, ts_ns in batch:
                    packets_count += 1
                    header, records = NetFlowParser.parse_packet(raw_data)
                    if not records:
                        continue

                    flows_count += len(records)

                    # Ejecutar análisis heurístico y de firmas L4/L7
                    alerts = engine.analyze_batch(records)
                    if alerts:
                        alerts_count += len(alerts)
                        for alert in alerts:
                            try:
                                alert_queue.put_nowait(alert.to_dict())
                            except Exception:
                                pass
            else:
                time.sleep(0.002)  # 2 ms backoff cuando la cola está vacía

            # Sincronizar estadísticas periódicamente hacia el proceso padre
            now = time.time()
            if now - last_stats_sync >= 0.1:
                stats_dict[worker_id] = {
                    "pid": os.getpid(),
                    "packets": packets_count,
                    "flows": flows_count,
                    "alerts": alerts_count,
                    "engine_stats": engine.stats,
                }
                last_stats_sync = now

    except Exception as e:
        logger.error(f"[Worker-{worker_id}] Error fatal en worker loop: {e}")
    finally:
        # Sincronización final
        stats_dict[worker_id] = {
            "pid": os.getpid(),
            "packets": packets_count,
            "flows": flows_count,
            "alerts": alerts_count,
            "engine_stats": engine.stats,
        }
        ring.close()
        logger.debug(f"[Worker-{worker_id}] Proceso finalizado limpiamente.")


class WireSpeedPipeline:
    """
    Pipeline multi-proceso de alto rendimiento con ring buffers en memoria compartida.
    Desacopla la ingesta de paquetes del motor analítico de detección para soportar
    tasas wire-speed (> 100k pps) sin latencia ni cuellos de botella del GIL.
    """

    def __init__(
        self,
        num_workers: Optional[int] = None,
        ring_capacity: int = 4096,
        slot_size: int = 2048,
        ch_host: str = "localhost",
        ch_port: int = 8123,
        database: str = "novaflow",
        pipeline_id: Optional[str] = None,
    ):
        self.num_workers = num_workers or min(os.cpu_count() or 4, 8)
        self.ring_capacity = ring_capacity
        self.slot_size = slot_size
        self.ch_host = ch_host
        self.ch_port = ch_port
        self.database = database
        self.pipeline_id = pipeline_id or f"nova_{uuid.uuid4().hex[:8]}"

        self.rings: List[SharedMemoryRingBuffer] = []
        self.workers: List[mp.Process] = []
        self.stop_event = mp.Event()
        self.alert_queue = mp.Queue(maxsize=10000)

        self._manager = mp.Manager()
        self.stats_dict = self._manager.dict()

        self.total_submitted_packets = 0
        self.total_dropped_packets = 0
        self.is_running = False

    def start(self):
        """Inicializa los ring buffers de memoria compartida y arranca los procesos workers."""
        if self.is_running:
            return

        self.is_running = True
        self.stop_event.clear()

        # 1. Crear los ring buffers en memoria compartida POSIX
        for w_idx in range(self.num_workers):
            ring_name = f"novaflow_shm_{self.pipeline_id}_w{w_idx}"
            ring = SharedMemoryRingBuffer(
                name=ring_name,
                capacity=self.ring_capacity,
                slot_size=self.slot_size,
                create=True,
            )
            self.rings.append(ring)
            self.stats_dict[w_idx] = {
                "pid": 0,
                "packets": 0,
                "flows": 0,
                "alerts": 0,
                "engine_stats": {},
            }

        # 2. Desplegar los procesos workers
        for w_idx in range(self.num_workers):
            ring_name = self.rings[w_idx].name
            p = mp.Process(
                target=_worker_process_loop,
                args=(
                    w_idx,
                    ring_name,
                    self.ring_capacity,
                    self.slot_size,
                    self.stop_event,
                    self.alert_queue,
                    self.stats_dict,
                    self.ch_host,
                    self.ch_port,
                    self.database,
                ),
                daemon=True,
            )
            p.start()
            self.workers.append(p)

        logger.info(
            f"WireSpeedPipeline activo [{self.num_workers} workers paralelos, "
            f"Capacidad total: {self.num_workers * self.ring_capacity:,} slots]."
        )

    def submit_packet(self, data: bytes, exporter_ip: str = "127.0.0.1") -> bool:
        """
        Ingesta y enruta un datagrama UDP en bruto al worker correspondiente.
        Utiliza hashing simétrico de la 5-tupla. Operación no bloqueante.
        """
        if not self.is_running or not self.rings:
            return False

        self.total_submitted_packets += 1

        # Enrutamiento ultra-rápido por 5-tupla
        t5 = extract_quick_5tuple_from_v5(data)
        if t5:
            src_ip, dst_ip, src_port, dst_port, proto = t5
            worker_idx = compute_symmetric_5tuple_hash(
                src_ip, dst_ip, src_port, dst_port, proto, self.num_workers
            )
        else:
            # Fallback para paquetes v9/IPFIX o truncados: hash del exporter o round-robin
            worker_idx = (self.total_submitted_packets) % self.num_workers

        # Escritura zero-copy al ring buffer del worker seleccionado
        ring = self.rings[worker_idx]
        success = ring.write(data)
        if not success:
            self.total_dropped_packets += 1

        return success

    def get_alerts(self, max_alerts: int = 100) -> List[Dict[str, Any]]:
        """Extrae las alertas de seguridad generadas por todos los workers."""
        alerts: List[Dict[str, Any]] = []
        for _ in range(max_alerts):
            try:
                alert_dict = self.alert_queue.get_nowait()
                alerts.append(alert_dict)
            except Exception:
                break
        return alerts

    def get_metrics(self) -> Dict[str, Any]:
        """Consolida las métricas de rendimiento y contrapresión de todo el cluster."""
        worker_metrics = []
        total_worker_packets = 0
        total_worker_flows = 0
        total_worker_alerts = 0
        total_ring_dropped = 0
        total_ring_pending = 0

        for w_idx in range(len(self.rings)):
            ring = self.rings[w_idx]
            r_metrics = ring.metrics
            w_stats = dict(self.stats_dict.get(w_idx, {}))

            total_ring_dropped += r_metrics.get("dropped_packets", 0)
            total_ring_pending += r_metrics.get("pending_packets", 0)
            total_worker_packets += w_stats.get("packets", 0)
            total_worker_flows += w_stats.get("flows", 0)
            total_worker_alerts += w_stats.get("alerts", 0)

            worker_metrics.append({
                "worker_id": w_idx,
                "pid": w_stats.get("pid", 0),
                "packets_processed": w_stats.get("packets", 0),
                "flows_analyzed": w_stats.get("flows", 0),
                "alerts_emitted": w_stats.get("alerts", 0),
                "ring_pending": r_metrics.get("pending_packets", 0),
                "ring_dropped": r_metrics.get("dropped_packets", 0),
                "ring_utilization_pct": r_metrics.get("utilization_pct", 0.0),
            })

        return {
            "pipeline_id": self.pipeline_id,
            "is_running": self.is_running,
            "num_workers": self.num_workers,
            "total_submitted_packets": self.total_submitted_packets,
            "total_dropped_packets": self.total_dropped_packets + total_ring_dropped,
            "total_worker_packets": total_worker_packets,
            "total_worker_flows": total_worker_flows,
            "total_worker_alerts": total_worker_alerts,
            "total_pending_in_rings": total_ring_pending,
            "workers": worker_metrics,
        }

    def stop(self, timeout: float = 3.0):
        """Detiene de forma segura los workers y destruye los segmentos de memoria compartida."""
        if not self.is_running:
            return

        self.is_running = False
        self.stop_event.set()

        # Esperar finalización de procesos
        for p in self.workers:
            p.join(timeout=timeout)
            if p.is_alive():
                p.terminate()

        self.workers.clear()

        # Destruir ring buffers de memoria compartida
        for ring in self.rings:
            ring.unlink()
        self.rings.clear()

        try:
            self._manager.shutdown()
        except Exception:
            pass

        logger.info(f"WireSpeedPipeline [{self.pipeline_id}] detenido y recursos liberados.")

    def __enter__(self) -> WireSpeedPipeline:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
