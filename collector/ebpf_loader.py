"""
NovaFlow NDR - eBPF / XDP Loader & Userspace Ring Buffer Pipeline
Cargador híbrido de sonda eBPF de ultra alta velocidad. Detecta soporte nativo
de kernel Linux (XDP/libbpf) y provee un emulador de Ring Buffer de alto rendimiento
en espacio de usuario para entornos Windows/macOS y pruebas de integración continuas.
"""

from __future__ import annotations

import collections
import logging
import os
import platform
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from collector.parser import NetFlowRecord

logger = logging.getLogger("NovaFlow.Collector.eBPF")


class EBPFProbeMode(str, Enum):
    NATIVE_XDP = "NATIVE_XDP"
    USERSPACE_RINGBUF_EMULATOR = "USERSPACE_RINGBUF_EMULATOR"


@dataclass(slots=True)
class FlowEvent:
    """Evento emitido desde el Ring Buffer de la sonda hacia el pipeline de análisis."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    tcp_flags: int
    packets: int
    bytes: int
    duration_ms: float
    timestamp: float

    def to_netflow_record(self) -> NetFlowRecord:
        """Convierte el evento eBPF en un NetFlowRecord formal compatible con el motor de detección."""
        dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        return NetFlowRecord(
            timestamp=dt,
            timestamp_ms=int(self.timestamp * 1000),
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            next_hop="0.0.0.0",
            input_snmp=1,
            output_snmp=2,
            packets=self.packets,
            bytes=self.bytes,
            first_switched=int(self.timestamp * 1000 - self.duration_ms),
            last_switched=int(self.timestamp * 1000),
            src_port=self.src_port,
            dst_port=self.dst_port,
            tcp_flags=self.tcp_flags,
            protocol=self.protocol,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )


class UserspaceRingBuffer:
    """Buffer circular de alta velocidad con política de descarte sin contención."""

    def __init__(self, capacity: int = 131072):
        self.capacity = capacity
        self.buffer: Deque[FlowEvent] = collections.deque(maxlen=capacity)
        self.total_enqueued = 0
        self.total_dropped = 0

    def push(self, event: FlowEvent):
        if len(self.buffer) >= self.capacity:
            self.total_dropped += 1
            # Deque con maxlen descarta el elemento más viejo a O(1)
        self.buffer.append(event)
        self.total_enqueued += 1

    def drain(self, max_count: int = 1000) -> List[FlowEvent]:
        """Extrae un lote de eventos para procesamiento vectorizado."""
        batch: List[FlowEvent] = []
        count = min(len(self.buffer), max_count)
        for _ in range(count):
            batch.append(self.buffer.popleft())
        return batch

    def __len__(self) -> int:
        return len(self.buffer)


class XDPProbeManager:
    """
    Gestor de la sonda de red eBPF/XDP.
    En Linux con privilegios root carga el programa C eBPF compilado.
    En otros entornos opera como emulador de Ring Buffer con desempaque zero-copy.
    """

    def __init__(
        self,
        interface: str = "eth0",
        ringbuf_capacity: int = 131072,
        force_emulator: bool = False,
    ):
        self.interface = interface
        self.ring_buffer = UserspaceRingBuffer(capacity=ringbuf_capacity)
        self.mode = EBPFProbeMode.USERSPACE_RINGBUF_EMULATOR
        self.is_running = False

        # Tabla de flujos activa en memoria para el emulador (clave: 5-tupla)
        self._flow_table: Dict[Tuple[str, str, int, int, int], Dict[str, Any]] = {}
        self.total_packets_processed = 0
        self.total_bytes_processed = 0

        c_source_path = Path(__file__).parent / "ebpf" / "novaflow_xdp.bpf.c"
        self.c_source_available = c_source_path.is_file()

        if not force_emulator and platform.system() == "Linux" and os.geteuid() == 0:
            self._try_load_native_xdp()
        else:
            self.mode = EBPFProbeMode.USERSPACE_RINGBUF_EMULATOR
            logger.info(
                "Sonda inicializada en modo Emulador de Ring Buffer eBPF/XDP (%s)",
                platform.system(),
            )

    def _try_load_native_xdp(self):
        """Intenta acoplar el programa eBPF nativo al controlador de red."""
        try:
            # Intento de carga con BCC o ctypes libbpf
            import bcc  # type: ignore
            c_file = Path(__file__).parent / "ebpf" / "novaflow_xdp.bpf.c"
            b = bcc.BPF(src_file=str(c_file))
            fn = b.load_func("novaflow_xdp_prog", bcc.BPF.XDP)
            b.attach_xdp(self.interface, fn, 0)
            self.mode = EBPFProbeMode.NATIVE_XDP
            self.is_running = True
            logger.info("Sonda eBPF/XDP acoplada exitosamente a la interfaz %s", self.interface)
        except Exception as e:
            logger.info("Fallback a emulador Ring Buffer: %s", str(e))
            self.mode = EBPFProbeMode.USERSPACE_RINGBUF_EMULATOR

    def process_raw_packet(self, data: bytes, timestamp: Optional[float] = None) -> bool:
        """
        Decodifica un paquete binario crudo (Ethernet + IPv4 + TCP/UDP).
        Actualiza la tabla de flujos interna y emite eventos al Ring Buffer.
        """
        now = timestamp if timestamp is not None else time.time()
        self.total_packets_processed += 1
        self.total_bytes_processed += len(data)

        if len(data) < 34:  # 14 Ethernet + 20 IP
            return False

        # Ethernet Header
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800:  # IPv4
            return False

        # IPv4 Header
        ip_header = data[14:34]
        ihl = (ip_header[0] & 0x0F) * 4
        protocol = ip_header[9]
        src_ip = ".".join(str(b) for b in ip_header[12:16])
        dst_ip = ".".join(str(b) for b in ip_header[16:20])

        offset_l4 = 14 + ihl
        if len(data) < offset_l4 + 4:
            return False

        src_port = 0
        dst_port = 0
        tcp_flags = 0

        if protocol == 6:  # TCP
            if len(data) < offset_l4 + 14:
                return False
            src_port, dst_port = struct.unpack("!HH", data[offset_l4:offset_l4 + 4])
            tcp_flags = data[offset_l4 + 13] & 0x3F
        elif protocol == 17:  # UDP
            if len(data) < offset_l4 + 4:
                return False
            src_port, dst_port = struct.unpack("!HH", data[offset_l4:offset_l4 + 4])
        else:
            return False

        # Clave 5-tupla
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        if key in self._flow_table:
            f = self._flow_table[key]
            f["packets"] += 1
            f["bytes"] += len(data)
            f["last_seen"] = now
            f["tcp_flags"] |= tcp_flags

            # Despachar evento si el flujo finaliza (FIN/RST) o cada 50 paquetes
            if (tcp_flags & 0x05) or (f["packets"] % 50 == 0):
                ev = FlowEvent(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    tcp_flags=f["tcp_flags"],
                    packets=f["packets"],
                    bytes=f["bytes"],
                    duration_ms=(now - f["first_seen"]) * 1000.0,
                    timestamp=now,
                )
                self.ring_buffer.push(ev)
                if tcp_flags & 0x05:
                    del self._flow_table[key]
        else:
            self._flow_table[key] = {
                "first_seen": now,
                "last_seen": now,
                "packets": 1,
                "bytes": len(data),
                "tcp_flags": tcp_flags,
            }

        return True

    def flush_inactive_flows(self, max_idle_seconds: float = 15.0) -> int:
        """Emite flujos inactivos hacia el Ring Buffer y limpia la tabla."""
        now = time.time()
        expired_keys = []
        for key, f in self._flow_table.items():
            if now - f["last_seen"] >= max_idle_seconds:
                expired_keys.append(key)

        for key in expired_keys:
            f = self._flow_table[key]
            ev = FlowEvent(
                src_ip=key[0],
                dst_ip=key[1],
                src_port=key[2],
                dst_port=key[3],
                protocol=key[4],
                tcp_flags=f["tcp_flags"],
                packets=f["packets"],
                bytes=f["bytes"],
                duration_ms=(f["last_seen"] - f["first_seen"]) * 1000.0,
                timestamp=f["last_seen"],
            )
            self.ring_buffer.push(ev)
            del self._flow_table[key]

        return len(expired_keys)

    def drain_events(self, max_count: int = 1000) -> List[FlowEvent]:
        """Extrae eventos del Ring Buffer para alimentar el motor de detección."""
        return self.ring_buffer.drain(max_count=max_count)

    def get_stats(self) -> Dict[str, Any]:
        """Retorna telemetría operativa de la sonda de captura."""
        return {
            "mode": self.mode.value,
            "interface": self.interface,
            "c_kernel_source_present": self.c_source_available,
            "total_packets": self.total_packets_processed,
            "total_bytes": self.total_bytes_processed,
            "active_flows_in_table": len(self._flow_table),
            "ring_buffer_depth": len(self.ring_buffer),
            "ring_buffer_enqueued": self.ring_buffer.total_enqueued,
            "ring_buffer_dropped": self.ring_buffer.total_dropped,
        }
