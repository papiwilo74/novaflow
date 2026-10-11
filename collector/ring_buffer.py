"""
NovaFlow NDR - Zero-Copy Shared-Memory Circular Ring Buffer
Búfer circular lock-free / low-latency en memoria compartida POSIX (multiprocessing.shared_memory)
para desacoplar la ingesta de paquetes eBPF/UDP de los motores analíticos de detección.
"""

from __future__ import annotations

import logging
import math
import struct
import time
from multiprocessing import Lock, shared_memory
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("NovaFlow.RingBuffer")

# ==============================================================================
# HEADER BINARIO (64 bytes alineado a línea de caché)
# Offset 0..7   : write_head   (uint64, 'Q')
# Offset 8..15  : read_tail    (uint64, 'Q')
# Offset 16..19 : capacity     (uint32, 'I') - Número de slots
# Offset 20..23 : slot_size    (uint32, 'I') - Bytes totales por slot
# Offset 24..31 : dropped      (uint64, 'Q') - Paquetes descartados por búfer lleno
# Offset 32..39 : magic        (uint64, 'Q') - Constante 0x4E4F5641464C4F57 ('NOVAFLOW')
# Offset 40..63 : reserved     (24 bytes de padding)
# ==============================================================================
HEADER_FORMAT = "!QQIIQQ24s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 64 bytes
MAGIC_CONSTANT = 0x4E4F5641464C4F57

# ==============================================================================
# SLOT BINARIO (Prefijo de 12 bytes + payload)
# Offset 0..1   : data_len     (uint16, 'H')
# Offset 2..3   : flags        (uint16, 'H')
# Offset 4..11  : timestamp_ns (uint64, 'Q')
# Offset 12..N  : payload      (bytes)
# ==============================================================================
SLOT_HEADER_FORMAT = "!HHQ"
SLOT_HEADER_SIZE = struct.calcsize(SLOT_HEADER_FORMAT)  # 12 bytes


class SharedMemoryRingBuffer:
    """
    Búfer circular de alto rendimiento basado en memoria compartida nativa.
    Permite comunicación IPC de ultra-baja latencia entre el proceso productor de red
    y los procesos trabajadores (workers) de inferencia analítica.
    """

    def __init__(
        self,
        name: str,
        capacity: int = 4096,
        slot_size: int = 2048,
        create: bool = False,
    ):
        """
        Inicializa o se enlaza a un segmento de memoria compartida existente.

        Args:
            name: Nombre único del segmento POSIX (/dev/shm/<name>).
            capacity: Número total de slots en el búfer.
            slot_size: Tamaño en bytes de cada slot individual (incluyendo prefijo de 12 bytes).
            create: Si True, crea y formatea el segmento. Si False, se adhiere a uno existente.
        """
        self.name = name
        self.capacity = capacity
        self.slot_size = slot_size
        self.max_payload_size = slot_size - SLOT_HEADER_SIZE
        self.total_size = HEADER_SIZE + (capacity * slot_size)
        self.is_owner = create
        self._lock = Lock()

        if create:
            try:
                # Si existía previamente un segmento huérfano con el mismo nombre, limpiarlo
                old_shm = shared_memory.SharedMemory(name=self.name)
                old_shm.close()
                old_shm.unlink()
            except FileNotFoundError:
                pass

            self.shm = shared_memory.SharedMemory(
                create=True, size=self.total_size, name=self.name
            )
            # Inicializar cabecera en ceros
            header_bytes = struct.pack(
                HEADER_FORMAT,
                0,  # write_head
                0,  # read_tail
                self.capacity,
                self.slot_size,
                0,  # dropped
                MAGIC_CONSTANT,
                b"\x00" * 24,  # reserved padding
            )
            self.shm.buf[0:HEADER_SIZE] = header_bytes
        else:
            self.shm = shared_memory.SharedMemory(name=self.name)
            # Leer metadatos de la cabecera formateada
            hdr = struct.unpack_from(HEADER_FORMAT, self.shm.buf, 0)
            if hdr[5] != MAGIC_CONSTANT:
                raise ValueError(
                    f"Segmento de memoria compartida inválido o corrupto (magic={hdr[5]:#x})"
                )
            self.capacity = hdr[2]
            self.slot_size = hdr[3]
            self.max_payload_size = self.slot_size - SLOT_HEADER_SIZE
            self.total_size = HEADER_SIZE + (self.capacity * self.slot_size)

        self._buf = self.shm.buf

    def write(self, data: bytes, flags: int = 0) -> bool:
        """
        Inserta un datagrama o rebanada L7 en el anillo.
        Operación no bloqueante: si el anillo está lleno, incrementa 'dropped' y retorna False.
        """
        data_len = min(len(data), self.max_payload_size)
        ts_ns = time.time_ns()

        with self._lock:
            # Leer punteros actuales
            write_head, read_tail, _, _, dropped, _, _ = struct.unpack_from(
                HEADER_FORMAT, self._buf, 0
            )

            # Verificar contrapresión / condición de saturación
            pending = write_head - read_tail
            if pending >= self.capacity:
                # Búfer saturado: registrar descarte sin bloquear el hilo de captura
                struct.pack_into("!Q", self._buf, 24, dropped + 1)
                return False

            slot_idx = write_head % self.capacity
            slot_offset = HEADER_SIZE + (slot_idx * self.slot_size)

            # Escribir metadatos del slot (12 bytes)
            struct.pack_into(
                SLOT_HEADER_FORMAT,
                self._buf,
                slot_offset,
                data_len,
                flags,
                ts_ns,
            )

            # Copia directa de memoria hacia el slot
            data_offset = slot_offset + SLOT_HEADER_SIZE
            self._buf[data_offset : data_offset + data_len] = data[:data_len]

            # Avanzar puntero de escritura atómicamente
            struct.pack_into("!Q", self._buf, 0, write_head + 1)
            return True

    def read(self) -> Optional[Tuple[bytes, int, int]]:
        """
        Extrae el siguiente paquete disponible en el anillo.
        Retorna (payload, flags, timestamp_ns) o None si el anillo está vacío.
        """
        with self._lock:
            write_head, read_tail = struct.unpack_from("!QQ", self._buf, 0)
            if read_tail >= write_head:
                return None

            slot_idx = read_tail % self.capacity
            slot_offset = HEADER_SIZE + (slot_idx * self.slot_size)

            data_len, flags, ts_ns = struct.unpack_from(
                SLOT_HEADER_FORMAT, self._buf, slot_offset
            )
            data_offset = slot_offset + SLOT_HEADER_SIZE
            payload = bytes(self._buf[data_offset : data_offset + data_len])

            # Avanzar puntero de lectura
            struct.pack_into("!Q", self._buf, 8, read_tail + 1)
            return payload, flags, ts_ns

    def read_batch(self, max_items: int = 64) -> List[Tuple[bytes, int, int]]:
        """
        Extrae un lote de paquetes contiguos para maximizar throughput analítico.
        """
        batch: List[Tuple[bytes, int, int]] = []
        with self._lock:
            write_head, read_tail = struct.unpack_from("!QQ", self._buf, 0)
            available = min(max_items, max(0, write_head - read_tail))
            if available <= 0:
                return batch

            for _ in range(available):
                slot_idx = read_tail % self.capacity
                slot_offset = HEADER_SIZE + (slot_idx * self.slot_size)

                data_len, flags, ts_ns = struct.unpack_from(
                    SLOT_HEADER_FORMAT, self._buf, slot_offset
                )
                data_offset = slot_offset + SLOT_HEADER_SIZE
                payload = bytes(self._buf[data_offset : data_offset + data_len])
                batch.append((payload, flags, ts_ns))
                read_tail += 1

            # Actualizar read_tail consolidado
            struct.pack_into("!Q", self._buf, 8, read_tail)
            return batch

    def clear(self):
        """Reinicia los punteros de lectura y escritura."""
        with self._lock:
            struct.pack_into("!QQ", self._buf, 0, 0, 0)
            struct.pack_into("!Q", self._buf, 24, 0)

    @property
    def metrics(self) -> Dict[str, Any]:
        """Retorna telemetría instantánea de utilización y contrapresión del ring buffer."""
        write_head, read_tail, capacity, slot_size, dropped, _, _ = struct.unpack_from(
            HEADER_FORMAT, self._buf, 0
        )
        pending = max(0, write_head - read_tail)
        utilization_pct = round((pending / max(1, capacity)) * 100.0, 2)
        return {
            "name": self.name,
            "write_head": write_head,
            "read_tail": read_tail,
            "pending_packets": pending,
            "dropped_packets": dropped,
            "capacity": capacity,
            "slot_size_bytes": slot_size,
            "utilization_pct": utilization_pct,
            "total_size_mb": round(self.total_size / (1024 * 1024), 2),
        }

    def close(self):
        """Cierra el descriptor local de memoria compartida."""
        try:
            self.shm.close()
        except Exception:
            pass

    def unlink(self):
        """Destruye el segmento de memoria compartida del sistema operativo."""
        try:
            self.shm.close()
        except Exception:
            pass
        try:
            self.shm.unlink()
        except Exception:
            pass

    def __enter__(self) -> SharedMemoryRingBuffer:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.is_owner:
            self.unlink()
        else:
            self.close()
