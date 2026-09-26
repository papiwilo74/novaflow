"""
NovaFlow NDR - Columnar Flow Storage Engine (.nfc)
Motor de persistencia y analítica columnar masiva en disco y memoria para telemetría
de red L3/L4/L7. Implementa codificación por diccionario, índices de zona (Min/Max)
y escaneo vectorizado para responder consultas analíticas en tiempo subsegundo.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple

from collector.parser import NetFlowRecord


MAGIC_HEADER = b"NFC1"  # NovaFlow Columnar Format Version 1


@dataclass
class BlockZoneMap:
    """Metadatos de poda de bloque (Zone Map / Min-Max Indexing)."""
    min_timestamp: float = float("inf")
    max_timestamp: float = float("-inf")
    min_dst_port: int = 65535
    max_dst_port: int = 0
    protocols: Set[int] = field(default_factory=set)
    src_ips: Set[str] = field(default_factory=set)
    dst_ips: Set[str] = field(default_factory=set)
    total_bytes: int = 0
    total_packets: int = 0
    row_count: int = 0

    def update(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: int,
        pkts: int,
        byte_count: int,
    ):
        if ts < self.min_timestamp:
            self.min_timestamp = ts
        if ts > self.max_timestamp:
            self.max_timestamp = ts
        if dst_port < self.min_dst_port:
            self.min_dst_port = dst_port
        if dst_port > self.max_dst_port:
            self.max_dst_port = dst_port
        self.protocols.add(proto)
        self.src_ips.add(src_ip)
        self.dst_ips.add(dst_ip)
        self.total_bytes += byte_count
        self.total_packets += pkts
        self.row_count += 1

    def can_skip(self, filters: Dict[str, Any]) -> bool:
        """Determina si el bloque entero puede descartarse sin leer sus columnas."""
        if self.row_count == 0:
            return True

        # Poda por rango temporal
        if "start_time" in filters and filters["start_time"] is not None:
            if self.max_timestamp < filters["start_time"]:
                return True
        if "end_time" in filters and filters["end_time"] is not None:
            if self.min_timestamp > filters["end_time"]:
                return True

        # Poda por puerto destino
        if "dst_port" in filters and filters["dst_port"] is not None:
            p = filters["dst_port"]
            if p < self.min_dst_port or p > self.max_dst_port:
                return True

        # Poda por protocolo
        if "protocol" in filters and filters["protocol"] is not None:
            if filters["protocol"] not in self.protocols:
                return True

        # Poda por IP específica
        if "src_ip" in filters and filters["src_ip"] is not None:
            if filters["src_ip"] not in self.src_ips:
                return True
        if "dst_ip" in filters and filters["dst_ip"] is not None:
            if filters["dst_ip"] not in self.dst_ips:
                return True

        return False


class ColumnBlock:
    """Bloque columnar de almacenamiento con codificación compacta."""

    def __init__(self, block_id: int = 0):
        self.block_id = block_id
        self.timestamps: List[float] = []
        self.src_ips: List[str] = []
        self.dst_ips: List[str] = []
        self.src_ports: List[int] = []
        self.dst_ports: List[int] = []
        self.protocols: List[int] = []
        self.packets: List[int] = []
        self.bytes_transferred: List[int] = []
        self.tcp_flags: List[int] = []
        self.ja4_hashes: List[str] = []

        self.zone_map = BlockZoneMap()

    def append(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: int,
        pkts: int,
        byte_count: int,
        flags: int = 0,
        ja4: str = "",
    ):
        self.timestamps.append(ts)
        self.src_ips.append(src_ip)
        self.dst_ips.append(dst_ip)
        self.src_ports.append(src_port)
        self.dst_ports.append(dst_port)
        self.protocols.append(proto)
        self.packets.append(pkts)
        self.bytes_transferred.append(byte_count)
        self.tcp_flags.append(flags)
        self.ja4_hashes.append(ja4)

        self.zone_map.update(ts, src_ip, dst_ip, dst_port, proto, pkts, byte_count)

    def __len__(self) -> int:
        return len(self.timestamps)

    def serialize(self) -> bytes:
        """Serializa el bloque a formato binario comprimido con diccionario de strings."""
        # 1. Crear diccionarios de strings para compresión óptima
        src_dict: List[str] = list(dict.fromkeys(self.src_ips))
        dst_dict: List[str] = list(dict.fromkeys(self.dst_ips))
        ja4_dict: List[str] = list(dict.fromkeys(self.ja4_hashes))

        src_map = {s: i for i, s in enumerate(src_dict)}
        dst_map = {d: i for i, d in enumerate(dst_dict)}
        ja4_map = {j: i for i, j in enumerate(ja4_dict)}

        meta = {
            "block_id": self.block_id,
            "row_count": len(self.timestamps),
            "min_ts": self.zone_map.min_timestamp,
            "max_ts": self.zone_map.max_timestamp,
            "min_dport": self.zone_map.min_dst_port,
            "max_dport": self.zone_map.max_dst_port,
            "protocols": list(self.zone_map.protocols),
            "src_dict": src_dict,
            "dst_dict": dst_dict,
            "ja4_dict": ja4_dict,
        }
        meta_json = json.dumps(meta).encode("utf-8")

        # 2. Empaquetar columnas numéricas y referencias de diccionario
        buf = bytearray()
        buf.extend(MAGIC_HEADER)
        buf.extend(struct.pack("!I", len(meta_json)))
        buf.extend(meta_json)

        # Empaquetar datos de fila en formato vectorial
        n = len(self.timestamps)
        # Array de timestamps (float64)
        for ts in self.timestamps:
            buf.extend(struct.pack("!d", ts))
        # Array de src_ip idx (uint16)
        for s in self.src_ips:
            buf.extend(struct.pack("!H", src_map[s]))
        # Array de dst_ip idx (uint16)
        for d in self.dst_ips:
            buf.extend(struct.pack("!H", dst_map[d]))
        # Array de src_port (uint16)
        for sp in self.src_ports:
            buf.extend(struct.pack("!H", sp))
        # Array de dst_port (uint16)
        for dp in self.dst_ports:
            buf.extend(struct.pack("!H", dp))
        # Array de protocol (uint8)
        for p in self.protocols:
            buf.append(p)
        # Array de packets (uint32)
        for pk in self.packets:
            buf.extend(struct.pack("!I", pk))
        # Array de bytes (uint64)
        for b in self.bytes_transferred:
            buf.extend(struct.pack("!Q", b))
        # Array de flags (uint8)
        for f in self.tcp_flags:
            buf.append(f)
        # Array de ja4 idx (uint16)
        for j in self.ja4_hashes:
            buf.extend(struct.pack("!H", ja4_map[j]))

        # Comprimir con gzip
        return gzip.compress(bytes(buf), compresslevel=4)

    @classmethod
    def deserialize(cls, data: bytes) -> ColumnBlock:
        """Descomprime y reconstruye un ColumnBlock desde bytes serializados."""
        raw = gzip.decompress(data)
        if not raw.startswith(MAGIC_HEADER):
            raise ValueError("Formato binario NFC no reconocido o cabecera inválida")

        meta_len = struct.unpack("!I", raw[4:8])[0]
        meta_json = raw[8:8 + meta_len].decode("utf-8")
        meta = json.loads(meta_json)

        block = cls(block_id=meta.get("block_id", 0))
        n = meta["row_count"]
        src_dict = meta["src_dict"]
        dst_dict = meta["dst_dict"]
        ja4_dict = meta["ja4_dict"]

        offset = 8 + meta_len
        # Leer timestamps (n * 8 bytes)
        block.timestamps = list(struct.unpack(f"!{n}d", raw[offset:offset + n * 8]))
        offset += n * 8

        # Leer src_ip idx (n * 2 bytes)
        src_indices = struct.unpack(f"!{n}H", raw[offset:offset + n * 2])
        block.src_ips = [src_dict[i] for i in src_indices]
        offset += n * 2

        # Leer dst_ip idx (n * 2 bytes)
        dst_indices = struct.unpack(f"!{n}H", raw[offset:offset + n * 2])
        block.dst_ips = [dst_dict[i] for i in dst_indices]
        offset += n * 2

        # Leer src_ports (n * 2 bytes)
        block.src_ports = list(struct.unpack(f"!{n}H", raw[offset:offset + n * 2]))
        offset += n * 2

        # Leer dst_ports (n * 2 bytes)
        block.dst_ports = list(struct.unpack(f"!{n}H", raw[offset:offset + n * 2]))
        offset += n * 2

        # Leer protocols (n bytes)
        block.protocols = list(raw[offset:offset + n])
        offset += n

        # Leer packets (n * 4 bytes)
        block.packets = list(struct.unpack(f"!{n}I", raw[offset:offset + n * 4]))
        offset += n * 4

        # Leer bytes (n * 8 bytes)
        block.bytes_transferred = list(struct.unpack(f"!{n}Q", raw[offset:offset + n * 8]))
        offset += n * 8

        # Leer flags (n bytes)
        block.tcp_flags = list(raw[offset:offset + n])
        offset += n

        # Leer ja4 idx (n * 2 bytes)
        ja4_indices = struct.unpack(f"!{n}H", raw[offset:offset + n * 2])
        block.ja4_hashes = [ja4_dict[i] for i in ja4_indices]

        # Reconstruir ZoneMap
        for i in range(n):
            block.zone_map.update(
                block.timestamps[i],
                block.src_ips[i],
                block.dst_ips[i],
                block.dst_ports[i],
                block.protocols[i],
                block.packets[i],
                block.bytes_transferred[i],
            )

        return block


class ColumnarFlowStorage:
    """
    Gestor de base de datos columnar nativo para flujos de red.
    Combina bloques activos en RAM con bloques inmutables indexados en disco (.nfc).
    """

    def __init__(self, storage_dir: Optional[str] = None, block_size: int = 5000):
        self.storage_dir = Path(storage_dir) if storage_dir else None
        if self.storage_dir:
            self.storage_dir.mkdir(parents=True, exist_ok=True)

        self.block_size = block_size
        self.active_block = ColumnBlock(block_id=0)
        self.frozen_blocks: List[ColumnBlock] = []
        self._next_block_id = 1

    def append_flow(
        self,
        flow: NetFlowRecord,
        timestamp: Optional[float] = None,
        ja4: str = "",
    ):
        """Agrega un flujo al bloque activo. Si se llena, congela y rota el bloque."""
        ts = timestamp if timestamp is not None else time.time()
        self.active_block.append(
            ts=ts,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            proto=flow.protocol,
            pkts=flow.packets,
            byte_count=flow.bytes,
            flags=flow.tcp_flags,
            ja4=ja4,
        )

        if len(self.active_block) >= self.block_size:
            self.rotate_block()

    def append_records_batch(self, records: List[Dict[str, Any]]):
        """Ingestión en bloque a alta velocidad."""
        for r in records:
            self.active_block.append(
                ts=r.get("timestamp", time.time()),
                src_ip=r.get("src_ip", "0.0.0.0"),
                dst_ip=r.get("dst_ip", "0.0.0.0"),
                src_port=r.get("src_port", 0),
                dst_port=r.get("dst_port", 0),
                proto=r.get("protocol", 6),
                pkts=r.get("packets", 1),
                byte_count=r.get("bytes", 64),
                flags=r.get("tcp_flags", 0),
                ja4=r.get("ja4", ""),
            )
            if len(self.active_block) >= self.block_size:
                self.rotate_block()

    def rotate_block(self):
        """Congela el bloque activo y opcionalmente lo persiste en disco."""
        if len(self.active_block) == 0:
            return

        frozen = self.active_block
        if self.storage_dir:
            file_path = self.storage_dir / f"block_{frozen.block_id:06d}.nfc"
            file_path.write_bytes(frozen.serialize())

        self.frozen_blocks.append(frozen)
        self.active_block = ColumnBlock(block_id=self._next_block_id)
        self._next_block_id += 1

    def total_flows(self) -> int:
        """Número total de flujos indexados en todos los bloques."""
        total = len(self.active_block)
        for b in self.frozen_blocks:
            total += len(b)
        return total

    def query(
        self,
        filters: Optional[Dict[str, Any]] = None,
        columns: Optional[List[str]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Consulta analítica con poda de bloques por ZoneMap y proyección selectiva de columnas.
        """
        filters = filters or {}
        all_blocks = self.frozen_blocks + [self.active_block]
        results: List[Dict[str, Any]] = []

        wanted_cols = columns or [
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packets", "bytes", "flags", "ja4"
        ]

        for block in all_blocks:
            if block.zone_map.can_skip(filters):
                continue

            n = len(block)
            for i in range(n):
                # Aplicar predicados de fila
                if "src_ip" in filters and filters["src_ip"] != block.src_ips[i]:
                    continue
                if "dst_ip" in filters and filters["dst_ip"] != block.dst_ips[i]:
                    continue
                if "dst_port" in filters and filters["dst_port"] != block.dst_ports[i]:
                    continue
                if "protocol" in filters and filters["protocol"] != block.protocols[i]:
                    continue
                if "min_bytes" in filters and block.bytes_transferred[i] < filters["min_bytes"]:
                    continue
                if "ja4" in filters and filters["ja4"] != block.ja4_hashes[i]:
                    continue
                if "start_time" in filters and filters["start_time"] is not None:
                    if block.timestamps[i] < filters["start_time"]:
                        continue
                if "end_time" in filters and filters["end_time"] is not None:
                    if block.timestamps[i] > filters["end_time"]:
                        continue

                # Proyectar columnas deseadas
                row: Dict[str, Any] = {}
                for col in wanted_cols:
                    if col == "timestamp":
                        row["timestamp"] = block.timestamps[i]
                    elif col == "src_ip":
                        row["src_ip"] = block.src_ips[i]
                    elif col == "dst_ip":
                        row["dst_ip"] = block.dst_ips[i]
                    elif col == "src_port":
                        row["src_port"] = block.src_ports[i]
                    elif col == "dst_port":
                        row["dst_port"] = block.dst_ports[i]
                    elif col == "protocol":
                        row["protocol"] = block.protocols[i]
                    elif col == "packets":
                        row["packets"] = block.packets[i]
                    elif col == "bytes":
                        row["bytes"] = block.bytes_transferred[i]
                    elif col == "flags":
                        row["flags"] = block.tcp_flags[i]
                    elif col == "ja4":
                        row["ja4"] = block.ja4_hashes[i]

                results.append(row)
                if len(results) >= limit:
                    return results

        return results

    def aggregate_top_talkers(
        self,
        limit: int = 10,
        by_bytes: bool = True,
        direction: str = "src",
    ) -> List[Dict[str, Any]]:
        """Calcula los hosts principales por volumen de tráfico en tiempo récord."""
        talkers: Dict[str, int] = defaultdict(int)
        talker_flows: Dict[str, int] = defaultdict(int)

        all_blocks = self.frozen_blocks + [self.active_block]
        for block in all_blocks:
            ips = block.src_ips if direction == "src" else block.dst_ips
            metric = block.bytes_transferred if by_bytes else block.packets
            for ip, val in zip(ips, metric):
                talkers[ip] += val
                talker_flows[ip] += 1

        sorted_items = sorted(talkers.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [
            {
                "ip": ip,
                "total_volume": val,
                "metric": "bytes" if by_bytes else "packets",
                "flow_count": talker_flows[ip],
            }
            for ip, val in sorted_items
        ]

    def aggregate_protocols(self) -> Dict[str, Dict[str, int]]:
        """Genera el desglose institucional de protocolos observados."""
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        breakdown: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"flows": 0, "bytes": 0, "packets": 0}
        )

        all_blocks = self.frozen_blocks + [self.active_block]
        for block in all_blocks:
            for p, b, pk in zip(block.protocols, block.bytes_transferred, block.packets):
                name = proto_map.get(p, f"OTHER_{p}")
                breakdown[name]["flows"] += 1
                breakdown[name]["bytes"] += b
                breakdown[name]["packets"] += pk

        return dict(breakdown)

    def aggregate_timeline(self, bucket_seconds: int = 60) -> List[Dict[str, Any]]:
        """Agrupa el tráfico en cubetas temporales de N segundos para gráficos de serie temporal."""
        buckets: Dict[int, Dict[str, int]] = defaultdict(
            lambda: {"flows": 0, "bytes": 0, "packets": 0}
        )

        all_blocks = self.frozen_blocks + [self.active_block]
        for block in all_blocks:
            for ts, b, pk in zip(block.timestamps, block.bytes_transferred, block.packets):
                bucket_key = int(ts // bucket_seconds) * bucket_seconds
                buckets[bucket_key]["flows"] += 1
                buckets[bucket_key]["bytes"] += b
                buckets[bucket_key]["packets"] += pk

        sorted_buckets = sorted(buckets.items(), key=lambda x: x[0])
        return [
            {
                "timestamp": ts,
                "flows": data["flows"],
                "bytes": data["bytes"],
                "packets": data["packets"],
            }
            for ts, data in sorted_buckets
        ]
