"""
NovaFlow NDR - NetFlow v9 (RFC 3954) & IPFIX (RFC 7011) Binary Protocol Parser
Decodificador dinámico de alta velocidad con soporte para Template Flowsets, IPv6 nativo (128 bits)
e Information Elements estándar IANA.
"""

import socket
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from collector.parser import NetFlowRecord

# Cabeceras binarias
# NetFlow v9: 20 bytes (!HHIIII)
V9_HEADER_FORMAT = "!HHIIII"
V9_HEADER_SIZE = struct.calcsize(V9_HEADER_FORMAT)

# IPFIX (v10): 16 bytes (!HHIII)
IPFIX_HEADER_FORMAT = "!HHIII"
IPFIX_HEADER_SIZE = struct.calcsize(IPFIX_HEADER_FORMAT)

# Flowset / Set Header: 4 bytes (!HH)
FLOWSET_HEADER_FORMAT = "!HH"
FLOWSET_HEADER_SIZE = struct.calcsize(FLOWSET_HEADER_FORMAT)

# IANA Standard Field Types
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_PROTOCOL = 4
FIELD_TOS = 5
FIELD_TCP_FLAGS = 6
FIELD_L4_SRC_PORT = 7
FIELD_IPV4_SRC_ADDR = 8
FIELD_SRC_MASK = 9
FIELD_INPUT_SNMP = 10
FIELD_L4_DST_PORT = 11
FIELD_IPV4_DST_ADDR = 12
FIELD_DST_MASK = 13
FIELD_OUTPUT_SNMP = 14
FIELD_IPV4_NEXT_HOP = 15
FIELD_SRC_AS = 16
FIELD_DST_AS = 17
FIELD_FIRST_SWITCHED = 21
FIELD_LAST_SWITCHED = 22
FIELD_IPV6_SRC_ADDR = 27
FIELD_IPV6_DST_ADDR = 28
FIELD_APPLICATION_ID = 95


class TemplateCache:
    """Mantiene en memoria las plantillas de flujo registradas por exportador y ID."""

    def __init__(self):
        # (exporter_ip, observation_domain_id, template_id) -> list of (field_type, field_length)
        self._templates: Dict[Tuple[str, int, int], List[Tuple[int, int]]] = {}

    def register_template(
        self,
        exporter_ip: str,
        domain_id: int,
        template_id: int,
        fields: List[Tuple[int, int]],
    ):
        self._templates[(exporter_ip, domain_id, template_id)] = fields

    def get_template(
        self,
        exporter_ip: str,
        domain_id: int,
        template_id: int,
    ) -> Optional[List[Tuple[int, int]]]:
        return self._templates.get((exporter_ip, domain_id, template_id))


# Instancia compartida de plantillas
global_template_cache = TemplateCache()


def parse_netflow_v9(
    data: bytes,
    exporter_ip: str = "127.0.0.1",
    cache: Optional[TemplateCache] = None,
) -> Tuple[Optional[Dict[str, Any]], List[NetFlowRecord]]:
    """
    Decodifica un datagrama binario NetFlow v9 (RFC 3954).
    Soporta Flowsets de Plantillas (ID 0) y Flowsets de Datos (ID >= 256).
    """
    if len(data) < V9_HEADER_SIZE:
        return None, []

    template_cache = cache or global_template_cache

    version, count, sys_uptime, unix_secs, flow_seq, source_id = struct.unpack(
        V9_HEADER_FORMAT, data[:V9_HEADER_SIZE]
    )

    if version != 9:
        return None, []

    header = {
        "version": 9,
        "count": count,
        "sys_uptime": sys_uptime,
        "unix_secs": unix_secs,
        "flow_sequence": flow_seq,
        "source_id": source_id,
    }

    records: List[NetFlowRecord] = []
    offset = V9_HEADER_SIZE
    data_len = len(data)
    flow_ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    while offset + FLOWSET_HEADER_SIZE <= data_len:
        flowset_id, flowset_len = struct.unpack(
            FLOWSET_HEADER_FORMAT, data[offset : offset + FLOWSET_HEADER_SIZE]
        )

        if flowset_len < FLOWSET_HEADER_SIZE or (offset + flowset_len) > data_len:
            break

        flowset_data = data[offset + FLOWSET_HEADER_SIZE : offset + flowset_len]

        # 1. Template Flowset (ID = 0)
        if flowset_id == 0:
            tmpl_offset = 0
            while tmpl_offset + 4 <= len(flowset_data):
                template_id, field_count = struct.unpack(
                    "!HH", flowset_data[tmpl_offset : tmpl_offset + 4]
                )
                tmpl_offset += 4
                fields: List[Tuple[int, int]] = []
                for _ in range(field_count):
                    if tmpl_offset + 4 > len(flowset_data):
                        break
                    f_type, f_len = struct.unpack(
                        "!HH", flowset_data[tmpl_offset : tmpl_offset + 4]
                    )
                    fields.append((f_type, f_len))
                    tmpl_offset += 4

                template_cache.register_template(
                    exporter_ip, source_id, template_id, fields
                )

        # 2. Options Template Flowset (ID = 1) -> ignorar o saltar
        elif flowset_id == 1:
            pass

        # 3. Data Flowset (ID >= 256)
        elif flowset_id >= 256:
            template = template_cache.get_template(exporter_ip, source_id, flowset_id)
            if template:
                record_size = sum(f_len for _, f_len in template)
                if record_size > 0:
                    d_offset = 0
                    while d_offset + record_size <= len(flowset_data):
                        rec = _decode_data_record(
                            flowset_data[d_offset : d_offset + record_size],
                            template,
                            flow_ts,
                            flow_version=9,
                        )
                        if rec:
                            records.append(rec)
                        d_offset += record_size

        offset += flowset_len

    return header, records


def parse_ipfix(
    data: bytes,
    exporter_ip: str = "127.0.0.1",
    cache: Optional[TemplateCache] = None,
) -> Tuple[Optional[Dict[str, Any]], List[NetFlowRecord]]:
    """
    Decodifica un datagrama binario IPFIX (RFC 7011 / NetFlow v10).
    Soporta Set ID 2 (Template Set) y Set ID >= 256 (Data Set).
    """
    if len(data) < IPFIX_HEADER_SIZE:
        return None, []

    template_cache = cache or global_template_cache

    version, total_len, export_time, seq_num, domain_id = struct.unpack(
        IPFIX_HEADER_FORMAT, data[:IPFIX_HEADER_SIZE]
    )

    if version != 10:
        return None, []

    header = {
        "version": 10,
        "length": total_len,
        "unix_secs": export_time,
        "flow_sequence": seq_num,
        "source_id": domain_id,
    }

    records: List[NetFlowRecord] = []
    offset = IPFIX_HEADER_SIZE
    data_len = min(len(data), total_len)
    flow_ts = datetime.fromtimestamp(export_time, tz=timezone.utc)

    while offset + FLOWSET_HEADER_SIZE <= data_len:
        set_id, set_len = struct.unpack(
            FLOWSET_HEADER_FORMAT, data[offset : offset + FLOWSET_HEADER_SIZE]
        )

        if set_len < FLOWSET_HEADER_SIZE or (offset + set_len) > data_len:
            break

        set_data = data[offset + FLOWSET_HEADER_SIZE : offset + set_len]

        # 1. IPFIX Template Set (ID = 2)
        if set_id == 2:
            tmpl_offset = 0
            while tmpl_offset + 4 <= len(set_data):
                template_id, field_count = struct.unpack(
                    "!HH", set_data[tmpl_offset : tmpl_offset + 4]
                )
                tmpl_offset += 4
                fields: List[Tuple[int, int]] = []
                for _ in range(field_count):
                    if tmpl_offset + 4 > len(set_data):
                        break
                    f_type, f_len = struct.unpack(
                        "!HH", set_data[tmpl_offset : tmpl_offset + 4]
                    )
                    tmpl_offset += 4
                    # Si el bit más significativo está activo, es Enterprise Specific (4 bytes extra de PEN)
                    if f_type & 0x8000:
                        f_type = f_type & 0x7FFF
                        tmpl_offset += 4
                    fields.append((f_type, f_len))

                template_cache.register_template(
                    exporter_ip, domain_id, template_id, fields
                )

        # 2. IPFIX Data Set (ID >= 256)
        elif set_id >= 256:
            template = template_cache.get_template(exporter_ip, domain_id, set_id)
            if template:
                record_size = sum(f_len for _, f_len in template)
                if record_size > 0:
                    d_offset = 0
                    while d_offset + record_size <= len(set_data):
                        rec = _decode_data_record(
                            set_data[d_offset : d_offset + record_size],
                            template,
                            flow_ts,
                            flow_version=10,
                        )
                        if rec:
                            records.append(rec)
                        d_offset += record_size

        offset += set_len

    return header, records


def _decode_data_record(
    raw_data: bytes,
    template: List[Tuple[int, int]],
    timestamp: datetime,
    flow_version: int,
) -> Optional[NetFlowRecord]:
    """Decodifica los bytes de un registro de datos según la plantilla activa."""
    values: Dict[int, Any] = {}
    pos = 0

    for f_type, f_len in template:
        chunk = raw_data[pos : pos + f_len]
        pos += f_len

        if f_len == 1:
            values[f_type] = struct.unpack("!B", chunk)[0]
        elif f_len == 2:
            values[f_type] = struct.unpack("!H", chunk)[0]
        elif f_len == 4:
            if f_type in (FIELD_IPV4_SRC_ADDR, FIELD_IPV4_DST_ADDR, FIELD_IPV4_NEXT_HOP):
                values[f_type] = socket.inet_ntoa(chunk)
            else:
                values[f_type] = struct.unpack("!I", chunk)[0]
        elif f_len == 8:
            values[f_type] = struct.unpack("!Q", chunk)[0]
        elif f_len == 16:
            if f_type in (FIELD_IPV6_SRC_ADDR, FIELD_IPV6_DST_ADDR):
                values[f_type] = socket.inet_ntop(socket.AF_INET6, chunk)
            else:
                values[f_type] = chunk.hex()
        else:
            values[f_type] = int.from_bytes(chunk, byteorder="big")

    # Extraer direcciones de origen y destino (con soporte IPv4 o IPv6)
    src_ip = values.get(FIELD_IPV4_SRC_ADDR) or values.get(FIELD_IPV6_SRC_ADDR) or "0.0.0.0"
    dst_ip = values.get(FIELD_IPV4_DST_ADDR) or values.get(FIELD_IPV6_DST_ADDR) or "0.0.0.0"

    bytes_val = values.get(FIELD_IN_BYTES, 0)
    pkts_val = values.get(FIELD_IN_PKTS, 1)

    return NetFlowRecord(
        timestamp=timestamp,
        timestamp_ms=int(timestamp.timestamp() * 1000),
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop=values.get(FIELD_IPV4_NEXT_HOP, "0.0.0.0"),
        input_snmp=values.get(FIELD_INPUT_SNMP, 0),
        output_snmp=values.get(FIELD_OUTPUT_SNMP, 0),
        packets=pkts_val,
        bytes=bytes_val,
        first_switched=values.get(FIELD_FIRST_SWITCHED, 0),
        last_switched=values.get(FIELD_LAST_SWITCHED, 0),
        src_port=values.get(FIELD_L4_SRC_PORT, 0),
        dst_port=values.get(FIELD_L4_DST_PORT, 0),
        tcp_flags=values.get(FIELD_TCP_FLAGS, 0),
        protocol=values.get(FIELD_PROTOCOL, 6),
        tos=values.get(FIELD_TOS, 0),
        src_as=values.get(FIELD_SRC_AS, 0),
        dst_as=values.get(FIELD_DST_AS, 0),
        src_mask=values.get(FIELD_SRC_MASK, 0),
        dst_mask=values.get(FIELD_DST_MASK, 0),
        flow_version=flow_version,
    )
