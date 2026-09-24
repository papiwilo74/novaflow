"""
NovaFlow NDR - NetFlow v5 Binary Protocol Parser
Decodificador de alto rendimiento para datagramas UDP NetFlow v5.
"""

import socket
import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional
from datetime import datetime, timezone

# Formatos de empaquetado binario conforme a RFC/Cisco NetFlow v5
# Header: 24 bytes (!HHIIIIBBH)
HEADER_FORMAT = "!HHIIIIBBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Record: 48 bytes (!4s4s4sHHIIIIHHBBBBHHBBH)
RECORD_FORMAT = "!4s4s4sHHIIIIHHBBBBHHBBH"
RECORD_SIZE = struct.calcsize(RECORD_FORMAT)


@dataclass(slots=True)
class NetFlowHeader:
    version: int
    count: int
    sys_uptime: int
    unix_secs: int
    unix_nsecs: int
    flow_sequence: int
    engine_type: int
    engine_id: int
    sampling_interval: int


@dataclass(slots=True)
class NetFlowRecord:
    timestamp: datetime
    timestamp_ms: int
    src_ip: str
    dst_ip: str
    next_hop: str
    input_snmp: int
    output_snmp: int
    packets: int
    bytes: int
    first_switched: int
    last_switched: int
    src_port: int
    dst_port: int
    tcp_flags: int
    protocol: int
    tos: int
    src_as: int
    dst_as: int
    src_mask: int
    dst_mask: int
    flow_version: int = 5
    campaign_id: Optional[str] = None
    vector_id: Optional[str] = None


class NetFlowParser:
    """Parser optimizado para procesar datagramas NetFlow v5 binarios."""

    @staticmethod
    def parse_packet(data: bytes, exporter_ip: str = "127.0.0.1") -> Tuple[Optional[NetFlowHeader], List[NetFlowRecord]]:
        """
        Parsea un buffer binario UDP completo recibido en puerto 2055/4739.
        Auto-detecta la versión del protocolo (v5, v9 o IPFIX) y retorna registros normalizados.
        """
        data_len = len(data)
        if data_len < 4:
            return None, []

        version = struct.unpack("!H", data[:2])[0]

        # 1. NetFlow v9 (RFC 3954)
        if version == 9:
            from collector.netflow_v9 import parse_netflow_v9
            hdr_v9, recs_v9 = parse_netflow_v9(data, exporter_ip=exporter_ip)
            if hdr_v9:
                header = NetFlowHeader(
                    version=9,
                    count=hdr_v9.get("count", len(recs_v9)),
                    sys_uptime=hdr_v9.get("sys_uptime", 0),
                    unix_secs=hdr_v9.get("unix_secs", 0),
                    unix_nsecs=0,
                    flow_sequence=hdr_v9.get("flow_sequence", 0),
                    engine_type=0,
                    engine_id=hdr_v9.get("source_id", 0),
                    sampling_interval=0,
                )
                return header, recs_v9
            return None, []

        # 2. IPFIX / NetFlow v10 (RFC 7011)
        if version == 10:
            from collector.netflow_v9 import parse_ipfix
            hdr_ipfix, recs_ipfix = parse_ipfix(data, exporter_ip=exporter_ip)
            if hdr_ipfix:
                header = NetFlowHeader(
                    version=10,
                    count=len(recs_ipfix),
                    sys_uptime=0,
                    unix_secs=hdr_ipfix.get("unix_secs", 0),
                    unix_nsecs=0,
                    flow_sequence=hdr_ipfix.get("flow_sequence", 0),
                    engine_type=0,
                    engine_id=hdr_ipfix.get("source_id", 0),
                    sampling_interval=0,
                )
                return header, recs_ipfix
            return None, []

        # 3. NetFlow v5 (Legacy 24 bytes header)
        if version != 5 or data_len < HEADER_SIZE:
            return None, []

        # Decodificar Header v5 (24 bytes)
        hdr_fields = struct.unpack_from(HEADER_FORMAT, data, 0)
        count = hdr_fields[1]
        sys_uptime = hdr_fields[2]
        unix_secs = hdr_fields[3]
        unix_nsecs = hdr_fields[4]
        flow_sequence = hdr_fields[5]
        engine_type = hdr_fields[6]
        engine_id = hdr_fields[7]
        sampling_interval = hdr_fields[8]

        header = NetFlowHeader(
            version=version,
            count=count,
            sys_uptime=sys_uptime,
            unix_secs=unix_secs,
            unix_nsecs=unix_nsecs,
            flow_sequence=flow_sequence,
            engine_type=engine_type,
            engine_id=engine_id,
            sampling_interval=sampling_interval,
        )

        expected_size = HEADER_SIZE + (count * RECORD_SIZE)
        if data_len < expected_size:
            # Paquete truncado, procesar los registros que quepan
            count = (data_len - HEADER_SIZE) // RECORD_SIZE

        records: List[NetFlowRecord] = []
        offset = HEADER_SIZE

        # Timestamp base del paquete
        try:
            base_time = datetime.fromtimestamp(unix_secs, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            base_time = datetime.now(timezone.utc)
        
        timestamp_ms = int(unix_nsecs / 1_000_000)

        # 2. Decodificar registros de flujo (48 bytes c/u)
        for _ in range(count):
            rec_fields = struct.unpack_from(RECORD_FORMAT, data, offset)
            offset += RECORD_SIZE

            src_ip = socket.inet_ntoa(rec_fields[0])
            dst_ip = socket.inet_ntoa(rec_fields[1])
            next_hop = socket.inet_ntoa(rec_fields[2])

            record = NetFlowRecord(
                timestamp=base_time,
                timestamp_ms=timestamp_ms,
                src_ip=src_ip,
                dst_ip=dst_ip,
                next_hop=next_hop,
                input_snmp=rec_fields[3],
                output_snmp=rec_fields[4],
                packets=rec_fields[5],
                bytes=rec_fields[6],
                first_switched=rec_fields[7],
                last_switched=rec_fields[8],
                src_port=rec_fields[9],
                dst_port=rec_fields[10],
                # rec_fields[11] es pad1
                tcp_flags=rec_fields[12],
                protocol=rec_fields[13],
                tos=rec_fields[14],
                src_as=rec_fields[15],
                dst_as=rec_fields[16],
                src_mask=rec_fields[17],
                dst_mask=rec_fields[18],
                # rec_fields[19] es pad2
                flow_version=5,
            )
            records.append(record)

        return header, records
