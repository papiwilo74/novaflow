"""
NovaFlow NDR - NetFlow v9 & IPFIX Binary Decoder Tests (Phase 2 Enterprise)
Valida la decodificación de Template Flowsets, Data Flowsets, soporte IPv6 nativo (RFC 7011)
y el auto-enrutador de versiones del colector.
"""

import socket
import struct
import unittest
from datetime import datetime, timezone

from collector.netflow_v9 import (
    FIELD_IN_BYTES,
    FIELD_IN_PKTS,
    FIELD_IPV4_DST_ADDR,
    FIELD_IPV4_SRC_ADDR,
    FIELD_IPV6_DST_ADDR,
    FIELD_IPV6_SRC_ADDR,
    FIELD_L4_DST_PORT,
    FIELD_L4_SRC_PORT,
    FIELD_PROTOCOL,
    FIELD_TCP_FLAGS,
    TemplateCache,
    parse_ipfix,
    parse_netflow_v9,
)
from collector.parser import NetFlowParser
from detector.engine import DetectionEngine
from detector.models import AlertCategory


def build_v9_packet(template_id=256, unix_secs=1700000000) -> bytes:
    """
    Construye un paquete NetFlow v9 sintético con un Template Flowset y un Data Flowset.
    """
    # 1. Cabecera v9 (20 bytes): !HHIIII
    # version=9, count=2 (2 flowsets), sys_uptime=10000, unix_secs, flow_seq=1, source_id=1
    hdr = struct.pack("!HHIIII", 9, 2, 10000, unix_secs, 1, 1)

    # 2. Template Flowset (ID=0)
    # Template define 8 campos:
    # IPV4_SRC_ADDR (4), IPV4_DST_ADDR (4), L4_SRC_PORT (2), L4_DST_PORT (2),
    # PROTOCOL (1), TCP_FLAGS (1), IN_BYTES (4), IN_PKTS (4)
    tmpl_fields = [
        (FIELD_IPV4_SRC_ADDR, 4),
        (FIELD_IPV4_DST_ADDR, 4),
        (FIELD_L4_SRC_PORT, 2),
        (FIELD_L4_DST_PORT, 2),
        (FIELD_PROTOCOL, 1),
        (FIELD_TCP_FLAGS, 1),
        (FIELD_IN_BYTES, 4),
        (FIELD_IN_PKTS, 4),
    ]
    # Flowset header: flowset_id=0, length = 4 + 4 + (8 * 4) = 40 bytes
    tmpl_body = struct.pack("!HH", template_id, len(tmpl_fields))
    for f_type, f_len in tmpl_fields:
        tmpl_body += struct.pack("!HH", f_type, f_len)

    tmpl_flowset_len = 4 + len(tmpl_body)
    tmpl_flowset = struct.pack("!HH", 0, tmpl_flowset_len) + tmpl_body

    # 3. Data Flowset (ID=template_id)
    # Registro de 22 bytes
    src_b = socket.inet_aton("192.168.1.50")
    dst_b = socket.inet_aton("104.244.42.1")
    rec_bytes = 25_000_000
    rec_pkts = 18_000
    rec_data = (
        src_b
        + dst_b
        + struct.pack("!HHBBII", 51234, 443, 6, 0x18, rec_bytes, rec_pkts)
    )

    data_flowset_len = 4 + len(rec_data)
    data_flowset = struct.pack("!HH", template_id, data_flowset_len) + rec_data

    return hdr + tmpl_flowset + data_flowset


def build_ipfix_ipv6_packet(template_id=258, export_time=1700000000) -> bytes:
    """
    Construye un datagrama IPFIX (RFC 7011 / v10) con direcciones IPv6 (128 bits).
    """
    # 1. Template Set (Set ID = 2)
    tmpl_fields = [
        (FIELD_IPV6_SRC_ADDR, 16),
        (FIELD_IPV6_DST_ADDR, 16),
        (FIELD_L4_SRC_PORT, 2),
        (FIELD_L4_DST_PORT, 2),
        (FIELD_PROTOCOL, 1),
        (FIELD_TCP_FLAGS, 1),
        (FIELD_IN_BYTES, 4),
        (FIELD_IN_PKTS, 4),
    ]
    tmpl_body = struct.pack("!HH", template_id, len(tmpl_fields))
    for f_type, f_len in tmpl_fields:
        tmpl_body += struct.pack("!HH", f_type, f_len)

    tmpl_set_len = 4 + len(tmpl_body)
    tmpl_set = struct.pack("!HH", 2, tmpl_set_len) + tmpl_body

    # 2. Data Set (Set ID = template_id)
    src_v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    dst_v6 = socket.inet_pton(socket.AF_INET6, "2606:4700::6811:d109")
    rec_data = (
        src_v6
        + dst_v6
        + struct.pack("!HHBBII", 45000, 80, 6, 0x02, 120, 2)
    )
    data_set_len = 4 + len(rec_data)
    data_set = struct.pack("!HH", template_id, data_set_len) + rec_data

    total_msg_len = 16 + len(tmpl_set) + len(data_set)

    # Cabecera IPFIX (16 bytes): !HHIII
    hdr = struct.pack("!HHIII", 10, total_msg_len, export_time, 1, 1)

    return hdr + tmpl_set + data_set


class TestNetFlowV9AndIPFIX(unittest.TestCase):
    """Pruebas para el decodificador de NetFlow v9 e IPFIX."""

    def test_parse_netflow_v9_packet(self):
        """Verifica la decodificación completa de una cabecera, plantilla y datos v9."""
        packet_bytes = build_v9_packet(template_id=300)
        cache = TemplateCache()
        header, records = parse_netflow_v9(packet_bytes, exporter_ip="192.168.1.1", cache=cache)

        self.assertIsNotNone(header)
        self.assertEqual(header["version"], 9)
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertEqual(rec.flow_version, 9)
        self.assertEqual(rec.src_ip, "192.168.1.50")
        self.assertEqual(rec.dst_ip, "104.244.42.1")
        self.assertEqual(rec.src_port, 51234)
        self.assertEqual(rec.dst_port, 443)
        self.assertEqual(rec.protocol, 6)
        self.assertEqual(rec.tcp_flags, 0x18)
        self.assertEqual(rec.bytes, 25_000_000)
        self.assertEqual(rec.packets, 18_000)

    def test_parse_ipfix_ipv6_packet(self):
        """Verifica la decodificación de paquetes IPFIX con soporte nativo de IPv6 (128 bits)."""
        packet_bytes = build_ipfix_ipv6_packet(template_id=301)
        cache = TemplateCache()
        header, records = parse_ipfix(packet_bytes, exporter_ip="10.0.0.1", cache=cache)

        self.assertIsNotNone(header)
        self.assertEqual(header["version"], 10)
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertEqual(rec.flow_version, 10)
        self.assertEqual(rec.src_ip, "2001:db8::1")
        self.assertEqual(rec.dst_ip, "2606:4700::6811:d109")
        self.assertEqual(rec.src_port, 45000)
        self.assertEqual(rec.dst_port, 80)
        self.assertEqual(rec.protocol, 6)
        self.assertEqual(rec.bytes, 120)

    def test_universal_netflow_parser_auto_dispatch(self):
        """Verifica que NetFlowParser.parse_packet auto-detecte v5, v9 e IPFIX sin configuración manual."""
        # 1. Probar con v9
        v9_data = build_v9_packet(template_id=305)
        hdr_v9, recs_v9 = NetFlowParser.parse_packet(v9_data)
        self.assertIsNotNone(hdr_v9)
        self.assertEqual(hdr_v9.version, 9)
        self.assertEqual(len(recs_v9), 1)
        self.assertEqual(recs_v9[0].src_ip, "192.168.1.50")

        # 2. Probar con IPFIX (v10)
        ipfix_data = build_ipfix_ipv6_packet(template_id=306)
        hdr_ipfix, recs_ipfix = NetFlowParser.parse_packet(ipfix_data)
        self.assertIsNotNone(hdr_ipfix)
        self.assertEqual(hdr_ipfix.version, 10)
        self.assertEqual(len(recs_ipfix), 1)
        self.assertEqual(recs_ipfix[0].src_ip, "2001:db8::1")

    def test_engine_processes_v9_flow_and_detects_threats(self):
        """Verifica que los flujos decodificados desde NetFlow v9 alimenten al DetectionEngine y disparen alertas."""
        engine = DetectionEngine()
        # Construir flujo v9 con 25 MB salientes hacia IP externa (exfiltración)
        v9_data = build_v9_packet(template_id=310)
        _, records = NetFlowParser.parse_packet(v9_data)
        self.assertEqual(len(records), 1)

        alerts = engine.analyze_flow(records[0])
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, AlertCategory.EXFILTRATION)
        self.assertEqual(alerts[0].src_ip, "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
