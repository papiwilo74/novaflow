"""
NovaFlow NDR - Test Suite: Unified L4/L7 Hybrid Detection Pipeline
Valida la integración integral de los analizadores de capa de aplicación (DNS, TLS JA4, Kerberos, DCE-RPC)
y su orquestación unificada en tiempo real dentro de DetectionEngine.
"""

import struct
import unittest
import uuid
from datetime import datetime, timezone

from collector.l7_parsers import KNOWN_RPC_INTERFACES
from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity


def make_test_flow(
    src_ip: str = "10.0.0.100",
    dst_ip: str = "192.168.1.10",
    src_port: int = 50000,
    dst_port: int = 443,
    protocol: int = 6,
    tcp_flags: int = 0x18,
    packets: int = 10,
    bytes_val: int = 1500,
    payload: bytes = b"",
    domain: str = None,
) -> NetFlowRecord:
    return NetFlowRecord(
        timestamp=datetime.now(timezone.utc),
        timestamp_ms=0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop="192.168.1.1",
        input_snmp=1,
        output_snmp=2,
        packets=packets,
        bytes=bytes_val,
        first_switched=1000,
        last_switched=2000,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        protocol=protocol,
        tos=0,
        src_as=65000,
        dst_as=65000,
        src_mask=24,
        dst_mask=24,
        payload=payload,
        domain=domain,
    )


def build_raw_dns_query(domain: str) -> bytes:
    """Construye un paquete binario RFC 1035 DNS Query en crudo."""
    tx_id = 0x1337
    flags = 0x0100  # Standard query, recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # Codificar labels
    qname = b""
    for part in domain.split("."):
        b_part = part.encode("ascii")
        qname += bytes([len(b_part)]) + b_part
    qname += b"\x00"

    qtype = 1  # A
    qclass = 1  # IN
    question = qname + struct.pack("!HH", qtype, qclass)
    return header + question


def build_raw_dns_response(domain: str, resolved_ips: list, ttl: int = 60) -> bytes:
    """Construye un paquete binario RFC 1035 DNS Response con múltiples registros A."""
    tx_id = 0x1337
    flags = 0x8180  # Standard response, recursion available, no error
    qdcount = 1
    ancount = len(resolved_ips)
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, 0, 0)

    # Question
    qname = b""
    for part in domain.split("."):
        b_part = part.encode("ascii")
        qname += bytes([len(b_part)]) + b_part
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)

    # Answers (usando compresión de puntero al inicio del question offset 12)
    answers = b""
    import socket
    for ip in resolved_ips:
        aname = b"\xc0\x0c"  # Puntero a offset 12
        ip_bytes = socket.inet_aton(ip)
        answers += aname + struct.pack("!HHIH", 1, 1, ttl, 4) + ip_bytes

    return header + question + answers


def build_raw_tls_client_hello() -> bytes:
    """Construye un payload binario TLS 1.2 ClientHello válido en wire format."""
    # Simula una suite representativa de Cobalt Strike / Sliver
    ciphers = [0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    ciphers_bytes = b"".join(struct.pack("!H", c) for c in ciphers)

    # Extensiones: SNI + supported_groups (10) + ec_point_formats (11) + signature_algorithms (13)
    sni_payload = b"\x00\x0f\x00\x00\x0cc2.darknet.ru"
    ext_sni = struct.pack("!HH", 0x0000, len(sni_payload)) + sni_payload
    ext_groups = struct.pack("!HH", 0x000A, 4) + struct.pack("!HH", 2, 0x0017)
    ext_formats = struct.pack("!HH", 0x000B, 2) + b"\x01\x00"
    ext_sig = struct.pack("!HH", 0x000D, 4) + struct.pack("!HH", 2, 0x0403)
    extensions_payload = ext_sni + ext_groups + ext_formats + ext_sig

    session_id = b"\x00"
    client_random = b"\x01" * 32
    client_version = 0x0303  # TLS 1.2

    ch_body = (
        struct.pack("!H", client_version)
        + client_random
        + session_id
        + struct.pack("!H", len(ciphers_bytes))
        + ciphers_bytes
        + b"\x01\x00"  # Compression: null
        + struct.pack("!H", len(extensions_payload))
        + extensions_payload
    )

    handshake_msg = struct.pack("!B", 0x01) + struct.pack("!I", len(ch_body))[1:] + ch_body
    tls_record = struct.pack("!BHH", 0x16, 0x0301, len(handshake_msg)) + handshake_msg
    return tls_record


def build_raw_kerberos_asrep_payload() -> bytes:
    """Construye una trama Kerberos AS-REQ sin pre-autenticación (AS-REP Roasting)."""
    # 0x6A (AS-REQ) + longitud
    body = b"\x30\x0c\xa1\x03\x02\x01\x05\xa2\x05\x02\x03\x01\x02\x03"
    return bytes([0x6A, len(body)]) + body


def build_raw_kerberos_tgs_rc4_payload() -> bytes:
    """Construye una trama Kerberos TGS-REQ forzando cifrado débil RC4 (Kerberoasting)."""
    # 0x6C (TGS-REQ), con padata indicando PA-TGS-REQ y etype 0x17 (RC4)
    # Sub-bloques TLV simulados
    body = (
        b"\x30\x22\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0c"
        b"\xa3\x08\x30\x06\x02\x01\x17\x02\x01\x12"  # etype 23 (0x17)
        b"\xa4\x0e\x30\x0c\x1b\x0aMSSQLSvc/db"
    )
    return bytes([0x6C, len(body)]) + body


def build_raw_dcerpc_bind(interface_uuid: str) -> bytes:
    """Construye una cabecera DCE-RPC versión 5 Bind Packet con el UUID solicitado."""
    guid_bytes = uuid.UUID(interface_uuid).bytes_le
    header = (
        struct.pack("!BBB", 5, 0, 11)  # v5.0, Bind (11)
        + b"\x03"  # pfc_flags
        + struct.pack("<I", 0x10)  # drep
        + struct.pack("<H", 72)    # frag_len
        + struct.pack("<H", 0)     # auth_len
        + struct.pack("<I", 1)     # call_id
        + struct.pack("<H", 5840)  # max_xmit_frag
        + struct.pack("<H", 5840)  # max_recv_frag
        + struct.pack("<I", 0)     # assoc_group_id
        + struct.pack("<B", 1)     # num_context_elem
        + b"\x00\x00\x00"          # reserved
        + struct.pack("<H", 0)     # context_id
        + struct.pack("<B", 1)     # num_trans_items
        + b"\x00"                  # reserved
        + guid_bytes               # Abstract Syntax Interface UUID
        + struct.pack("<H", 1)     # vers_major
        + struct.pack("<H", 0)     # vers_minor
    )
    return header


class TestUnifiedL7DetectionPipeline(unittest.TestCase):
    """Batería de pruebas que verifica la unificación de L4 y L7 en DetectionEngine."""

    def setUp(self):
        self.engine = DetectionEngine()

    def test_pure_l4_flow_backward_compatibility(self):
        """Verifica que flujos tradicionales sin payload sigan evaluándose a microsegundos."""
        flow = make_test_flow(src_ip="10.0.0.5", dst_ip="10.0.0.10", dst_port=80, payload=b"")
        alerts = self.engine.analyze_flow(flow)
        self.assertEqual(len(alerts), 0)
        self.assertEqual(self.engine.stats["flows_analyzed"], 1)

    def test_dns_wire_query_dga_detection(self):
        """Valida que un datagrama UDP/53 conteniendo un dominio DGA en cable dispare alerta."""
        dga_domain = "kzxytmqwvbnplk.biz"
        dns_pkt = build_raw_dns_query(dga_domain)

        flow = make_test_flow(
            src_ip="192.168.1.45",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol=17,
            payload=dns_pkt,
        )

        alerts = self.engine.analyze_flow(flow)
        dga_alert = next((a for a in alerts if a.category == AlertCategory.DGA_DOMAIN), None)
        self.assertIsNotNone(dga_alert, "FALLO: Dominio DGA dentro del paquete DNS no detectado")
        self.assertIn("DGA", dga_alert.title)
        self.assertEqual(dga_alert.src_ip, "192.168.1.45")

    def test_dns_wire_response_fast_flux_detection(self):
        """Valida que respuestas DNS con múltiples IPs y bajo TTL disparen alerta Fast-Flux."""
        domain = "fastflux-resilient-c2.org"
        ips = ["198.51.100.1", "198.51.100.2", "203.0.113.5", "203.0.113.6", "192.0.2.7"]
        dns_resp = build_raw_dns_response(domain, ips, ttl=45)

        flow = make_test_flow(
            src_ip="192.168.1.45",
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol=17,
            payload=dns_resp,
        )

        alerts = self.engine.analyze_flow(flow)
        ff_alert = next((a for a in alerts if a.category == AlertCategory.DGA_DOMAIN and "Fast-Flux" in a.title), None)
        self.assertIsNotNone(ff_alert, "FALLO: Respuesta DNS Fast-Flux no detectada")
        self.assertIn("fastflux", ff_alert.title.lower())

    def test_tls_ja4_client_hello_detection(self):
        """Valida que un paquete TLS ClientHello sea diseccionado y cotejado contra firmas JA4."""
        tls_payload = build_raw_tls_client_hello()

        # Inyectar una firma conocida en la base de JA4 para la prueba
        from detector.ja4 import JA4Fingerprint
        from collector.tls_parser import TLSParser
        hello = TLSParser.parse_client_hello(tls_payload)
        self.assertIsNotNone(hello)
        ja4_sig = JA4Fingerprint.calculate_ja4(hello, protocol="TCP")
        self.engine.ja4_threat_detector.db.add_fingerprint(
            fingerprint=ja4_sig,
            family="Cobalt Strike",
            tool="Malleable C2 Beacon",
            severity="CRITICAL",
        )

        flow = make_test_flow(
            src_ip="10.0.0.77",
            dst_ip="198.51.100.88",
            dst_port=443,
            protocol=6,
            payload=tls_payload,
        )

        alerts = self.engine.analyze_flow(flow)
        ja4_alert = next((a for a in alerts if a.category == AlertCategory.MALICIOUS_C2), None)
        self.assertIsNotNone(ja4_alert, "FALLO: Firma JA4 C2 en ClientHello no detectada")
        self.assertIn("Cobalt Strike", ja4_alert.title)
        self.assertEqual(ja4_alert.src_ip, "10.0.0.77")

    def test_kerberos_asrep_roasting_detection(self):
        """Valida que una trama Kerberos AS-REQ sin pre-autenticación dispare AS-REP Roasting."""
        asrep_payload = build_raw_kerberos_asrep_payload()

        flow = make_test_flow(
            src_ip="10.0.0.50",
            dst_ip="10.0.0.1",
            dst_port=88,
            protocol=17,
            payload=asrep_payload,
        )

        alerts = self.engine.analyze_flow(flow)
        ad_alert = next((a for a in alerts if a.category == AlertCategory.IDENTITY_ATTACK), None)
        self.assertIsNotNone(ad_alert, "FALLO: Ataque AS-REP Roasting no detectado")
        self.assertIn("AS-REP", ad_alert.title)

    def test_kerberos_kerberoasting_detection(self):
        """Valida que tramas Kerberos TGS-REQ solicitando RC4 disparen Kerberoasting."""
        tgs_payload = build_raw_kerberos_tgs_rc4_payload()

        # Emitir 2 solicitudes consecutivas hacia diferentes servicios
        flow1 = make_test_flow(
            src_ip="10.0.0.60",
            dst_ip="10.0.0.1",
            dst_port=88,
            protocol=6,
            payload=tgs_payload,
        )
        self.engine.analyze_flow(flow1)

        flow2 = make_test_flow(
            src_ip="10.0.0.60",
            dst_ip="10.0.0.1",
            dst_port=88,
            protocol=6,
            payload=tgs_payload,
        )
        alerts = self.engine.analyze_flow(flow2)
        roast_alert = next((a for a in alerts if a.category == AlertCategory.IDENTITY_ATTACK and "Kerberoasting" in a.title), None)
        self.assertIsNotNone(roast_alert, "FALLO: Ataque Kerberoasting no detectado")
        self.assertEqual(roast_alert.src_ip, "10.0.0.60")

    def test_dcerpc_dcsync_detection(self):
        """Valida que una trama DCE-RPC Bind contra DRSUAPI dispare alerta crítica de DCSync."""
        drsuapi_uuid = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
        dcerpc_payload = build_raw_dcerpc_bind(drsuapi_uuid)

        flow = make_test_flow(
            src_ip="10.0.0.99",
            dst_ip="10.0.0.2",
            dst_port=445,
            protocol=6,
            payload=dcerpc_payload,
        )

        alerts = self.engine.analyze_flow(flow)
        dcsync_alert = next((a for a in alerts if a.category == AlertCategory.IDENTITY_ATTACK and "DCSync" in a.title), None)
        self.assertIsNotNone(dcsync_alert, "FALLO: Ataque DCSync (DRSUAPI) no detectado")
        self.assertEqual(dcsync_alert.severity, AlertSeverity.CRITICAL)

    def test_dcerpc_psexec_detection(self):
        """Valida que una conexión RPC hacia svcctl dispare alerta de movimiento lateral (PsExec)."""
        svcctl_uuid = "367abb81-9844-35f1-ad32-98f038001003"
        dcerpc_payload = build_raw_dcerpc_bind(svcctl_uuid)

        flow = make_test_flow(
            src_ip="10.0.0.99",
            dst_ip="10.0.0.3",
            dst_port=445,
            protocol=6,
            payload=dcerpc_payload,
        )

        alerts = self.engine.analyze_flow(flow)
        psexec_alert = next((a for a in alerts if a.category == AlertCategory.LATERAL_MOVEMENT and "svcctl" in a.title), None)
        self.assertIsNotNone(psexec_alert, "FALLO: Movimiento lateral PsExec (svcctl) no detectado")
        self.assertEqual(psexec_alert.severity, AlertSeverity.HIGH)

    def test_campaign_and_entity_ledger_auto_updates(self):
        """Verifica que las alertas L7 actualicen automáticamente el EntityLedger y el CampaignEngine."""
        drsuapi_uuid = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
        dcerpc_payload = build_raw_dcerpc_bind(drsuapi_uuid)

        flow = make_test_flow(
            src_ip="10.0.0.123",
            dst_ip="10.0.0.2",
            dst_port=445,
            protocol=6,
            payload=dcerpc_payload,
        )

        self.engine.analyze_flow(flow)

        # 1. Verificar Entity Ledger
        entity = self.engine.entity_ledger.lookup_by_ip("10.0.0.123")
        self.assertIsNotNone(entity, "La entidad 10.0.0.123 debió ser registrada en el EntityLedger")
        self.assertGreater(entity.current_threat_score, 0.0, "El Threat Score debió incrementarse por DCSync")

        # 2. Verificar Bayesian Campaign Engine
        cases = self.engine.campaign_engine.list_cases()
        self.assertGreater(len(cases), 0, "Una campaña multi-etapa debió ser creada o actualizada")
        self.assertIn("10.0.0.123", cases[0].involved_assets)


if __name__ == "__main__":
    unittest.main()
