"""
Pruebas unitarias para el Pilar 2: Inspección L7 de Protocolos de Identidad (Kerberos y DCE-RPC/SMB).
"""

import struct
import unittest
import uuid

from collector.l7_parsers import (
    ASN1Reader,
    DCERPCMessage,
    DCERPCParser,
    KerberosMessage,
    KerberosParser,
    KNOWN_RPC_INTERFACES,
)
from detector.models import AlertCategory, AlertSeverity
from detector.rules.ad_threat import ActiveDirectoryThreatDetector


def build_synthetic_as_req(include_preauth: bool = True) -> bytes:
    """Construye un mensaje Kerberos AS-REQ sintético (Application 10 / 0x6A)."""
    body = bytearray()
    if include_preauth:
        # padata-type: 2 (PA-ENC-TIMESTAMP)
        body.extend(b"\x02\x01\x02\x04\x08dummyenc")
    else:
        # Sin pre-autenticación
        body.extend(b"\x02\x01\x80\x04\x00")

    # etypes
    body.extend(b"\x02\x01\x12")  # AES256

    # TLV: Tag 0x6A (AS-REQ), Length
    req = bytearray([0x6A, len(body)])
    req.extend(body)
    return bytes(req)


def build_synthetic_tgs_req_rc4(spn: str = "MSSQLSvc") -> bytes:
    """Construye un mensaje Kerberos TGS-REQ sintético solicitando cifrado débil RC4."""
    body = bytearray()
    # etype 0x17 (RC4-HMAC)
    body.extend(b"\x02\x01\x17")
    # SPN
    body.extend(spn.encode("utf-8"))

    req = bytearray([0x6C, len(body)])  # 0x6C = Application 12 (TGS-REQ)
    req.extend(body)
    return bytes(req)


def build_synthetic_dcerpc_bind(interface_uuid_str: str) -> bytes:
    """Construye una cabecera MSRPC Bind sintética versión 5.0."""
    header = bytearray(16)
    header[0] = 5   # rpc_vers 5
    header[1] = 0   # rpc_vers_minor 0
    header[2] = 11  # ptype BIND
    header[3] = 3   # pfc_flags (first_frag | last_frag)
    # drep little-endian (0x10)
    header[4] = 0x10

    # Payload con UUID de interfaz en little-endian
    guid_bytes = uuid.UUID(interface_uuid_str).bytes_le
    body = bytearray(28)
    body.extend(guid_bytes)
    body.extend(b"\x01\x00\x00\x00")  # interface version 1.0

    tot_len = len(header) + len(body)
    header[8:10] = struct.pack("<H", tot_len)
    header[12:16] = struct.pack("<I", 1)  # call_id

    return bytes(header + body)


class TestActiveDirectoryL7(unittest.TestCase):
    """Batería de validación de parsers L7 y detección de ataques de identidad."""

    def test_asn1_reader_tlv(self):
        """Valida que el lector ASN.1 DER decodifique elementos TLV con longitudes variables."""
        # Tag 0x02 (INTEGER), Len 0x01, Val 0x17
        data = b"\x02\x01\x17"
        reader = ASN1Reader(data)
        tlv = reader.read_tlv()
        self.assertIsNotNone(tlv)
        tag, val = tlv
        self.assertEqual(tag, 0x02)
        self.assertEqual(val, b"\x17")

    def test_kerberos_parser_and_asrep_roasting(self):
        """Verifica la detección de solicitudes AS-REQ sin preautenticación (AS-REP Roasting)."""
        detector = ActiveDirectoryThreatDetector()

        # 1. AS-REQ legítimo con preautenticación
        pkt_legit = build_synthetic_as_req(include_preauth=True)
        msg_legit = KerberosParser.parse_payload(pkt_legit)
        self.assertIsNotNone(msg_legit)
        self.assertTrue(msg_legit.has_preauth)
        alert_legit = detector.evaluate_kerberos(msg_legit, "10.0.0.10", "10.0.0.2")
        self.assertIsNone(alert_legit)

        # 2. AS-REQ hostil sin preautenticación
        pkt_roast = build_synthetic_as_req(include_preauth=False)
        msg_roast = KerberosParser.parse_payload(pkt_roast)
        self.assertIsNotNone(msg_roast)
        self.assertFalse(msg_roast.has_preauth)
        alert_roast = detector.evaluate_kerberos(msg_roast, "10.0.0.99", "10.0.0.2")
        self.assertIsNotNone(alert_roast)
        self.assertEqual(alert_roast.category, AlertCategory.IDENTITY_ATTACK)
        self.assertEqual(alert_roast.severity, AlertSeverity.HIGH)
        self.assertIn("AS-REP Roasting", alert_roast.title)

    def test_kerberos_parser_and_kerberoasting(self):
        """Valida la detección de solicitudes TGS pidiendo cifrado débil RC4 (Kerberoasting)."""
        detector = ActiveDirectoryThreatDetector()

        pkt_tgs = build_synthetic_tgs_req_rc4(spn="MSSQLSvc/sql01.corp:1433")
        msg_tgs = KerberosParser.parse_payload(pkt_tgs)
        self.assertIsNotNone(msg_tgs)
        self.assertTrue(msg_tgs.is_rc4_requested)
        self.assertIn("MSSQLSvc", msg_tgs.sname)

        alert = detector.evaluate_kerberos(msg_tgs, "10.0.50.40", "10.0.0.2")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.IDENTITY_ATTACK)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertIn("Kerberoasting", alert.title)

    def test_dcerpc_dcsync_drsuapi_detection(self):
        """Verifica la decodificación de interfaz DRSUAPI y alerta de replicación DCSync."""
        detector = ActiveDirectoryThreatDetector()
        drsuapi_uuid = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"

        raw_bind = build_synthetic_dcerpc_bind(drsuapi_uuid)
        rpc_msg = DCERPCParser.parse_payload(raw_bind)
        self.assertIsNotNone(rpc_msg)
        self.assertEqual(rpc_msg.interface_name, "drsuapi")
        self.assertEqual(rpc_msg.risk_level, "CRITICAL")

        alert = detector.evaluate_dcerpc(rpc_msg, src_ip="10.0.50.99", target_ip="10.0.0.2", port=445)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.IDENTITY_ATTACK)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertIn("DCSync", alert.title)

    def test_dcerpc_psexec_svcctl_detection(self):
        """Verifica la detección de ejecución remota de servicios (PsExec / svcctl)."""
        detector = ActiveDirectoryThreatDetector()
        svcctl_uuid = "367abb81-9844-35f1-ad32-98f038001003"

        raw_bind = build_synthetic_dcerpc_bind(svcctl_uuid)
        rpc_msg = DCERPCParser.parse_payload(raw_bind)
        self.assertIsNotNone(rpc_msg)
        self.assertEqual(rpc_msg.interface_name, "svcctl")

        alert = detector.evaluate_dcerpc(rpc_msg, src_ip="10.0.50.99", target_ip="10.0.0.20", port=445)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.LATERAL_MOVEMENT)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertIn("PsExec/svcctl", alert.title)


if __name__ == "__main__":
    unittest.main()
