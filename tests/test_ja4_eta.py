"""
Pruebas unitarias para la Fase 1: Extractor de Huellas Criptográficas JA4 / TLS ClientHello & ETA.
"""

import struct
import unittest

from collector.tls_parser import TLSClientHello, TLSParser
from detector.ja4 import JA4Fingerprint, SPLTProfile
from detector.ja4_database import KNOWN_MALICIOUS_JA4, JA4Database
from detector.models import AlertCategory, AlertSeverity
from detector.rules.ja4_threat import JA4ThreatDetector


def build_synthetic_client_hello(
    sni: str = "c2.adversary.org",
    alpn: str = "h2",
    ciphers: list = None,
    extensions: list = None,
    supported_versions: list = None,
    inject_grease: bool = True,
) -> bytes:
    """Construye un paquete binario TLS ClientHello sintético con estructura RFC 5246/8446."""
    ciphers = ciphers or [0x1301, 0x1302, 0xC02B, 0xC02F]
    extensions = extensions or [0x0000, 0x0010, 0x000A, 0x000D, 0x002B]
    supported_versions = supported_versions or [0x0304, 0x0303]

    if inject_grease:
        ciphers = [0x5A5A] + ciphers  # GREASE cipher
        extensions = [0x1A1A] + extensions  # GREASE extension

    # 1. Cuerpo del ClientHello
    body = bytearray()
    body.extend(struct.pack("!H", 0x0303))  # Client Version TLS 1.2
    body.extend(b"\x01" * 32)  # Random 32 bytes
    body.append(0)  # Session ID length 0

    # Ciphers
    cipher_bytes = bytearray()
    for c in ciphers:
        cipher_bytes.extend(struct.pack("!H", c))
    body.extend(struct.pack("!H", len(cipher_bytes)))
    body.extend(cipher_bytes)

    # Compression
    body.append(1)  # Length 1
    body.append(0)  # Null compression

    # Extensions block
    ext_block = bytearray()
    for ext_type in extensions:
        if ext_type == 0x0000:  # SNI
            sni_bytes = sni.encode("utf-8")
            # ServerNameList: len(2) -> name_type(1) -> len(2) -> name
            sn_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
            sni_ext_data = struct.pack("!H", len(sn_entry)) + sn_entry
            ext_block.extend(struct.pack("!HH", 0x0000, len(sni_ext_data)))
            ext_block.extend(sni_ext_data)
        elif ext_type == 0x0010:  # ALPN
            alpn_bytes = alpn.encode("utf-8")
            alpn_entry = bytes([len(alpn_bytes)]) + alpn_bytes
            alpn_ext_data = struct.pack("!H", len(alpn_entry)) + alpn_entry
            ext_block.extend(struct.pack("!HH", 0x0010, len(alpn_ext_data)))
            ext_block.extend(alpn_ext_data)
        elif ext_type == 0x002B:  # Supported Versions
            sv_bytes = bytearray()
            for sv in supported_versions:
                sv_bytes.extend(struct.pack("!H", sv))
            sv_data = bytes([len(sv_bytes)]) + sv_bytes
            ext_block.extend(struct.pack("!HH", 0x002B, len(sv_data)))
            ext_block.extend(sv_data)
        elif ext_type == 0x000A:  # Supported Groups
            sg_data = struct.pack("!HH", 2, 0x001D)  # x25519
            ext_block.extend(struct.pack("!HH", 0x000A, len(sg_data)))
            ext_block.extend(sg_data)
        elif ext_type == 0x000D:  # Signature Algorithms
            sa_data = struct.pack("!HH", 2, 0x0403)  # ecdsa_secp256r1_sha256
            ext_block.extend(struct.pack("!HH", 0x000D, len(sa_data)))
            ext_block.extend(sa_data)
        else:
            # Dummy extension
            ext_block.extend(struct.pack("!HH", ext_type, 2))
            ext_block.extend(b"\x00\x00")

    body.extend(struct.pack("!H", len(ext_block)))
    body.extend(ext_block)

    # 2. Handshake Header: Type (1 byte) + Length (3 bytes)
    handshake = bytearray()
    handshake.append(0x01)  # ClientHello
    handshake.extend(struct.pack("!I", len(body))[1:])  # 3 bytes length
    handshake.extend(body)

    # 3. TLS Record Header: Type (1 byte: 0x16) + Version (2 bytes: 0x0301) + Length (2 bytes)
    record = bytearray()
    record.append(0x16)  # Handshake record
    record.extend(struct.pack("!H", 0x0301))  # Record version
    record.extend(struct.pack("!H", len(handshake)))
    record.extend(handshake)

    return bytes(record)


class TestJA4AndETA(unittest.TestCase):
    """Batería de pruebas para validación de huellas JA4, JA3 y análisis SPLT."""

    def test_tls_parser_client_hello(self):
        """Verifica el análisis binario de ClientHello y la extracción de extensiones."""
        raw_data = build_synthetic_client_hello(
            sni="command-control.darknet.ru",
            alpn="h2",
            inject_grease=True,
        )
        hello = TLSParser.parse_client_hello(raw_data)
        self.assertIsNotNone(hello)
        self.assertEqual(hello.sni, "command-control.darknet.ru")
        self.assertEqual(hello.alpn, "h2")
        # El valor GREASE 0x5A5A en ciphers debe haber sido filtrado automáticamente
        self.assertNotIn(0x5A5A, hello.cipher_suites)
        # El valor GREASE 0x1A1A en extensions debe haber sido filtrado automáticamente
        self.assertNotIn(0x1A1A, hello.extensions)
        # La versión efectiva negociada debe ser TLS 1.3 (0x0304)
        self.assertEqual(hello.effective_version, 0x0304)

    def test_ja4_canonical_generation(self):
        """Valida que el generador JA4 produzca la estructura canónica [JA4_a]_[JA4_b]_[JA4_c]."""
        raw_data = build_synthetic_client_hello(
            sni="victim.portal.corp",
            alpn="h2",
        )
        hello = TLSParser.parse_client_hello(raw_data)
        ja4_fingerprint = JA4Fingerprint.calculate_ja4(hello, protocol="TCP")

        parts = ja4_fingerprint.split("_")
        self.assertEqual(len(parts), 3, "JA4 debe tener 3 componentes delimitados por guión bajo")
        self.assertEqual(len(parts[0]), 10, "JA4_a debe constar exactamente de 10 caracteres")
        self.assertEqual(len(parts[1]), 12, "JA4_b debe ser un hash truncado a 12 caracteres")
        self.assertEqual(len(parts[2]), 12, "JA4_c debe ser un hash truncado a 12 caracteres")

        # Comprobación de determinismo: misma entrada produce idéntico hash
        repeat_ja4 = JA4Fingerprint.calculate_ja4(hello, protocol="TCP")
        self.assertEqual(ja4_fingerprint, repeat_ja4)

    def test_ja3_retrocompatible_generation(self):
        """Verifica la generación de la huella MD5 JA3 estándar."""
        raw_data = build_synthetic_client_hello()
        hello = TLSParser.parse_client_hello(raw_data)
        ja3_hash, raw_ja3 = JA4Fingerprint.calculate_ja3(hello)

        self.assertEqual(len(ja3_hash), 32, "JA3 debe ser un digest MD5 de 32 caracteres hexadecimales")
        self.assertIn(",", raw_ja3)

    def test_ja4_database_and_matching(self):
        """Prueba la búsqueda y detección en base de datos de huellas maliciosas."""
        db = JA4Database()
        # Verificar huella conocida de Cobalt Strike
        cs_ja4 = "t13d1516h2_8daaf6152771_e562703ab855"
        meta = db.lookup_ja4(cs_ja4)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["family"], "Cobalt Strike C2")

        # Verificar huella inexistente
        unknown = db.lookup_ja4("t10i000000_000000000000_000000000000")
        self.assertIsNone(unknown)

        # Registro dinámico
        db.add_custom_threat(
            fingerprint="t13d9999h2_aabbccddeeff_112233445566",
            family="Custom Red Team Implant",
            tool="In-House Framework",
            severity="HIGH",
        )
        match = db.lookup_ja4("t13d9999h2_aabbccddeeff_112233445566")
        self.assertIsNotNone(match)
        self.assertEqual(match["family"], "Custom Red Team Implant")

    def test_splt_profile_beacon_detection(self):
        """Valida que SPLT capture ráfagas regulares características de balizamiento C2."""
        splt = SPLTProfile(max_packets=20)
        # Simular 10 paquetes de consulta de tamaño idéntico (210 bytes) y respuesta idéntica (350 bytes)
        t = 1000.0
        for _ in range(8):
            splt.add_packet(210, "CLIENT", t)
            t += 0.05
            splt.add_packet(350, "SERVER", t)
            t += 2.0  # Baliza cada 2 segundos

        self.assertTrue(splt.is_beacon_pattern(), "El patrón regular debe identificarse como beaconing")
        entropy = splt.calculate_entropy()
        self.assertGreater(entropy, 0.0)

    def test_ja4_threat_detector_rule(self):
        """Prueba que el detector emita una alerta de seguridad formal ante firmas maliciosas."""
        detector = JA4ThreatDetector()
        # Simular objeto TLSClientHello con huella idéntica a Cobalt Strike en la base de datos
        db = JA4Database()
        detector.db = db

        # Agregamos una firma de prueba que podamos generar con certeza
        test_hello = TLSClientHello(
            record_version=0x0301,
            client_version=0x0303,
            cipher_suites=[0xC02B, 0xC02F],
            extensions=[0x000A, 0x000D],
            sni="c2-apt29.ru",
            alpn="h2",
            supported_versions=[0x0304],
        )
        ja4_test = JA4Fingerprint.calculate_ja4(test_hello)
        db.add_custom_threat(
            fingerprint=ja4_test,
            family="APT29 Emulated",
            tool="Cobalt Strike HTTPS",
            severity="CRITICAL",
        )

        alert = detector.evaluate_tls_hello(
            test_hello,
            src_ip="10.0.50.40",
            dst_ip="194.165.16.89",
            dst_port=443,
        )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.MALICIOUS_C2)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.metrics["ja4"], ja4_test)
        self.assertEqual(alert.metrics["family"], "APT29 Emulated")


if __name__ == "__main__":
    unittest.main()
