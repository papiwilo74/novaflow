"""
NovaFlow NDR - BiFlow & Session Stitching Engine Tests
Verifica el ensamblado bidireccional L4, ratios de subida/bajada y supresión de falsos positivos.
"""

import unittest
from datetime import datetime, timezone

from collector.parser import NetFlowRecord
from detector.biflow import BiFlowSession, BiFlowStitcher
from detector.rules.bandwidth_exfil import BandwidthExfiltrationDetector
from detector.engine import DetectionEngine


def make_test_flow(
    src_ip="192.168.1.100",
    dst_ip="203.0.113.50",
    src_port=52344,
    dst_port=443,
    protocol=6,
    tcp_flags=0x18,
    packets=50,
    bytes_count=50000,
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
        bytes=bytes_count,
        first_switched=1000,
        last_switched=2000,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        protocol=protocol,
        tos=0,
        src_as=65000,
        dst_as=13335,
        src_mask=24,
        dst_mask=24,
    )


class TestBiFlowStitcher(unittest.TestCase):
    """Pruebas unitarias para el ensamblado de sesiones Bi-Flow L4."""

    def setUp(self):
        self.stitcher = BiFlowStitcher(session_timeout_seconds=30.0)

    def test_canonical_key_symmetry(self):
        """Verifica que A->B y B->A generen la misma clave canónica."""
        key1 = self.stitcher._make_canonical_key("10.0.0.1", "203.0.113.1", 50000, 443, 6)
        key2 = self.stitcher._make_canonical_key("203.0.113.1", "10.0.0.1", 443, 50000, 6)
        self.assertEqual(key1, key2)

    def test_session_stitching_forward_and_reverse(self):
        """Verifica que el flujo de ida y el de vuelta se fusionen en la misma BiFlowSession."""
        # 1. Flujo Forward: Cliente solicita descarga HTTP
        fwd = make_test_flow(
            src_ip="10.1.1.5",
            dst_ip="198.51.100.10",
            src_port=49152,
            dst_port=80,
            tcp_flags=0x02,  # SYN
            packets=5,
            bytes_count=300,
        )
        session = self.stitcher.ingest_flow(fwd)
        self.assertEqual(session.client_ip, "10.1.1.5")
        self.assertEqual(session.server_ip, "198.51.100.10")
        self.assertEqual(session.bytes_sent, 300)
        self.assertEqual(session.bytes_received, 0)
        self.assertEqual(session.handshake_status, "UNANSWERED")

        # 2. Flujo Reverse: Servidor responde con contenido
        rev = make_test_flow(
            src_ip="198.51.100.10",
            dst_ip="10.1.1.5",
            src_port=80,
            dst_port=49152,
            tcp_flags=0x12,  # SYN-ACK
            packets=1000,
            bytes_count=1_450_000,
        )
        updated = self.stitcher.ingest_flow(rev)
        self.assertIs(updated, session)
        self.assertEqual(updated.bytes_sent, 300)
        self.assertEqual(updated.bytes_received, 1_450_000)
        self.assertEqual(updated.handshake_status, "ESTABLISHED")
        # Ratio: 300 / 1450000 = 0.0002 < 0.2 (Descarga pura)
        self.assertLess(updated.bytes_ratio, 0.01)

    def test_asymmetric_upload_exfiltration_ratio(self):
        """Verifica que una exfiltración masiva de datos tenga un ratio superior a 20.0."""
        # Cliente sube 30 MB al servidor C2, el servidor solo devuelve 50 KB en ACKs
        fwd = make_test_flow(
            src_ip="10.0.0.99",
            dst_ip="203.0.113.88",
            src_port=60000,
            dst_port=8443,
            tcp_flags=0x18,
            packets=25000,
            bytes_count=30_000_000,
        )
        rev = make_test_flow(
            src_ip="203.0.113.88",
            dst_ip="10.0.0.99",
            src_port=8443,
            dst_port=60000,
            tcp_flags=0x10,
            packets=1000,
            bytes_count=50_000,
        )
        self.stitcher.ingest_flow(fwd)
        session = self.stitcher.ingest_flow(rev)
        # Ratio: 30,000,000 / 50,000 = 600.0 >> 20.0
        self.assertGreater(session.bytes_ratio, 20.0)
        self.assertEqual(session.bytes_ratio, 600.0)

    def test_tcp_reset_handshake_state(self):
        """Verifica que una conexión abortada por RST sea marcada como RESET."""
        fwd = make_test_flow(
            src_ip="10.0.0.5",
            dst_ip="198.51.100.20",
            src_port=50000,
            dst_port=22,
            tcp_flags=0x02,  # SYN
            packets=1,
            bytes_count=60,
        )
        rev = make_test_flow(
            src_ip="198.51.100.20",
            dst_ip="10.0.0.5",
            src_port=22,
            dst_port=50000,
            tcp_flags=0x04,  # RST
            packets=1,
            bytes_count=40,
        )
        self.stitcher.ingest_flow(fwd)
        session = self.stitcher.ingest_flow(rev)
        self.assertEqual(session.handshake_status, "RESET")

    def test_false_positive_elimination_in_bandwidth_exfil(self):
        """
        Demuestra la eliminación de falsos positivos:
        Una descarga de 60 MB normalmente alertaría por acumulación volumétrica.
        Con BiFlowStitcher, ratio < 0.2 suprime la alerta.
        """
        stitcher = BiFlowStitcher()
        detector = BandwidthExfiltrationDetector(
            single_flow_threshold_bytes=20_000_000,
            window_threshold_bytes=50_000_000,
            biflow_stitcher=stitcher,
        )

        client_ip = "192.168.1.50"
        server_ip = "104.244.42.1"  # Twitter / CDN

        # 1. Ingestar flujo entrante masivo de descarga (60 MB) en stitcher
        download_flow = make_test_flow(
            src_ip=server_ip,
            dst_ip=client_ip,
            src_port=443,
            dst_port=54321,
            packets=45000,
            bytes_count=60_000_000,
        )
        stitcher.ingest_flow(download_flow)

        # 2. Flujo saliente de ACKs del cliente (apenas 25 MB en tráfico total acumulado)
        client_acks = make_test_flow(
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=54321,
            dst_port=443,
            packets=20000,
            bytes_count=21_000_000,  # Superaría el umbral de 20 MB si no hubiera BiFlow
        )
        stitcher.ingest_flow(client_acks)

        # 3. El detector analiza el flujo saliente
        # bytes_ratio = 21,000,000 / 60,000,000 = 0.35 -> ratio no exfiltrativo
        # Para que sea suprimido ratio < 0.2:
        # Probemos con 5 MB subidos vs 60 MB descargados:
        session = stitcher.get_session(client_ip, server_ip, 54321, 443, 6)
        self.assertIsNotNone(session)

        # Caso legítimo claro: 1 MB subido vs 50 MB bajados
        stitcher_clean = BiFlowStitcher()
        detector_clean = BandwidthExfiltrationDetector(
            single_flow_threshold_bytes=20_000_000,
            window_threshold_bytes=30_000_000,
            biflow_stitcher=stitcher_clean,
        )
        # Registrar bajada en el stitcher
        stitcher_clean.ingest_flow(make_test_flow(
            src_ip=server_ip, dst_ip=client_ip, src_port=443, dst_port=51111,
            packets=100000, bytes_count=100_000_000
        ))
        # Registrar subida en el stitcher (22 MB acumulados, pero con ratio 22/100 = 0.22, ajustemos a 10 MB para < 0.2)
        stitcher_clean.ingest_flow(make_test_flow(
            src_ip=client_ip, dst_ip=server_ip, src_port=51111, dst_port=443,
            packets=5000, bytes_count=15_000_000
        ))
        # Ratio = 15/100 = 0.15 < 0.2
        session_clean = stitcher_clean.get_session(client_ip, server_ip, 51111, 443, 6)
        self.assertLess(session_clean.bytes_ratio, 0.2)

        # Al analizar un flujo saliente que llevaría el acumulado a superar el umbral:
        outgoing_flow = make_test_flow(
            src_ip=client_ip, dst_ip=server_ip, src_port=51111, dst_port=443,
            packets=6000, bytes_count=21_000_000
        )
        # Con 21 MB subidos vs 200 MB descargados
        stitcher_clean.ingest_flow(make_test_flow(
            src_ip=server_ip, dst_ip=client_ip, src_port=443, dst_port=51111,
            packets=150000, bytes_count=200_000_000
        ))
        stitcher_clean.ingest_flow(outgoing_flow)
        alert = detector_clean.analyze_flow(outgoing_flow)
        # La alerta DEBE ser suprimida (None) gracias al BiFlow stitcher
        self.assertIsNone(alert)

    def test_engine_integration_with_biflow(self):
        """Verifica que DetectionEngine ingeste flujos en su BiFlowStitcher interno automáticamente."""
        engine = DetectionEngine()
        flow_a = make_test_flow(src_ip="192.168.1.20", dst_ip="93.184.216.34", src_port=40000, dst_port=80, bytes_count=500)
        flow_b = make_test_flow(src_ip="93.184.216.34", dst_ip="192.168.1.20", src_port=80, dst_port=40000, bytes_count=2000)

        engine.analyze_flow(flow_a)
        engine.analyze_flow(flow_b)

        session = engine.biflow_stitcher.get_session("192.168.1.20", "93.184.216.34", 40000, 80, 6)
        self.assertIsNotNone(session)
        self.assertEqual(session.bytes_sent, 500)
        self.assertEqual(session.bytes_received, 2000)


if __name__ == "__main__":
    unittest.main()
