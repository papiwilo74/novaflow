"""
NovaFlow NDR - Automated Tests for Encrypted Traffic Analysis (ETA) & SPLT Profiler
Valida el perfilado SPLT en flujos TLS/HTTPS sin descifrado, detectando balizas C2 y exfiltración cifrada.
"""

from datetime import datetime, timezone, timedelta
import unittest

from collector.parser import NetFlowRecord
from detector.biflow import BiFlowStitcher
from detector.engine import DetectionEngine
from detector.eta import EncryptedTrafficAnalyzer
from detector.models import AlertCategory, AlertSeverity


class TestEncryptedTrafficAnalysis(unittest.TestCase):
    def setUp(self):
        self.stitcher = BiFlowStitcher()
        self.analyzer = EncryptedTrafficAnalyzer(biflow_stitcher=self.stitcher)
        self.now = datetime.now(timezone.utc)

    def _make_flow(
        self,
        src: str,
        dst: str,
        src_port: int,
        dst_port: int,
        bytes_count: int,
        packets_count: int,
        delta_sec: int = 0,
    ) -> NetFlowRecord:
        ts = self.now + timedelta(seconds=delta_sec)
        return NetFlowRecord(
            timestamp=ts,
            timestamp_ms=int(ts.timestamp() * 1000),
            src_ip=src,
            dst_ip=dst,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=packets_count,
            bytes=bytes_count,
            first_switched=1000,
            last_switched=2000,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=0x18,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def test_benign_https_browsing_discarded(self):
        """Valida que la navegación HTTPS web legítima no genere alertas de canal anómalo."""
        # Usuario navegando sitio web benigno: pocos paquetes pequeños de subida
        f = self._make_flow(
            src="10.0.1.15",
            dst="142.250.190.46",  # Google
            src_port=51200,
            dst_port=443,
            bytes_count=1200,
            packets_count=3,
        )
        alert = self.analyzer.analyze_flow(f)
        self.assertIsNone(alert)

    def test_encrypted_exfiltration_tunnel_detected(self):
        """Valida la detección de exfiltración masiva sobre TLS (SPLT saturando MTU ~1200+ bytes/pkt)."""
        # Flujo saliente: 8.5 MB en 6,500 paquetes hacia IP externa en puerto 443 (promedio 1369 bytes/pkt)
        f_out = self._make_flow(
            src="10.0.1.50",
            dst="198.51.100.99",
            src_port=54321,
            dst_port=443,
            bytes_count=8_900_000,
            packets_count=6_500,
        )
        self.stitcher.ingest_flow(f_out)
        alert = self.analyzer.analyze_flow(f_out)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.ANOMALOUS_TLS)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.metrics["technique"], "SPLT_ENCRYPTED_EXFILTRATION")
        self.assertGreaterEqual(alert.metrics["avg_packet_size"], 1150)
        self.assertEqual(alert.mitre["technique_id"], "T1573")

    def test_encrypted_c2_stealth_beaconing_detected(self):
        """Valida la detección de balizas C2 cifradas (SPLT periódico con paquetes pequeños uniformes)."""
        # Simular 4 ráfagas periódicas de baliza HTTPS (Cobalt Strike malleable C2)
        # 15 paquetes, 3600 bytes por flujo (promedio 240 bytes/pkt)
        alerts = []
        for i in range(4):
            f = self._make_flow(
                src="10.0.1.80",
                dst="198.51.100.40",
                src_port=49800 + i,
                dst_port=443,
                bytes_count=3600,
                packets_count=15,
                delta_sec=i * 30,
            )
            a = self.analyzer.analyze_flow(f)
            if a:
                alerts.append(a)

        # Debe generar alerta al detectar las ráfagas consistentes (a partir del 3er o 4to flujo)
        self.assertGreaterEqual(len(alerts), 1)
        alert = alerts[-1]
        self.assertEqual(alert.category, AlertCategory.ANOMALOUS_TLS)
        self.assertEqual(alert.metrics["technique"], "SPLT_ENCRYPTED_C2_BEACON")
        self.assertIn("T1573", alert.mitre["technique_id"])

    def test_detection_engine_eta_integration(self):
        """Valida la integración completa del analizador ETA dentro del DetectionEngine."""
        engine = DetectionEngine()

        # Flujo de exfiltración masiva cifrada
        f_exfil = self._make_flow(
            src="10.0.2.10",
            dst="203.0.113.111",
            src_port=58000,
            dst_port=443,
            bytes_count=7_000_000,
            packets_count=5_500,
        )
        emitted = engine.analyze_flow(f_exfil)

        categories = [a.category for a in emitted]
        self.assertIn(AlertCategory.ANOMALOUS_TLS, categories)


if __name__ == "__main__":
    unittest.main()
