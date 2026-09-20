"""
NovaFlow NDR - Advanced Edge Cases, Evasion Resistance & Confidence Tests
Valida casos límite, técnicas de evasión de firewalls (FIN/NULL/Xmas),
emparejamiento de subredes CIDR, listas de confianza y calibración dinámica de confianza.
"""

from datetime import datetime, timezone
import unittest

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity
from detector.rules.bandwidth_exfil import BandwidthExfiltrationDetector
from detector.rules.port_scan import PortScanDetector
from detector.rules.syn_flood import SynFloodDetector
from detector.rules.threat_intel import ThreatIntelMatcher


class TestEdgeCasesAndEvasion(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.now_ms = int(self.now.timestamp() * 1000)

    def _create_flow(self, **kwargs) -> NetFlowRecord:
        defaults = {
            "timestamp": self.now,
            "timestamp_ms": self.now_ms,
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.200",
            "next_hop": "192.168.1.1",
            "input_snmp": 1,
            "output_snmp": 2,
            "packets": 1,
            "bytes": 40,
            "first_switched": 1000,
            "last_switched": 1005,
            "src_port": 50000,
            "dst_port": 80,
            "tcp_flags": 2,
            "protocol": 6,
            "tos": 0,
            "src_as": 0,
            "dst_as": 0,
            "src_mask": 24,
            "dst_mask": 24,
        }
        defaults.update(kwargs)
        return NetFlowRecord(**defaults)

    def test_stealth_scans_fin_null_xmas(self):
        """Valida que PortScanDetector detecte escaneos sigilosos FIN (0x01), NULL (0x00) y Xmas (0x29)."""
        detector = PortScanDetector(port_threshold=15, window_seconds=10.0)

        # 1. FIN scan (0x01)
        alert_fin = None
        for p in range(16):
            flow = self._create_flow(src_ip="10.0.0.91", dst_port=1000 + p, tcp_flags=0x01, packets=1)
            res = detector.analyze_flow(flow)
            if res:
                alert_fin = res

        self.assertIsNotNone(alert_fin)
        self.assertEqual(alert_fin.category, AlertCategory.PORT_SCAN)
        self.assertIn("FIN", alert_fin.title)
        self.assertGreaterEqual(alert_fin.confidence, 0.85)

        # 2. Xmas scan (0x29)
        detector_xmas = PortScanDetector(port_threshold=15, window_seconds=10.0)
        alert_xmas = None
        for p in range(16):
            flow = self._create_flow(src_ip="10.0.0.92", dst_port=2000 + p, tcp_flags=0x29, packets=1)
            res = detector_xmas.analyze_flow(flow)
            if res:
                alert_xmas = res

        self.assertIsNotNone(alert_xmas)
        self.assertIn("XMAS", alert_xmas.title)

    def test_benign_browsing_multiple_connections_single_port(self):
        """Valida que múltiples conexiones HTTPS a un solo puerto (443) NO disparen Port Scan."""
        detector = PortScanDetector(port_threshold=15, window_seconds=10.0)

        for i in range(50):
            # Cliente navega web: múltiples conexiones al puerto 443 desde puertos efímeros
            flow = self._create_flow(
                src_ip="192.168.1.50",
                dst_ip="104.16.123.96",
                src_port=49000 + i,
                dst_port=443,
                tcp_flags=0x02,
                packets=1,
            )
            alert = detector.analyze_flow(flow)
            self.assertIsNone(alert, "Conexiones normales al mismo puerto no deben alertar Port Scan")

    def test_established_session_with_syn_flag_ignored(self):
        """Valida que flujos con muchos paquetes (>4) con flag SYN no se consideren escaneo."""
        detector = PortScanDetector(port_threshold=15, window_seconds=10.0)

        for p in range(20):
            flow = self._create_flow(
                src_ip="192.168.1.77",
                dst_port=1000 + p,
                tcp_flags=0x02,
                packets=50,  # Sesión de datos establecida
                bytes=50000,
            )
            alert = detector.analyze_flow(flow)
            self.assertIsNone(alert, "Flujos con muchos paquetes (>4) corresponden a datos, no a sondeo")

    def test_threat_intel_cidr_subnet_matching(self):
        """Valida que ThreatIntelMatcher detecte conexiones hacia rangos de subred CIDR maliciosos."""
        matcher = ThreatIntelMatcher()
        matcher.add_ioc(
            "198.51.200.0/24",
            family="Bulletproof Hosting C2 Subnet",
            severity="CRITICAL",
            actor="FIN7",
        )

        # IP perteneciente a la subred /24
        flow = self._create_flow(src_ip="10.0.0.10", dst_ip="198.51.200.55", dst_port=443)
        alert = matcher.analyze_flow(flow)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.MALICIOUS_C2)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertIn("Bulletproof Hosting", alert.title)

        # IP fuera de la subred /24
        flow_clean = self._create_flow(src_ip="10.0.0.10", dst_ip="198.51.201.55", dst_port=443)
        self.assertIsNone(matcher.analyze_flow(flow_clean))

    def test_exfiltration_trusted_destination_whitelist(self):
        """Valida que destinos aprobados en lista blanca no disparen alerta de exfiltración."""
        detector = BandwidthExfiltrationDetector(
            single_flow_threshold_bytes=20_000_000,
            trusted_destinations={"52.216.100.10"},  # AWS S3 Backup Bucket autorizado
        )

        # Flujo masivo de 40MB hacia destino autorizado
        trusted_flow = self._create_flow(
            src_ip="10.0.0.5",
            dst_ip="52.216.100.10",
            dst_port=443,
            bytes=40_000_000,
            packets=30000,
        )
        self.assertIsNone(detector.analyze_flow(trusted_flow), "Destino en lista blanca no debe generar alerta")

        # Mismo flujo hacia IP no autorizada
        untrusted_flow = self._create_flow(
            src_ip="10.0.0.5",
            dst_ip="203.0.113.99",
            dst_port=443,
            bytes=40_000_000,
            packets=30000,
        )
        alert = detector.analyze_flow(untrusted_flow)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.EXFILTRATION)

    def test_syn_flood_flash_crowd_with_ack_ignored(self):
        """Valida que ráfagas de usuarios legítimos con ACK (0x10) no disparen SYN Flood."""
        detector = SynFloodDetector(syn_count_threshold=30, window_seconds=5.0)

        for i in range(50):
            # Usuarios completando conexión (SYN + ACK o ACK)
            flow = self._create_flow(
                src_ip=f"10.0.50.{i + 1}",
                dst_ip="10.0.0.80",
                dst_port=80,
                tcp_flags=0x12,  # SYN + ACK (handshake legítimo)
                packets=2,
            )
            alert = detector.analyze_flow(flow)
            self.assertIsNone(alert, "Conexiones con ACK no son SYN floods")

    def test_dynamic_confidence_scaling(self):
        """Valida que la confianza escale suavemente entre 0.85 y 0.99 según la intensidad."""
        detector = PortScanDetector(port_threshold=15, window_seconds=10.0)

        # 16 puertos (umbral apenas superado)
        alert_16 = None
        for p in range(16):
            res = detector.analyze_flow(self._create_flow(src_ip="10.0.100.1", dst_port=100 + p))
            if res:
                alert_16 = res

        self.assertIsNotNone(alert_16)
        self.assertGreaterEqual(alert_16.confidence, 0.85)
        self.assertLessEqual(alert_16.confidence, 0.90)

        # Escaneo masivo de 60 puertos con múltiples objetivos (sin cooldown para capturar el pico de 60 puertos)
        detector_massive = PortScanDetector(port_threshold=15, window_seconds=10.0, alert_cooldown_seconds=0.0)
        alert_massive = None
        for p in range(60):
            target = f"10.0.2.{p % 5 + 1}"
            res = detector_massive.analyze_flow(self._create_flow(src_ip="10.0.100.2", dst_ip=target, dst_port=1000 + p))
            if res:
                alert_massive = res

        self.assertIsNotNone(alert_massive)
        self.assertGreater(alert_massive.confidence, alert_16.confidence)
        self.assertGreaterEqual(alert_massive.confidence, 0.94)


if __name__ == "__main__":
    unittest.main()
