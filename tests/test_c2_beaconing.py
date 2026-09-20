"""
Tests unitarios para el motor de detección de balizamiento C2 por jitter y variación temporal.
"""

import unittest
from datetime import datetime, timezone

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity
from detector.rules.c2_beaconing import C2BeaconingDetector


class TestC2BeaconingDetector(unittest.TestCase):
    def setUp(self):
        self.detector = C2BeaconingDetector(
            cv_threshold=0.35,
            min_samples=5,
            min_interval_sec=2.0,
            max_interval_sec=120.0,
            window_seconds=600.0,
            alert_cooldown_seconds=10.0,
        )

    def _create_flow(self, src_ip: str, dst_ip: str, dst_port: int, ts_epoch: float, bytes_val: int = 150) -> NetFlowRecord:
        dt = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)
        return NetFlowRecord(
            timestamp=dt,
            timestamp_ms=int(ts_epoch * 1000),
            src_ip=src_ip,
            dst_ip=dst_ip,
            next_hop="0.0.0.0",
            input_snmp=1,
            output_snmp=2,
            packets=2,
            bytes=bytes_val,
            first_switched=1000,
            last_switched=1010,
            src_port=49152,
            dst_port=dst_port,
            tcp_flags=24,  # PSH, ACK
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def test_c2_beaconing_detected_with_jitter(self):
        """Valida que conexiones con intervalo medio regular y 10% de jitter disparen alerta C2."""
        base_time = 1700000000.0
        # Intervalos regulares de ~10 segundos con pequeño jitter: [10.2, 9.8, 10.1, 9.9, 10.3]
        offsets = [0.0, 10.2, 20.0, 30.1, 40.0, 50.3]
        alert = None

        for off in offsets:
            flow = self._create_flow("10.0.0.15", "198.51.100.99", 443, base_time + off)
            res = self.detector.analyze_flow(flow)
            if res:
                alert = res

        self.assertIsNotNone(alert, "Debe detectar balizamiento periódico con bajo CV")
        self.assertEqual(alert.category, AlertCategory.C2_BEACONING)
        self.assertIn(alert.severity, (AlertSeverity.HIGH, AlertSeverity.CRITICAL))
        self.assertGreaterEqual(alert.confidence, 0.85)
        self.assertLessEqual(alert.metrics["coefficient_of_variation"], 0.35)
        self.assertAlmostEqual(alert.metrics["beacon_interval_seconds"], 10.0, delta=1.0)
        self.assertIn("198.51.100.99:443", alert.title)

    def test_benign_random_traffic_ignored(self):
        """Valida que tráfico humano/web con alta dispersión temporal (CV > 1.0) NO dispare alerta."""
        base_time = 1700000000.0
        # Intervalos caóticos de navegación: [0.2s, 45s, 1.1s, 80s, 0.5s]
        offsets = [0.0, 0.2, 45.2, 46.3, 126.3, 126.8]
        alert = None

        for off in offsets:
            flow = self._create_flow("10.0.0.20", "142.250.190.46", 443, base_time + off)
            res = self.detector.analyze_flow(flow)
            if res:
                alert = res

        self.assertIsNone(alert, "El tráfico benigno irregular no debe activar alerta C2")

    def test_bulk_transfer_ignored(self):
        """Valida que flujos con transferencia masiva de datos sean descartados para balizamiento."""
        base_time = 1700000000.0
        offsets = [0.0, 10.0, 20.0, 30.0, 40.0, 50.0]
        alert = None

        for off in offsets:
            flow = self._create_flow("10.0.0.25", "198.51.100.5", 443, base_time + off, bytes_val=2_000_000)
            res = self.detector.analyze_flow(flow)
            if res:
                alert = res

        self.assertIsNone(alert, "Descargas grandes no deben ser tratadas como balizas de comando")


if __name__ == "__main__":
    unittest.main()
