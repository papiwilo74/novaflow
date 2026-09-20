"""
NovaFlow NDR - Lateral Movement & Internal Pivoting Detection Tests (T1021)
Valida la detección de propagación horizontal en puertos administrativos, playbooks SOAR y Kill Chain.
"""

import unittest
from datetime import datetime, timezone

from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.playbooks import MitigationPlaybookGenerator
from detector.rules.lateral_movement import LateralMovementDetector


def make_test_flow(
    src_ip="10.0.0.50",
    dst_ip="10.0.0.100",
    src_port=49500,
    dst_port=445,
    protocol=6,
    tcp_flags=0x18,
    packets=10,
    bytes_count=2500,
) -> NetFlowRecord:
    return NetFlowRecord(
        timestamp=datetime.now(timezone.utc),
        timestamp_ms=0,
        src_ip=src_ip,
        dst_ip=dst_ip,
        next_hop="10.0.0.1",
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
        dst_as=65000,
        src_mask=24,
        dst_mask=24,
    )


class TestLateralMovementDetector(unittest.TestCase):
    """Pruebas unitarias para la heurística de movimiento lateral L4."""

    def setUp(self):
        self.detector = LateralMovementDetector(
            target_threshold=3,
            window_seconds=30.0,
            alert_cooldown_seconds=45.0,
        )

    def test_smb_fanout_detection(self):
        """Detección de propagación masiva en SMB (puerto 445) contra >= 3 hosts internos."""
        src_attacker = "192.168.1.75"

        # Flujo 1: hacia 192.168.1.10
        f1 = make_test_flow(src_ip=src_attacker, dst_ip="192.168.1.10", dst_port=445)
        self.assertIsNone(self.detector.analyze_flow(f1))

        # Flujo 2: hacia 192.168.1.11
        f2 = make_test_flow(src_ip=src_attacker, dst_ip="192.168.1.11", dst_port=445)
        self.assertIsNone(self.detector.analyze_flow(f2))

        # Flujo 3: hacia 192.168.1.12 (cruza el umbral de 3 destinos)
        f3 = make_test_flow(src_ip=src_attacker, dst_ip="192.168.1.12", dst_port=445)
        alert = self.detector.analyze_flow(f3)

        self.assertIsNotNone(alert, "Debe alertar cuando un host interno contacta a 3 hosts en SMB")
        self.assertEqual(alert.category, AlertCategory.LATERAL_MOVEMENT)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.src_ip, src_attacker)
        self.assertEqual(alert.dst_port, 445)
        self.assertGreaterEqual(alert.confidence, 0.88)
        self.assertEqual(alert.metrics["unique_targets_count"], 3)
        self.assertIn("192.168.1.10", alert.metrics["targets"])
        self.assertIn("192.168.1.11", alert.metrics["targets"])
        self.assertIn("192.168.1.12", alert.metrics["targets"])

    def test_critical_severity_on_multi_protocol_or_high_fanout(self):
        """Escalación a CRITICAL si involucra múltiples protocolos (SMB+RDP) o >= 6 hosts."""
        src = "10.10.10.5"

        # Tocar 6 hosts diferentes en RDP (3389) y SMB (445)
        targets = [f"10.10.10.{i}" for i in range(20, 27)]
        alert = None
        for i, t in enumerate(targets):
            port = 445 if i % 2 == 0 else 3389
            f = make_test_flow(src_ip=src, dst_ip=t, dst_port=port)
            res = self.detector.analyze_flow(f)
            if res:
                alert = res

        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)

    def test_ignores_non_admin_ports(self):
        """No debe alertar si el tráfico interno es hacia puertos benignos estándar (80, 443, 8080)."""
        src = "10.0.0.10"
        for i in range(1, 10):
            f = make_test_flow(src_ip=src, dst_ip=f"10.0.0.{i}", dst_port=80)
            self.assertIsNone(self.detector.analyze_flow(f))

    def test_ignores_external_traffic(self):
        """No debe alertar si el origen o destino es una IP pública de Internet."""
        f_ext = make_test_flow(src_ip="10.0.0.10", dst_ip="8.8.8.8", dst_port=445)
        self.assertIsNone(self.detector.analyze_flow(f_ext))

        f_ext2 = make_test_flow(src_ip="198.51.100.20", dst_ip="10.0.0.10", dst_port=445)
        self.assertIsNone(self.detector.analyze_flow(f_ext2))

    def test_whitelisted_source_suppressed(self):
        """Un bastion o escáner autorizado en lista blanca no debe disparar alerta."""
        self.detector.add_whitelist_source("10.0.0.254")
        for i in range(1, 6):
            f = make_test_flow(src_ip="10.0.0.254", dst_ip=f"10.0.0.{i}", dst_port=445)
            self.assertIsNone(self.detector.analyze_flow(f))

    def test_playbook_generation_for_lateral_movement(self):
        """Valida que los playbooks SOAR generen comandos de aislamiento host quarantine para LATERAL_MOVEMENT."""
        alert = SecurityAlert(
            category=AlertCategory.LATERAL_MOVEMENT,
            severity=AlertSeverity.HIGH,
            title="Movimiento Lateral L4 Detectado",
            src_ip="192.168.50.33",
            dst_ip="192.168.50.99",
            dst_port=445,
            confidence=0.92,
        )

        playbook = MitigationPlaybookGenerator.generate_playbook(alert)
        self.assertEqual(playbook.target_ip_to_block, "192.168.50.33")
        self.assertEqual(playbook.estimated_impact, "HIGH")
        self.assertIn("CUARENTENA", playbook.recommended_action)
        self.assertTrue(any("iptables" in r.platform.lower() for r in playbook.rules))
        self.assertTrue(any("192.168.50.33" in r.block_command for r in playbook.rules))

    def test_detection_engine_lateral_movement_integration(self):
        """Valida que DetectionEngine ejecute LateralMovementDetector en su pipeline unificado."""
        engine = DetectionEngine()
        src = "10.0.1.100"

        f1 = make_test_flow(src_ip=src, dst_ip="10.0.1.10", dst_port=5985)  # WinRM
        f2 = make_test_flow(src_ip=src, dst_ip="10.0.1.11", dst_port=5985)
        f3 = make_test_flow(src_ip=src, dst_ip="10.0.1.12", dst_port=5985)

        alerts1 = engine.analyze_flow(f1)
        alerts2 = engine.analyze_flow(f2)
        alerts3 = engine.analyze_flow(f3)

        self.assertEqual(len(alerts1), 0)
        self.assertEqual(len(alerts2), 0)
        self.assertGreaterEqual(len(alerts3), 1)

        lat_alert = next((a for a in alerts3 if a.category == AlertCategory.LATERAL_MOVEMENT), None)
        self.assertIsNotNone(lat_alert)
        self.assertEqual(lat_alert.src_ip, src)
        self.assertEqual(lat_alert.mitre["technique_id"], "T1021")


if __name__ == "__main__":
    unittest.main()
