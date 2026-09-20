"""
Tests unitarios y de integración para el motor de correlación de campañas Attack Kill Chain.
"""

import unittest
from datetime import datetime, timezone

from detector.correlator import AttackKillChainCorrelator
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestAttackKillChainCorrelator(unittest.TestCase):
    def setUp(self):
        self.correlator = AttackKillChainCorrelator(correlation_window_seconds=600.0)

    def _make_alert(self, category: AlertCategory, src_ip: str, dst_ip: str, title: str) -> SecurityAlert:
        return SecurityAlert(
            category=category,
            severity=AlertSeverity.MEDIUM,
            title=title,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=443,
            protocol=6,
            confidence=0.88,
        )

    def test_single_stage_does_not_trigger_campaign(self):
        """Múltiples alertas de la misma etapa (ej. solo escaneos) no constituyen una campaña multi-etapa."""
        a1 = self._make_alert(AlertCategory.PORT_SCAN, "10.0.0.99", "10.0.0.1", "Escaneo 1")
        a2 = self._make_alert(AlertCategory.PORT_SCAN, "10.0.0.99", "10.0.0.2", "Escaneo 2")

        self.assertIsNone(self.correlator.process_alert(a1))
        self.assertIsNone(self.correlator.process_alert(a2))

    def test_multi_stage_progression_triggers_campaign(self):
        """La transición de Reconocimiento a C2 y luego a Exfiltración genera alerta de campaña consolidada."""
        src_attacker = "10.0.0.15"

        # Etapa 1: Reconocimiento (PORT_SCAN)
        alert_recon = self._make_alert(AlertCategory.PORT_SCAN, src_attacker, "10.0.0.50", "Port Scan Discovery")
        res1 = self.correlator.process_alert(alert_recon)
        self.assertIsNone(res1, "Solo 1 etapa presente, no debe disparar campaña aún")

        # Etapa 2: Command & Control (C2_BEACONING)
        alert_c2 = self._make_alert(AlertCategory.C2_BEACONING, src_attacker, "198.51.100.77", "C2 Beaconing")
        campaign_alert = self.correlator.process_alert(alert_c2)

        self.assertIsNotNone(campaign_alert, "Al observar 2 etapas debe emitir alerta de campaña")
        self.assertEqual(campaign_alert.category, AlertCategory.ATTACK_CAMPAIGN)
        self.assertEqual(campaign_alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(campaign_alert.confidence, 0.99)
        self.assertEqual(campaign_alert.src_ip, src_attacker)
        self.assertIn("1_RECONNAISSANCE", campaign_alert.metrics["stages_observed"])
        self.assertIn("2_COMMAND_AND_CONTROL", campaign_alert.metrics["stages_observed"])
        self.assertEqual(campaign_alert.metrics["correlated_alerts_count"], 2)

        # Etapa 3: Acciones en Objetivos (EXFILTRATION)
        alert_exfil = self._make_alert(AlertCategory.EXFILTRATION, src_attacker, "203.0.113.88", "Data Exfiltration")
        campaign_alert_3 = self.correlator.process_alert(alert_exfil)

        self.assertIsNotNone(campaign_alert_3, "Al desbloquear la tercera etapa debe emitir campaña escalada")
        self.assertIn("3_ACTIONS_ON_OBJECTIVES", campaign_alert_3.metrics["stages_observed"])
        self.assertEqual(campaign_alert_3.metrics["tactics_count"], 3)
        self.assertEqual(campaign_alert_3.metrics["correlated_alerts_count"], 3)

    def test_detection_engine_kill_chain_integration(self):
        """Valida que DetectionEngine ejecute la correlación de forma automática al registrar alertas."""
        engine = DetectionEngine()

        # Inyectar alerta 1: Discovery
        a1 = self._make_alert(AlertCategory.PORT_SCAN, "10.0.50.77", "10.0.0.10", "Scan Test")
        engine._record_alert(a1)
        self.assertEqual(len(engine.alerts_history), 1)

        # Inyectar alerta 2: C2 desde la misma IP
        a2 = self._make_alert(AlertCategory.MALICIOUS_C2, "10.0.50.77", "198.51.100.99", "C2 Test")
        engine._record_alert(a2)

        # La historia de alertas ahora debe contener a1, a2 Y la alerta consolidada de campaña
        self.assertEqual(len(engine.alerts_history), 3)
        campaign = engine.alerts_history[-1]
        self.assertEqual(campaign.category, AlertCategory.ATTACK_CAMPAIGN)
        self.assertEqual(campaign.severity, AlertSeverity.CRITICAL)
        self.assertEqual(campaign.src_ip, "10.0.50.77")


if __name__ == "__main__":
    unittest.main()
