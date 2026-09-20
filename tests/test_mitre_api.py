"""
NovaFlow NDR - MITRE ATT&CK Matrix & Heatmap API Tests
Valida los endpoints REST de telemetría táctica, niveles térmicos y drill-down de incidentes.
"""

import unittest
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestMitreMatrixAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        system_state.initialize(cls.engine)
        cls.client = TestClient(app)

    def test_get_mitre_matrix(self):
        """Valida que /api/v1/mitre/matrix retorne la taxonomía táctica de MITRE."""
        res = self.client.get("/api/v1/mitre/matrix")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("tactics", data)
        self.assertIn("timestamp", data)
        tactics = data["tactics"]
        self.assertIn("Discovery", tactics)
        self.assertIn("Command and Control", tactics)
        self.assertIn("Lateral Movement", tactics)
        self.assertIn("Exfiltration", tactics)

    def test_get_mitre_heatmap_baseline_and_active(self):
        """Valida que /api/v1/mitre/heatmap responda con el cálculo térmico correcto."""
        # 1. En estado inicial
        res1 = self.client.get("/api/v1/mitre/heatmap")
        self.assertEqual(res1.status_code, 200)
        data1 = res1.json()
        self.assertIn("threat_level", data1)
        self.assertIn("cells", data1)
        self.assertTrue(len(data1["cells"]) > 0)

        # 2. Inyectar una alerta crítica de Movimiento Lateral (T1021)
        alert_lat = SecurityAlert(
            category=AlertCategory.LATERAL_MOVEMENT,
            severity=AlertSeverity.CRITICAL,
            title="Movimiento Lateral Crítico",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.200",
            dst_port=445,
            confidence=0.95,
        )
        self.engine._record_alert(alert_lat)

        res2 = self.client.get("/api/v1/mitre/heatmap")
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()

        # El nivel de amenaza global debe ser CRITICAL_RED
        self.assertEqual(data2["threat_level"], "CRITICAL_RED")
        self.assertGreaterEqual(data2["total_mitre_alerts"], 1)

        # Buscar celda de T1021
        cell_t1021 = next((c for c in data2["cells"] if c["technique_id"] == "T1021"), None)
        self.assertIsNotNone(cell_t1021)
        self.assertGreaterEqual(cell_t1021["active_alerts_count"], 1)
        self.assertEqual(cell_t1021["heat_score"], 3)
        self.assertEqual(cell_t1021["max_severity"], "CRITICAL")
        self.assertIn("10.0.0.99", cell_t1021["sources"])

    def test_get_alerts_by_technique_drilldown(self):
        """Valida que /api/v1/mitre/techniques/{technique_id}/alerts retorne los incidentes específicos."""
        # Asegurar que existe al menos una alerta registrada para T1021
        alert = SecurityAlert(
            category=AlertCategory.LATERAL_MOVEMENT,
            severity=AlertSeverity.HIGH,
            title="Drilldown Test Alert",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.200",
            dst_port=445,
            confidence=0.91,
        )
        self.engine._record_alert(alert)

        res = self.client.get("/api/v1/mitre/techniques/T1021/alerts")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["technique_id"], "T1021")
        self.assertGreaterEqual(data["count"], 1)
        self.assertTrue(any("10.0.0.99" == a["src_ip"] for a in data["alerts"]))


if __name__ == "__main__":
    unittest.main()
