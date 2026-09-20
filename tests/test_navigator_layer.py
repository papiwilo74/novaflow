"""
NovaFlow NDR - Automated Tests for MITRE ATT&CK Navigator Layer Export
Valida la especificación formal Navigator v4.5 en GET /api/v1/mitre/navigator-layer.json.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestMitreNavigatorLayer(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)

    def test_navigator_layer_schema(self):
        """Valida que la salida cumpla con el estándar MITRE ATT&CK Navigator v4.5."""
        response = self.client.get("/api/v1/mitre/navigator-layer.json")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["domain"], "enterprise-attack")
        self.assertIn("versions", data)
        self.assertEqual(data["versions"]["layer"], "4.5")
        self.assertEqual(data["versions"]["attack"], "14")
        self.assertIn("gradient", data)
        self.assertEqual(len(data["gradient"]["colors"]), 4)
        self.assertIn("legendItems", data)
        self.assertEqual(len(data["legendItems"]), 4)
        self.assertIn("techniques", data)
        self.assertGreater(len(data["techniques"]), 5)

        # Cada técnica debe tener techniqueID, tactic, score, color, enabled
        sample_tech = data["techniques"][0]
        self.assertIn("techniqueID", sample_tech)
        self.assertIn("tactic", sample_tech)
        self.assertIn("score", sample_tech)
        self.assertIn("color", sample_tech)
        self.assertTrue(sample_tech["enabled"])

    def test_navigator_layer_threat_scoring(self):
        """Valida que la presencia de alertas críticas coloree adecuadamente la capa de MITRE."""
        # Insertar alerta crítica de C2 (T1071)
        crit_alert = SecurityAlert(
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.MALICIOUS_C2,
            title="Active Cobalt Strike C2",
            src_ip="10.0.0.10",
            dst_ip="198.51.100.77",
            status="NEW",
        )
        self.engine.alerts_history.append(crit_alert)

        response = self.client.get("/api/v1/mitre/navigator-layer.json")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        tech_c2 = next((t for t in data["techniques"] if t["techniqueID"] == "T1071"), None)
        self.assertIsNotNone(tech_c2)
        self.assertEqual(tech_c2["score"], 10)  # Puntuación máxima para crítico
        self.assertEqual(tech_c2["color"], "#ef4444")  # Rojo crítico


if __name__ == "__main__":
    unittest.main()
