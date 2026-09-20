"""
NovaFlow NDR - Test Suite para Purple Team Integration (OmniBreach vs NovaFlow)
Valida la matriz de correlación MITRE ATT&CK, los endpoints REST de simulación
y la orquestación defensiva frente a vectores de ataque DAST.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from scripts.purple_team_demo import run_purple_team_demo


class TestPurpleTeamIntegration(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)

    def test_purple_team_correlation_matrix_endpoint(self):
        """Valida que el endpoint /matrix retorne los 4 vectores canónicos con MITRE y CEF."""
        response = self.client.get("/api/v1/purple-team/matrix")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["total_vectors"], 4)
        self.assertEqual(data["red_team_tool"], "OmniBreach DAST")
        self.assertEqual(data["blue_team_tool"], "NovaFlow NDR")

        vector_ids = [v["vector_id"] for v in data["correlation_matrix"]]
        self.assertIn("OB-RECON-01", vector_ids)
        self.assertIn("OB-EXFIL-02", vector_ids)
        self.assertIn("OB-DOS-03", vector_ids)
        self.assertIn("OB-C2-04", vector_ids)

        mitre_ids = [v["mitre_id"] for v in data["correlation_matrix"]]
        self.assertIn("T1046", mitre_ids)
        self.assertIn("T1048.003", mitre_ids)
        self.assertIn("T1498.001", mitre_ids)
        self.assertIn("T1071", mitre_ids)

    def test_purple_team_simulation_live_endpoint(self):
        """Valida que la simulación en vivo /simulate dispare alertas y alcance 100% de detección."""
        response = self.client.post("/api/v1/purple-team/simulate")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["vectors_executed"], 4)
        self.assertEqual(data["alerts_triggered"], 4)
        self.assertEqual(data["detection_rate_pct"], 100.0)

        for res in data["results"]:
            self.assertTrue(res["detected"], f"Vector {res['vector_id']} no fue detectado")
            self.assertIsNotNone(res["alert_id"])
            self.assertIsNotNone(res["severity"])
            self.assertTrue(res["cef_log"].startswith("CEF:0|NovaSec|NovaFlow|1.0.0|"))

    def test_purple_team_demo_script_execution(self):
        """Valida que el script standalone de demostración ejecute los 4 escenarios exitosamente."""
        success = run_purple_team_demo(live_udp=False)
        self.assertTrue(success, "La demostración Purple Team debe detectar el 100% de los vectores")


if __name__ == "__main__":
    unittest.main()
