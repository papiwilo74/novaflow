"""
NovaFlow NDR - Automated Tests for Dynamic Sigma Rule Engine
Valida el parser de reglas YAML nativo, la evaluación de condiciones y la gestión REST de reglas Sigma.
"""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.sigma_engine import SigmaEngine, parse_simple_yaml


class TestSigmaEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)
        self.admin_headers = {"X-API-Key": "novaflow-admin-key-9988"}
        self.now = datetime.now(timezone.utc)

    def _make_flow(self, src: str, dst: str, dst_port: int, proto: int = 6, pkts: int = 10, bytes_cnt: int = 1500) -> NetFlowRecord:
        return NetFlowRecord(
            timestamp=self.now,
            timestamp_ms=int(self.now.timestamp() * 1000),
            src_ip=src,
            dst_ip=dst,
            next_hop="0.0.0.0",
            input_snmp=1,
            output_snmp=2,
            packets=pkts,
            bytes=bytes_cnt,
            first_switched=0,
            last_switched=1000,
            src_port=50000,
            dst_port=dst_port,
            tcp_flags=2,
            protocol=proto,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def test_pure_python_yaml_parser(self):
        """Valida que parse_simple_yaml parsee diccionarios, listas, números y comentarios."""
        sample_yaml = """
        # Regla de prueba
        title: Test Rule
        id: test-01
        level: high
        tags:
          - attack.command_and_control
          - attack.t1071.001
        detection:
          selection:
            dst_port: [8080, 8443]
            protocol: 6
            bytes: "> 5000"
          condition: selection
        """
        parsed = parse_simple_yaml(sample_yaml)
        self.assertEqual(parsed["title"], "Test Rule")
        self.assertEqual(parsed["id"], "test-01")
        self.assertEqual(parsed["level"], "high")
        self.assertEqual(len(parsed["tags"]), 2)
        self.assertEqual(parsed["tags"][0], "attack.command_and_control")
        self.assertEqual(parsed["tags"][1], "attack.t1071.001")
        self.assertEqual(parsed["detection"]["selection"]["dst_port"], [8080, 8443])
        self.assertEqual(parsed["detection"]["selection"]["bytes"], "> 5000")

    def test_sigma_rule_evaluation_and_mitre_mapping(self):
        """Valida que una regla Sigma coincida con un flujo hostil y genere una alerta con MITRE mapeado."""
        sigma = SigmaEngine()
        yaml_rule = """
        title: Detection of Custom Backdoor Port
        id: backdoor-99
        level: critical
        tags:
          - attack.command_and_control
          - attack.t1071
        detection:
          selection:
            dst_port: 9999
            protocol: 6
            bytes: "> 1000"
          condition: selection
        """
        rule = sigma.load_rule_text(yaml_rule)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.mitre_technique, "T1071")
        self.assertEqual(rule.mitre_tactic, "Command And Control")

        # Flujo que NO coincide (puerto diferente)
        flow_benign = self._make_flow("10.0.0.5", "198.51.100.1", dst_port=80, bytes_cnt=2000)
        alerts_benign = sigma.evaluate_flow(flow_benign)
        self.assertEqual(len(alerts_benign), 0)

        # Flujo que SÍ coincide
        flow_hostile = self._make_flow("10.0.0.5", "198.51.100.1", dst_port=9999, bytes_cnt=2000)
        alerts_hostile = sigma.evaluate_flow(flow_hostile)
        self.assertEqual(len(alerts_hostile), 1)
        alert = alerts_hostile[0]
        self.assertEqual(alert.severity.value, "CRITICAL")
        self.assertIn("[SIGMA]", alert.title)
        self.assertEqual(alert.mitre["technique_id"], "T1071")

    def test_api_sigma_rules_endpoints(self):
        """Valida los endpoints REST /api/v1/rules/sigma (listar, recargar y probar regla)."""
        # 1. Listar reglas activas
        resp_list = self.client.get("/api/v1/rules/sigma", headers=self.admin_headers)
        self.assertEqual(resp_list.status_code, 200)
        data_list = resp_list.json()
        self.assertIn("total", data_list)
        self.assertIn("rules", data_list)

        # 2. Probar regla dinámica vía POST /test
        test_payload = {
            "rule_yaml": """
            title: API Test Rule
            id: api-test-rule
            level: high
            detection:
              selection:
                dst_port: 4444
                protocol: 6
              condition: selection
            """,
            "flow": {
                "src_ip": "10.0.0.15",
                "dst_ip": "198.51.100.5",
                "dst_port": 4444,
                "protocol": 6,
                "bytes": 500,
            }
        }
        resp_test = self.client.post("/api/v1/rules/sigma/test", json=test_payload, headers=self.admin_headers)
        self.assertEqual(resp_test.status_code, 200)
        data_test = resp_test.json()
        self.assertTrue(data_test["matched"])
        self.assertEqual(data_test["rule_id"], "api-test-rule")

        # 3. Recargar reglas
        resp_reload = self.client.post("/api/v1/rules/sigma/reload", headers=self.admin_headers)
        self.assertEqual(resp_reload.status_code, 200)
        self.assertEqual(resp_reload.json()["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
