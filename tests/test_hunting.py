"""
NovaFlow NDR - Automated Tests for Threat Hunting DSL & Playbooks
Valida el tokenizador, evaluador booleano AST, catálogo de playbooks y endpoints REST de búsqueda proactiva.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.hunting import ThreatHuntingParser, execute_flow_hunt, parse_byte_units, HUNTING_PLAYBOOKS


class TestThreatHunting(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)

        self.sample_flows = [
            {"src_ip": "10.0.0.15", "dst_ip": "10.0.0.5", "dst_port": 445, "protocol": 6, "bytes": 75000, "packets": 35},
            {"src_ip": "10.0.0.22", "dst_ip": "198.51.100.77", "dst_port": 8080, "protocol": 6, "bytes": 1500, "packets": 12},
            {"src_ip": "10.0.0.30", "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": 17, "bytes": 6200, "packets": 8},
            {"src_ip": "10.0.0.40", "dst_ip": "142.250.190.46", "dst_port": 443, "protocol": 6, "bytes": 15 * 1024 * 1024, "packets": 12000},
            {"src_ip": "10.0.0.50", "dst_ip": "10.0.0.80", "dst_port": 80, "protocol": 6, "bytes": 200, "packets": 2},
        ]
        system_state.recent_flows.extend(self.sample_flows)

    def test_byte_unit_parser(self):
        """Valida la conversión de unidades (K, M, G) en enteros de bytes."""
        self.assertEqual(parse_byte_units("10K"), 10 * 1024)
        self.assertEqual(parse_byte_units("5M"), 5 * 1024 * 1024)
        self.assertEqual(parse_byte_units("1G"), 1024 * 1024 * 1024)
        self.assertEqual(parse_byte_units("443"), 443)
        self.assertEqual(parse_byte_units("TCP"), "TCP")

    def test_ast_parsing_and_evaluation(self):
        """Valida que el parser genere un AST correcto y evalúe operadores lógicos."""
        # 1. Comparación simple
        ast1 = ThreatHuntingParser.parse("dst_port == 445")
        self.assertTrue(ast1.evaluate({"dst_port": 445}))
        self.assertFalse(ast1.evaluate({"dst_port": 80}))

        # 2. Operador IN con lista
        ast2 = ThreatHuntingParser.parse("dst_port IN [80, 443, 8080]")
        self.assertTrue(ast2.evaluate({"dst_port": 443}))
        self.assertFalse(ast2.evaluate({"dst_port": 22}))

        # 3. Expresión compleja con AND, OR y paréntesis
        ast3 = ThreatHuntingParser.parse("(dst_port == 443 OR dst_port == 80) AND bytes > 1M")
        self.assertTrue(ast3.evaluate({"dst_port": 443, "bytes": 2 * 1024 * 1024}))
        self.assertFalse(ast3.evaluate({"dst_port": 443, "bytes": 500}))
        self.assertFalse(ast3.evaluate({"dst_port": 21, "bytes": 2 * 1024 * 1024}))

        # 4. Operador NOT
        ast4 = ThreatHuntingParser.parse("NOT dst_port == 53")
        self.assertTrue(ast4.evaluate({"dst_port": 443}))
        self.assertFalse(ast4.evaluate({"dst_port": 53}))

    def test_execute_hunt_on_flows(self):
        """Valida la ejecución de una búsqueda sobre un conjunto de flujos en memoria."""
        # Buscar flujos en SMB (puerto 445) con más de 50KB
        query = "dst_port == 445 AND bytes > 50K"
        result = execute_flow_hunt(query, self.sample_flows)
        self.assertEqual(result["total_scanned"], 5)
        self.assertEqual(result["total_matched"], 1)
        self.assertEqual(result["results"][0]["src_ip"], "10.0.0.15")

    def test_syntax_error_handling(self):
        """Valida que las consultas mal formadas levanten ValueError descriptivo."""
        with self.assertRaises(ValueError):
            ThreatHuntingParser.parse("dst_port == [80, 443")  # Falta corchete

        with self.assertRaises(ValueError):
            ThreatHuntingParser.parse("(dst_port == 80 AND bytes > 100")  # Falta paréntesis

    def test_api_hunting_endpoints(self):
        """Valida los endpoints REST /api/v1/flows/hunt y /api/v1/flows/hunt/playbooks."""
        # 1. Catálogo de playbooks
        resp_playbooks = self.client.get("/api/v1/flows/hunt/playbooks")
        self.assertEqual(resp_playbooks.status_code, 200)
        data_pb = resp_playbooks.json()
        self.assertGreaterEqual(data_pb["total_playbooks"], 4)

        # 2. Ejecución de búsqueda válida
        req_payload = {
            "query": "proto == TCP AND bytes > 1M",
            "limit": 10,
        }
        resp_hunt = self.client.post("/api/v1/flows/hunt", json=req_payload)
        self.assertEqual(resp_hunt.status_code, 200)
        data_hunt = resp_hunt.json()
        self.assertIn("total_matched", data_hunt)
        self.assertIn("results", data_hunt)
        self.assertGreaterEqual(data_hunt["total_matched"], 1)

        # 3. Error sintáctico retorna HTTP 400
        bad_payload = {"query": "dst_port == (unclosed"}
        resp_bad = self.client.post("/api/v1/flows/hunt", json=bad_payload)
        self.assertEqual(resp_bad.status_code, 400)


if __name__ == "__main__":
    unittest.main()
