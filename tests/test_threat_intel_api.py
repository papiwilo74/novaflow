"""
NovaFlow NDR - Automated Tests for Threat Intelligence REST API
Valida la consulta de estado del Counting Bloom Filter, sincronización de feeds C2 y gestión CRUD de IOCs en vivo.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine


class TestThreatIntelAPI(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)
        self.admin_headers = {"X-API-Key": "novaflow-admin-key-9988"}

    def test_get_threat_intel_status(self):
        """Valida GET /api/v1/threat-intel/status informando capacidad, memoria y conteo de IOCs."""
        response = self.client.get("/api/v1/threat-intel/status", headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("capacity", data)
        self.assertIn("items_count", data)
        self.assertIn("memory_bytes", data)
        self.assertIn("error_rate", data)
        self.assertIn("total_iocs_cached", data)
        self.assertIn("last_sync_status", data)
        self.assertGreater(data["capacity"], 0)
        self.assertLess(data["memory_bytes"], 10_000_000)

    def test_sync_custom_threat_intel_feed(self):
        """Valida POST /api/v1/threat-intel/sync incorporando un feed de reputación C2 en caliente."""
        feed_content = (
            "# Feodo Tracker Abuse.ch C2 Blocklist Test\n"
            "# Format: dst_ip:dst_port, malware\n"
            "198.51.100.123:443\tDridex C2\n"
            "198.51.100.124:8080\tQakBot C2\n"
            "203.0.113.50:443\tIcedID C2\n"
        )

        response = self.client.post(
            "/api/v1/threat-intel/sync",
            json={"custom_feed_text": feed_content},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["source"], "CUSTOM_PAYLOAD")
        self.assertEqual(data["synced_count"], 3)

        # Verificar que los IOCs estén indexados en el Bloom Filter del motor
        query_res = self.engine.bloom_intel.query_ip("198.51.100.123")
        self.assertIsNotNone(query_res)
        self.assertEqual(query_res["threat_name"], "Dridex C2")

        query_qak = self.engine.bloom_intel.query_ip("198.51.100.124")
        self.assertIsNotNone(query_qak)
        self.assertEqual(query_qak["threat_name"], "QakBot C2")

    def test_sync_public_feeds_offline_tolerance(self):
        """Valida que la sincronización sin payload gestione entornos desconectados sin lanzar excepciones."""
        # Al no pasar custom_feed_text intentará conectar a feodotracker.abuse.ch con timeout seguro de 2s
        response = self.client.post(
            "/api/v1/threat-intel/sync",
            json={},
            headers=self.admin_headers,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn(data["status"], ["SUCCESS", "OFFLINE_FALLBACK"])

    def test_add_and_remove_custom_ioc(self):
        """Valida adición y eliminación dinámica de IOCs en caliente (POST /iocs y DELETE /iocs/{ip})."""
        test_ip = "192.0.2.200"

        # 1. Agregar IOC
        add_payload = {
            "ip": test_ip,
            "threat_name": "TrickBot Banking Trojan",
            "threat_actor": "Wizard Spider",
            "confidence": 0.96,
        }
        add_resp = self.client.post(
            "/api/v1/threat-intel/iocs",
            json=add_payload,
            headers=self.admin_headers,
        )
        self.assertEqual(add_resp.status_code, 200)
        self.assertEqual(add_resp.json()["status"], "SUCCESS")
        self.assertEqual(add_resp.json()["ip"], test_ip)

        # Comprobar presencia en el Bloom Filter
        self.assertIsNotNone(self.engine.bloom_intel.query_ip(test_ip))

        # 2. Eliminar IOC
        del_resp = self.client.delete(
            f"/api/v1/threat-intel/iocs/{test_ip}",
            headers=self.admin_headers,
        )
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.json()["status"], "REMOVED")

        # Comprobar ausencia
        self.assertIsNone(self.engine.bloom_intel.query_ip(test_ip))

        # 3. Eliminar IOC inexistente (retorna 404)
        del_non_existent = self.client.delete(
            "/api/v1/threat-intel/iocs/10.99.99.99",
            headers=self.admin_headers,
        )
        self.assertEqual(del_non_existent.status_code, 404)


if __name__ == "__main__":
    unittest.main()
