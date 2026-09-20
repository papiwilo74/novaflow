"""
NovaFlow NDR - Automated Tests for OCSF v1.1.0 Export (Open Cybersecurity Schema Framework)
Valida la serialización de alertas de seguridad bajo Category 2: Findings, Class 2001: Security Finding.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestOCSFExport(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)

        self.alert_c2 = SecurityAlert(
            alert_id="c2-ocsf-001",
            category=AlertCategory.MALICIOUS_C2,
            severity=AlertSeverity.CRITICAL,
            title="Conexión de Comando y Control C2",
            description="Baliza periódica C2 detectada hacia 198.51.100.44",
            src_ip="10.0.0.10",
            dst_ip="198.51.100.44",
            dst_port=443,
            protocol=6,
            confidence=0.98,
            metrics={"beacon_jitter": 0.04, "entropy": 7.85},
            status="NEW",
        )

        self.alert_scan = SecurityAlert(
            alert_id="scan-ocsf-002",
            category=AlertCategory.PORT_SCAN,
            severity=AlertSeverity.MEDIUM,
            title="Escaneo Horizontal de Puertos",
            description="Sondeo TCP SYN hacia múltiples destinos",
            src_ip="192.168.1.55",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol=6,
            confidence=0.88,
            metrics={"scanned_ports": 45},
            status="RESOLVED",
        )

    def test_alert_to_ocsf_schema_conformance(self):
        """Valida que SecurityAlert.to_ocsf() cumpla con la especificación formal OCSF v1.1.0."""
        ocsf = self.alert_c2.to_ocsf()

        # Metadatos del esquema
        self.assertEqual(ocsf["category_uid"], 2)  # Findings
        self.assertEqual(ocsf["category_name"], "Findings")
        self.assertEqual(ocsf["class_uid"], 2001)  # Security Finding
        self.assertEqual(ocsf["class_name"], "Security Finding")
        self.assertEqual(ocsf["activity_id"], 1)  # Create
        self.assertEqual(ocsf["metadata"]["version"], "1.1.0")

        # Mapeo de severidad (CRITICAL -> severity_id 5)
        self.assertEqual(ocsf["severity_id"], 5)
        self.assertEqual(ocsf["severity"], "CRITICAL")

        # Mapeo de estado (NEW -> status_id 1)
        self.assertEqual(ocsf["status_id"], 1)
        self.assertEqual(ocsf["status"], "NEW")

        # Finding info
        finding = ocsf["finding_info"]
        self.assertEqual(finding["uid"], "c2-ocsf-001")
        self.assertEqual(finding["title"], "Conexión de Comando y Control C2")
        self.assertEqual(finding["desc"], "Baliza periódica C2 detectada hacia 198.51.100.44")
        self.assertIn("attacks", ocsf)
        self.assertGreaterEqual(len(ocsf["attacks"]), 1)
        self.assertIn("technique", ocsf["attacks"][0])
        self.assertIn("tactic", ocsf["attacks"][0])

        # Red y endpoints
        net = ocsf["network_activity"]
        self.assertEqual(net["src_endpoint"]["ip"], "10.0.0.10")
        self.assertEqual(net["dst_endpoint"]["ip"], "198.51.100.44")
        self.assertEqual(net["dst_endpoint"]["port"], 443)
        self.assertEqual(net["protocol_num"], 6)
        self.assertEqual(net["protocol_name"], "TCP")

        # Metadatos del producto
        metadata = ocsf["metadata"]
        self.assertEqual(metadata["product"]["name"], "NovaFlow NDR")
        self.assertEqual(metadata["product"]["vendor_name"], "NovaSec")

        # Datos no mapeados (preservación de métricas y telemetría)
        self.assertIn("unmapped", ocsf)
        self.assertEqual(ocsf["unmapped"]["beacon_jitter"], 0.04)
        self.assertEqual(ocsf["unmapped"]["entropy"], 7.85)

    def test_ocsf_severity_and_status_translations(self):
        """Valida que todos los niveles de severidad y estados se traduzcan correctamente a IDs OCSF."""
        ocsf_scan = self.alert_scan.to_ocsf()
        # MEDIUM -> 3, RESOLVED -> 4
        self.assertEqual(ocsf_scan["severity_id"], 3)
        self.assertEqual(ocsf_scan["severity"], "MEDIUM")
        self.assertEqual(ocsf_scan["status_id"], 4)
        self.assertEqual(ocsf_scan["status"], "RESOLVED")

    def test_api_export_all_alerts_ocsf(self):
        """Valida el endpoint GET /api/v1/alerts/export/ocsf para SIEM / Data Lakes."""
        self.engine.alerts_history.append(self.alert_c2)
        self.engine.alerts_history.append(self.alert_scan)

        response = self.client.get("/api/v1/alerts/export/ocsf")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["version"], "1.1.0")
        self.assertEqual(data["class_uid"], 2001)
        self.assertEqual(data["findings_count"], 2)
        self.assertEqual(len(data["findings"]), 2)
        uids = [f["finding_info"]["uid"] for f in data["findings"]]
        self.assertIn("c2-ocsf-001", uids)
        self.assertIn("scan-ocsf-002", uids)

    def test_api_export_single_alert_ocsf(self):
        """Valida el endpoint GET /api/v1/alerts/{alert_id}/ocsf para un incidente específico."""
        self.engine.alerts_history.append(self.alert_c2)

        response = self.client.get("/api/v1/alerts/c2-ocsf-001/ocsf")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["finding_info"]["uid"], "c2-ocsf-001")
        self.assertEqual(data["class_uid"], 2001)

        # Caso no encontrado
        resp_404 = self.client.get("/api/v1/alerts/non-existent-alert/ocsf")
        self.assertEqual(resp_404.status_code, 404)


if __name__ == "__main__":
    unittest.main()
