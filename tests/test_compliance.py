"""
NovaFlow NDR - Test Suite para Cumplimiento Normativo Corporativo
Valida el mapeo de incidentes de red contra PCI-DSS v4.0, ISO/IEC 27001:2022,
NIST CSF 2.0 y CIS Controls v8, así como los endpoints REST de cumplimiento.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.compliance import COMPLIANCE_MAPPING, get_all_compliance_catalog, get_compliance_for_category
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestCorporateCompliance(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)

    def test_all_alert_categories_have_compliance_mapping(self):
        """Valida que cada categoría de alerta esté formalmente mapeada a los 4 marcos normativos."""
        for category in AlertCategory:
            self.assertIn(
                category,
                COMPLIANCE_MAPPING,
                f"La categoría {category} carece de mapeo normativo!",
            )
            refs = COMPLIANCE_MAPPING[category]
            self.assertGreaterEqual(len(refs), 3, f"Categoría {category} debe tener al menos 3 estándares")

            standards_present = {r.standard for r in refs}
            self.assertIn("PCI-DSS v4.0", standards_present)
            self.assertIn("ISO/IEC 27001:2022", standards_present)
            self.assertIn("NIST CSF 2.0", standards_present)

    def test_security_alert_auto_populates_compliance(self):
        """Valida que una entidad SecurityAlert se inicialice automáticamente con sus referencias de cumplimiento."""
        alert = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.PORT_SCAN,
            title="Sondeo L4",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
        )
        self.assertIsNotNone(alert.compliance)
        self.assertGreater(len(alert.compliance), 0)

        # Verificar que aparezca en la serialización to_dict()
        data = alert.to_dict()
        self.assertIn("compliance", data)
        pci_entry = next((c for c in data["compliance"] if c["standard"] == "PCI-DSS v4.0"), None)
        self.assertIsNotNone(pci_entry)
        self.assertIn("Req 11.4", pci_entry["requirement_id"])

    def test_compliance_matrix_endpoint(self):
        """Valida que GET /api/v1/compliance/matrix retorne el catálogo completo."""
        response = self.client.get("/api/v1/compliance/matrix")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("catalog", data)
        self.assertEqual(data["catalog"]["frameworks_count"], 4)
        self.assertIn("PCI-DSS v4.0", data["catalog"]["standards"])
        self.assertIn("ISO/IEC 27001:2022", data["catalog"]["standards"])
        self.assertIn("NIST CSF 2.0", data["catalog"]["standards"])
        self.assertIn("CIS Controls v8", data["catalog"]["standards"])

    def test_compliance_status_endpoint(self):
        """Valida que GET /api/v1/compliance/status calcule la postura de cumplimiento."""
        # 1. Sin alertas: postura 100% EXCELLENT
        response = self.client.get("/api/v1/compliance/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["compliance_posture_score"], 100.0)
        self.assertEqual(data["posture_status"], "EXCELLENT")
        self.assertEqual(data["critical_violations"], 0)

        # 2. Agregar una alerta crítica (penalización)
        crit_alert = SecurityAlert(
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.MALICIOUS_C2,
            title="C2 Detectado",
            status="NEW",
        )
        self.engine.alerts_history.append(crit_alert)

        resp_after = self.client.get("/api/v1/compliance/status")
        self.assertEqual(resp_after.status_code, 200)
        data_after = resp_after.json()

        self.assertEqual(data_after["critical_violations"], 1)
        self.assertEqual(data_after["compliance_posture_score"], 85.0)  # 100 - 15
        self.assertEqual(data_after["standards"]["PCI-DSS v4.0"]["status"], "AT_RISK")


if __name__ == "__main__":
    unittest.main()
