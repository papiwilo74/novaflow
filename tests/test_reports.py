"""
Tests unitarios y de integración para el generador de reportes ejecutivos C-Level.
"""

import unittest
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from reports.executive_report import ExecutiveReportGenerator


class TestExecutiveReports(unittest.TestCase):
    def setUp(self):
        self.alerts = [
            SecurityAlert(
                alert_id="crit-c2-01",
                category=AlertCategory.MALICIOUS_C2,
                severity=AlertSeverity.CRITICAL,
                title="Infiltración de C2 Cobalt Strike",
                src_ip="10.0.0.15",
                dst_ip="198.51.100.77",
                dst_port=443,
                protocol=6,
                confidence=0.98,
            ),
            SecurityAlert(
                alert_id="high-exfil-02",
                category=AlertCategory.EXFILTRATION,
                severity=AlertSeverity.HIGH,
                title="Exfiltración Masiva de Datos",
                src_ip="10.0.0.10",
                dst_ip="203.0.113.5",
                dst_port=443,
                protocol=6,
                confidence=0.91,
            ),
        ]
        self.flows = [
            {"src_ip": "10.0.0.15", "dst_ip": "198.51.100.77", "bytes": 1048576, "packets": 500},
            {"src_ip": "10.0.0.10", "dst_ip": "203.0.113.5", "bytes": 20971520, "packets": 15000},
        ]

    def test_risk_score_calculation(self):
        """Valida que las ponderaciones de severidad calculen el Risk Score adecuadamente."""
        # Sin incidentes: Red segura
        clean_risk = ExecutiveReportGenerator.calculate_risk_scores([])
        self.assertEqual(clean_risk["risk_score"], 0.0)
        self.assertEqual(clean_risk["posture_score"], 100.0)
        self.assertEqual(clean_risk["status"], "HEALTHY")

        # Con incidentes CRITICAL + HIGH
        elevated_risk = ExecutiveReportGenerator.calculate_risk_scores(self.alerts)
        self.assertGreater(elevated_risk["risk_score"], 30.0)
        self.assertLess(elevated_risk["posture_score"], 70.0)
        self.assertIn(elevated_risk["status"], ("ELEVATED_RISK", "CRITICAL_RISK"))

    def test_report_data_and_html_rendering(self):
        """Valida la estructura de datos y el HTML generado para impresión/PDF."""
        data = ExecutiveReportGenerator.generate_report_data(self.alerts, self.flows)
        self.assertIn("report_title", data)
        self.assertIn("risk_assessment", data)
        self.assertIn("compliance_evaluation", data)
        self.assertEqual(len(data["findings"]), 2)
        self.assertEqual(data["telemetry_stats"]["total_flows"], 2)

        # HTML
        html = ExecutiveReportGenerator.generate_html_report(self.alerts, self.flows)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("NOVAFLOW", html)
        self.assertIn("@media print", html)
        self.assertIn("PCI-DSS v4.0", html)
        self.assertIn("Infiltración de C2 Cobalt Strike", html)

    def test_api_report_endpoints(self):
        """Valida los endpoints REST de reportes ejecutivos."""
        client = TestClient(app)
        engine = DetectionEngine()
        for a in self.alerts:
            engine.alerts_history.append(a)
        system_state.engine = engine
        system_state.recent_flows.extend(self.flows)

        headers = {"X-API-Key": "novaflow-admin-key-9988"}

        # 1. JSON Report
        res_json = client.get("/api/v1/reports/executive", headers=headers)
        self.assertEqual(res_json.status_code, 200)
        json_data = res_json.json()
        self.assertEqual(json_data["organization"], "NovaSec Technologies & Enterprise SOC")
        self.assertGreaterEqual(len(json_data["findings"]), 2)

        # 2. HTML Report
        res_html = client.get("/api/v1/reports/executive/html", headers=headers)
        self.assertEqual(res_html.status_code, 200)
        self.assertIn("text/html", res_html.headers["content-type"])
        self.assertIn("Reporte Ejecutivo de Seguridad", res_html.text)

        # 3. PCI-DSS Report
        res_pci = client.get("/api/v1/reports/pci-dss", headers=headers)
        self.assertEqual(res_pci.status_code, 200)
        pci_data = res_pci.json()
        self.assertEqual(pci_data["standard"], "PCI-DSS v4.0")
        self.assertEqual(len(pci_data["evaluated_requirements"]), 2)


if __name__ == "__main__":
    unittest.main()
