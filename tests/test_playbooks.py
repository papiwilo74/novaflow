"""
Tests unitarios y de integración para el motor de mitigación activa y SOAR playbooks.
"""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.playbooks import MitigationPlaybookGenerator, IncidentPlaybook
from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine


class TestMitigationPlaybooks(unittest.TestCase):
    def setUp(self):
        self.alert_scan = SecurityAlert(
            alert_id="scan-001",
            category=AlertCategory.PORT_SCAN,
            severity=AlertSeverity.MEDIUM,
            title="Barrido de Puertos SYN",
            description="Escaneo horizontal detectado desde 192.168.1.100",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol=6,
            confidence=0.92,
            metrics={"scanned_ports": 25},
        )

        self.alert_c2 = SecurityAlert(
            alert_id="c2-002",
            category=AlertCategory.MALICIOUS_C2,
            severity=AlertSeverity.CRITICAL,
            title="Conexión con C2 Cobalt Strike",
            description="Baliza saliente hacia IP maliciosa 198.51.100.77",
            src_ip="10.0.0.15",
            dst_ip="198.51.100.77",
            dst_port=443,
            protocol=6,
            confidence=0.98,
            metrics={"threat_name": "Cobalt Strike C2"},
        )

    def test_playbook_generation_for_attacker_scan(self):
        """Para escaneos y ataques entrantes, el playbook debe bloquear el src_ip."""
        playbook = MitigationPlaybookGenerator.generate_playbook(self.alert_scan)
        self.assertEqual(playbook.alert_id, "scan-001")
        self.assertEqual(playbook.target_ip_to_block, "192.168.1.100")
        self.assertEqual(playbook.incident_category, "PORT_SCAN")
        self.assertEqual(playbook.incident_severity, "MEDIUM")
        self.assertIn("cuarentena", playbook.recommended_action)
        self.assertEqual(len(playbook.rules), 5)

        # Verificar reglas individuales
        platforms = [r.platform for r in playbook.rules]
        self.assertIn("Linux iptables", platforms)
        self.assertIn("Linux nftables", platforms)
        self.assertIn("Cisco IOS ACL", platforms)
        self.assertIn("AWS Network ACL (NACL)", platforms)
        self.assertIn("Linux Null-Route", platforms)

        iptables_rule = next(r for r in playbook.rules if r.platform == "Linux iptables")
        self.assertIn("192.168.1.100", iptables_rule.block_command)
        self.assertIn("DROP", iptables_rule.block_command)
        self.assertIn("192.168.1.100", iptables_rule.rollback_command)

        nft_rule = next(r for r in playbook.rules if r.platform == "Linux nftables")
        self.assertIn("192.168.1.100", nft_rule.block_command)

        cisco_rule = next(r for r in playbook.rules if r.platform == "Cisco IOS ACL")
        self.assertIn("deny ip host 192.168.1.100", cisco_rule.block_command)

        aws_rule = next(r for r in playbook.rules if r.platform == "AWS Network ACL (NACL)")
        self.assertIn("192.168.1.100/32", aws_rule.block_command)
        self.assertIn("deny", aws_rule.block_command)

        null_route_rule = next(r for r in playbook.rules if r.platform == "Linux Null-Route")
        self.assertIn("blackhole 192.168.1.100/32", null_route_rule.block_command)

    def test_playbook_generation_for_c2_exfiltration(self):
        """Para C2 y Exfiltración, el playbook debe bloquear el destino externo hostil (dst_ip)."""
        playbook = MitigationPlaybookGenerator.generate_playbook(self.alert_c2)
        self.assertEqual(playbook.target_ip_to_block, "198.51.100.77")
        self.assertIn("servidor externo hostil/C2", playbook.recommended_action)
        self.assertEqual(playbook.estimated_impact, "LOW")

        d = playbook.to_dict()
        self.assertEqual(d["target_ip_to_block"], "198.51.100.77")
        self.assertEqual(len(d["rules"]), 5)

    def test_api_playbook_endpoint(self):
        """Prueba del endpoint REST /api/v1/alerts/{alert_id}/playbook."""
        client = TestClient(app)
        engine = DetectionEngine()
        engine.alerts_history.append(self.alert_c2)
        system_state.engine = engine

        headers = {"X-API-Key": "novaflow-admin-key-9988"}
        response = client.get("/api/v1/alerts/c2-002/playbook", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["alert_id"], "c2-002")
        self.assertEqual(data["target_ip_to_block"], "198.51.100.77")
        self.assertEqual(len(data["rules"]), 5)

        # Caso inexistente
        resp_404 = client.get("/api/v1/alerts/nonexistent/playbook", headers=headers)
        self.assertEqual(resp_404.status_code, 404)


if __name__ == "__main__":
    unittest.main()
