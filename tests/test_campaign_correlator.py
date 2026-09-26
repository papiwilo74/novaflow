"""
Pruebas unitarias para el Pilar 3: Correlador Causal Multi-Etapa de Kill Chain Bayesiano / Markoviano.
"""

import time
import unittest
from starlette.testclient import TestClient

from api.main import app
from api.security.auth import JWTManager, Role
from detector.campaign_correlator import (
    BayesianCampaignEngine,
    CampaignCase,
    KillChainStage,
    map_alert_to_stage,
)
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestCampaignCorrelator(unittest.TestCase):
    """Batería de validación de correlación causal bayesiana y consolidación de campañas."""

    def setUp(self):
        self.admin_token = JWTManager.create_token(
            {
                "sub": "soc-admin-tester",
                "role": Role.ADMIN,
                "tenant_id": "default",
                "name": "Admin Tester",
            },
            expires_in_minutes=30,
        )
        self.auth_headers = {"Authorization": f"Bearer {self.admin_token}"}

    def test_map_alert_to_stage(self):
        """Verifica el mapeo correcto de categorías de alerta a etapas del Enterprise Kill Chain."""
        a_recon = SecurityAlert(category=AlertCategory.PORT_SCAN)
        self.assertEqual(map_alert_to_stage(a_recon), KillChainStage.RECONNAISSANCE)

        a_lat = SecurityAlert(category=AlertCategory.LATERAL_MOVEMENT)
        self.assertEqual(map_alert_to_stage(a_lat), KillChainStage.LATERAL_MOVEMENT)

        a_cred = SecurityAlert(category=AlertCategory.IDENTITY_ATTACK)
        self.assertEqual(map_alert_to_stage(a_cred), KillChainStage.CREDENTIAL_ACCESS)

        a_c2 = SecurityAlert(category=AlertCategory.C2_BEACONING)
        self.assertEqual(map_alert_to_stage(a_c2), KillChainStage.COMMAND_AND_CONTROL)

        a_exfil = SecurityAlert(category=AlertCategory.EXFILTRATION)
        self.assertEqual(map_alert_to_stage(a_exfil), KillChainStage.EXFILTRATION)

    def test_bayesian_campaign_escalation(self):
        """Valida que una secuencia de ataques multi-etapa escale a Campaña Confirmada."""
        engine = BayesianCampaignEngine(time_window_seconds=600.0)
        victim = "10.0.50.25"
        t0 = 1700000000.0

        # Etapa 1: Reconocimiento (Port Scan)
        alert_1 = SecurityAlert(
            severity=AlertSeverity.MEDIUM,
            category=AlertCategory.PORT_SCAN,
            src_ip="10.0.50.99",
            dst_ip=victim,
        )
        case_1, esc_1 = engine.ingest_alert(alert_1, timestamp=t0)
        self.assertIsNotNone(case_1)
        self.assertIsNone(esc_1, "Una única alerta no debe escalar a campaña")
        self.assertIn(KillChainStage.RECONNAISSANCE, case_1.stages)
        prob_stage_1 = case_1.bayesian_probability

        # Etapa 2: Movimiento Lateral (PsExec)
        alert_2 = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.LATERAL_MOVEMENT,
            src_ip="10.0.50.99",
            dst_ip=victim,
        )
        case_2, esc_2 = engine.ingest_alert(alert_2, timestamp=t0 + 60)
        self.assertGreater(case_2.bayesian_probability, prob_stage_1)

        # Etapa 3: Acceso a Credenciales (Kerberoasting)
        alert_3 = SecurityAlert(
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.IDENTITY_ATTACK,
            src_ip="10.0.50.99",
            dst_ip="10.0.0.2",
        )
        case_3, esc_3 = engine.ingest_alert(alert_3, timestamp=t0 + 120)
        self.assertGreaterEqual(case_3.bayesian_probability, 0.85)
        self.assertIsNotNone(esc_3, "Tres etapas críticas deben gatillar una alerta consolidada")
        self.assertEqual(esc_3.category, AlertCategory.ATTACK_CAMPAIGN)
        self.assertEqual(esc_3.severity, AlertSeverity.CRITICAL)
        self.assertEqual(case_3.status, "ESCALATED")

    def test_campaigns_api_endpoints(self):
        """Verifica la API REST de consulta y gestión de campañas."""
        with TestClient(app) as client:
            # 1. Listado de campañas
            res = client.get("/api/v1/campaigns", headers=self.auth_headers)
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertIn("campaigns", data)

            # 2. Inyectar alertas para generar una campaña en memoria
            from api.state import system_state
            engine = system_state.campaign_engine
            a1 = SecurityAlert(category=AlertCategory.PORT_SCAN, src_ip="192.168.10.100", severity=AlertSeverity.HIGH)
            a2 = SecurityAlert(category=AlertCategory.MALICIOUS_C2, src_ip="192.168.10.100", severity=AlertSeverity.CRITICAL)
            engine.ingest_alert(a1)
            case, _ = engine.ingest_alert(a2)
            campaign_id = case.campaign_id

            # 3. Consultar detalle de la campaña generada
            res_det = client.get(f"/api/v1/campaigns/{campaign_id}", headers=self.auth_headers)
            self.assertEqual(res_det.status_code, 200)
            self.assertEqual(res_det.json()["campaign_id"], campaign_id)
            self.assertIn("192.168.10.100", res_det.json()["involved_assets"])

            # 4. Modificar estado
            res_status = client.post(
                f"/api/v1/campaigns/{campaign_id}/status",
                json={"status": "CONTAINED"},
                headers=self.auth_headers,
            )
            self.assertEqual(res_status.status_code, 200)
            self.assertEqual(res_status.json()["new_status"], "CONTAINED")


if __name__ == "__main__":
    unittest.main()
