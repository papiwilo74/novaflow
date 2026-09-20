"""
NovaFlow NDR - Automated Tests for SOAR Active Dispatcher & Webhooks
Valida la firma HMAC-SHA256, políticas de auto-contención, reintentos y Dead-Letter Queue (DLQ).
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import unittest
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from api.security.auth import JWTManager, Role
from detector.dispatcher import SOARWebhookDispatcher
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestSOARDispatcher(unittest.TestCase):
    def setUp(self):
        self.dispatcher = SOARWebhookDispatcher(max_retries=2)
        self.now = datetime.now(timezone.utc)

    def _make_alert(
        self,
        severity: AlertSeverity = AlertSeverity.CRITICAL,
        confidence: float = 0.95,
        category: AlertCategory = AlertCategory.MALICIOUS_C2,
        src_ip: str = "10.0.0.15",
        dst_ip: str = "198.51.100.77",
    ) -> SecurityAlert:
        return SecurityAlert(
            category=category,
            severity=severity,
            title="Alerta de Prueba SOAR",
            description="Incidente crítico para prueba de despacho",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=443,
            protocol=6,
            confidence=confidence,
            timestamp=self.now,
        )

    def test_hmac_sha256_signature(self):
        """Valida que la firma criptográfica HMAC-SHA256 sea calculada exactamente."""
        secret = "super-secret-key-12345"
        payload = json.dumps({"test": "value"}, sort_keys=True).encode("utf-8")

        sig_header = SOARWebhookDispatcher.sign_payload(secret, payload)
        self.assertTrue(sig_header.startswith("sha256="))

        expected_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        self.assertEqual(sig_header, expected_sig)

    def test_auto_containment_trigger_on_critical_alert(self):
        """Valida que alertas CRITICAL con alta confianza disparen el aislamiento automático."""
        crit_alert = self._make_alert(
            severity=AlertSeverity.CRITICAL,
            confidence=0.98,
            category=AlertCategory.MALICIOUS_C2,
            dst_ip="198.51.100.77",
        )

        action = self.dispatcher.evaluate_auto_containment(crit_alert)
        self.assertIsNotNone(action)
        self.assertEqual(action.status, "CONTAINED")
        self.assertEqual(action.target_ip, "198.51.100.77")
        self.assertIn("rules", action.playbook)
        self.assertGreaterEqual(len(action.playbook["rules"]), 4)

        # Verificar que alertas INFO o LOW no disparen contención
        low_alert = self._make_alert(severity=AlertSeverity.LOW, confidence=0.40)
        no_action = self.dispatcher.evaluate_auto_containment(low_alert)
        self.assertIsNone(no_action)

    def test_dispatch_success_and_delivery_counters(self):
        """Valida el despacho exitoso incrementando los contadores de entrega."""
        sub = self.dispatcher.register_webhook(
            name="Splunk SIEM",
            url="https://siem.corp.internal:8088/services/collector",
            secret="splunk-token",
            min_severity="HIGH",
        )

        alert = self._make_alert(severity=AlertSeverity.HIGH)
        result = self.dispatcher.dispatch_alert(alert)

        self.assertEqual(len(result["dispatched_targets"]), 1)
        self.assertEqual(result["dispatched_targets"][0]["status"], "DELIVERED")
        self.assertEqual(sub.deliveries_count, 1)
        self.assertEqual(sub.failures_count, 0)
        self.assertEqual(len(self.dispatcher.dead_letter_queue), 0)

    def test_dead_letter_queue_on_failure_and_retry(self):
        """Valida que fallos repetidos envíen el mensaje a Dead-Letter Queue y se pueda reintentar."""
        self.dispatcher.register_webhook(
            name="Unreachable Webhook",
            url="https://broken-endpoint.corp.internal/simulate_failure",
            min_severity="LOW",
        )

        alert = self._make_alert(severity=AlertSeverity.CRITICAL)
        result = self.dispatcher.dispatch_alert(alert)

        self.assertEqual(len(result["dispatched_targets"]), 1)
        self.assertEqual(result["dispatched_targets"][0]["status"], "QUEUED_IN_DLQ")

        # Verificar que se acumuló en la DLQ
        dlq_items = self.dispatcher.get_dlq()
        self.assertEqual(len(dlq_items), 1)
        self.assertEqual(dlq_items[0]["status"], "FAILED")

        # Reintentar con transport_sender exitoso
        def mock_success_sender(url, headers, body):
            return True

        retry_res = self.dispatcher.retry_dlq(transport_sender=mock_success_sender)
        self.assertEqual(retry_res["succeeded"], 1)
        self.assertEqual(retry_res["remaining_failed"], 0)


class TestSOARAPI(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)
        self.token = JWTManager.create_token({"sub": "admin_user", "role": Role.ADMIN, "tenant_id": "*"})
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_api_soar_endpoints(self):
        """Valida el ciclo de vida REST de suscripciones webhook y DLQ."""
        # 1. Registrar webhook
        reg_payload = {
            "name": "Cortex XSOAR",
            "url": "https://xsoar.corp.internal/webhook",
            "secret": "xsoar-secret-key",
            "min_severity": "HIGH",
            "enabled": True,
        }
        res_reg = self.client.post("/api/v1/soar/webhooks/register", json=reg_payload, headers=self.headers)
        self.assertEqual(res_reg.status_code, 200)
        wh = res_reg.json()["webhook"]
        wh_id = wh["id"]
        self.assertEqual(wh["name"], "Cortex XSOAR")

        # 2. Listar webhooks
        res_list = self.client.get("/api/v1/soar/webhooks", headers=self.headers)
        self.assertEqual(res_list.status_code, 200)
        self.assertGreaterEqual(len(res_list.json()["webhooks"]), 1)

        # 3. Consultar DLQ
        res_dlq = self.client.get("/api/v1/soar/dlq", headers=self.headers)
        self.assertEqual(res_dlq.status_code, 200)
        self.assertIn("dlq", res_dlq.json())

        # 4. Consultar Contenciones
        res_cont = self.client.get("/api/v1/soar/containments", headers=self.headers)
        self.assertEqual(res_cont.status_code, 200)
        self.assertIn("containments", res_cont.json())

        # 5. Eliminar webhook
        res_del = self.client.delete(f"/api/v1/soar/webhooks/{wh_id}", headers=self.headers)
        self.assertEqual(res_del.status_code, 200)


if __name__ == "__main__":
    unittest.main()
