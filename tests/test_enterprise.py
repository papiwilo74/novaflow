"""
NovaFlow NDR - Enterprise Architecture & Hardening Test Suite
"""

import time
import unittest
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from api.security.auth import JWTManager, Role
from api.security.config import security_config
from api.security.audit import audit_logger
from api.security.rate_limiter import SlidingWindowRateLimiter
from api.observability.metrics import generate_prometheus_metrics
from api.observability.tracing import DistributedTracingMiddleware
from collector.adaptive_batcher import AdaptiveBatcher
from collector.worker_pool import UDPWorkerPool
from collector.kafka import KafkaFlowProducer, KafkaFlowConsumer
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.engine import DetectionEngine
from detector.ml.model_registry import model_registry
from detector.ml.explainability import AnomalyExplainer
from detector.ml.online_learner import OnlineDistributionLearner


class TestNovaFlowEnterprise(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        system_state.initialize(cls.engine)
        cls.client = TestClient(app)

    # 1. SEGURIDAD & AUTH (JWT, API KEYS, RBAC)
    def test_jwt_generation_and_validation(self):
        payload = {
            "sub": "analyst-01",
            "name": "Security Analyst",
            "role": Role.ANALYST,
            "tenant_id": "tenant-corp-a",
        }
        token = JWTManager.create_token(payload, expires_in_minutes=15)
        self.assertIsInstance(token, str)
        self.assertEqual(len(token.split(".")), 3)

        decoded = JWTManager.decode_token(token)
        self.assertEqual(decoded["sub"], "analyst-01")
        self.assertEqual(decoded["role"], Role.ANALYST)
        self.assertEqual(decoded["tenant_id"], "tenant-corp-a")

    def test_rbac_analyst_vs_readonly(self):
        readonly_token = JWTManager.create_token({
            "sub": "auditor-01",
            "role": Role.READONLY,
            "tenant_id": "default",
        })

        analyst_token = JWTManager.create_token({
            "sub": "analyst-01",
            "role": Role.ANALYST,
            "tenant_id": "default",
        })

        alert = SecurityAlert(
            severity=AlertSeverity.MEDIUM,
            category=AlertCategory.SYN_FLOOD,
            title="Prueba RBAC",
            tenant_id="default",
        )
        self.engine._record_alert(alert)

        # READONLY -> 403 Forbidden
        res_forbidden = self.client.patch(
            f"/api/v1/alerts/{alert.alert_id}/status",
            headers={"Authorization": f"Bearer {readonly_token}"},
            json={"status": "INVESTIGATING"},
        )
        self.assertEqual(res_forbidden.status_code, 403)

        # ANALYST -> 200 OK
        res_allowed = self.client.patch(
            f"/api/v1/alerts/{alert.alert_id}/status",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={"status": "INVESTIGATING"},
        )
        self.assertEqual(res_allowed.status_code, 200)
        self.assertEqual(res_allowed.json()["alert"]["status"], "INVESTIGATING")

    def test_api_key_authentication(self):
        """Valida que el acceso con cabecera X-API-Key resuelva identidades de servicio."""
        valid_key = "novaflow-admin-key-9988"
        response = self.client.get(
            "/api/v1/alerts",
            headers={"X-API-Key": valid_key},
        )
        self.assertEqual(response.status_code, 200)

        # Probar API Key falsa -> debe dar 401
        invalid_resp = self.client.get(
            "/api/v1/alerts",
            headers={"X-API-Key": "invalid-secret-key-1234"},
        )
        self.assertEqual(invalid_resp.status_code, 401)

    # 2. MULTI-TENANCY
    def test_multi_tenancy_alert_isolation(self):
        tenant_a_token = JWTManager.create_token({
            "sub": "user-a",
            "role": Role.ANALYST,
            "tenant_id": "tenant-finance",
        })
        tenant_b_token = JWTManager.create_token({
            "sub": "user-b",
            "role": Role.ANALYST,
            "tenant_id": "tenant-hr",
        })

        alert_finance = SecurityAlert(
            title="Alerta Finanzas",
            tenant_id="tenant-finance",
            severity=AlertSeverity.HIGH,
        )
        alert_hr = SecurityAlert(
            title="Alerta HR",
            tenant_id="tenant-hr",
            severity=AlertSeverity.MEDIUM,
        )
        self.engine._record_alert(alert_finance)
        self.engine._record_alert(alert_hr)

        # Usuario Finanzas consulta lista
        resp_fin = self.client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Bearer {tenant_a_token}"},
        )
        self.assertEqual(resp_fin.status_code, 200)
        fin_alerts = resp_fin.json()["alerts"]
        fin_titles = [a["title"] for a in fin_alerts]
        self.assertIn("Alerta Finanzas", fin_titles)
        self.assertNotIn("Alerta HR", fin_titles)

        # Usuario Finanzas intenta consultar directamente la alerta de HR por ID -> 403 Forbidden
        resp_cross_tenant = self.client.get(
            f"/api/v1/alerts/{alert_hr.alert_id}",
            headers={"Authorization": f"Bearer {tenant_a_token}"},
        )
        self.assertEqual(resp_cross_tenant.status_code, 403)

    # 3. OBSERVABILIDAD & CUMPLIMIENTO
    def test_prometheus_metrics_endpoint(self):
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.headers["content-type"])
        body = response.text
        self.assertIn("novaflow_uptime_seconds", body)
        self.assertIn("novaflow_throughput_mbps", body)
        self.assertIn("novaflow_alerts_total", body)

    def test_audit_trail_logging(self):
        entry = audit_logger.log(
            user_id="analyst-99",
            role=Role.ANALYST,
            tenant_id="tenant-corp-a",
            action="RULE_CONFIGURATION_CHANGE",
            resource_id="rule-syn-flood",
            details={"threshold_old": 50, "threshold_new": 100},
            status="SUCCESS",
        )
        self.assertIsNotNone(entry.audit_id)
        self.assertEqual(entry.action, "RULE_CONFIGURATION_CHANGE")

        admin_token = JWTManager.create_token({
            "sub": "admin",
            "role": Role.ADMIN,
            "tenant_id": "*",
        })
        resp = self.client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        logs = resp.json()["audit_logs"]
        actions = [log["action"] for log in logs]
        self.assertIn("RULE_CONFIGURATION_CHANGE", actions)

    # 4. RATE LIMITING
    def test_sliding_window_rate_limiter_logic(self):
        from starlette.datastructures import Headers

        class DummyClient:
            host = "192.168.100.99"

        class DummyRequest:
            client = DummyClient()
            headers = Headers({"X-API-Key": "test-rate-key"})
            url = type("URL", (), {"path": "/api/v1/test"})()

        limiter = SlidingWindowRateLimiter(app=None, max_requests_per_minute=3)

        async def dummy_next(req):
            from starlette.responses import Response
            return Response("OK")

        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        r1 = loop.run_until_complete(limiter.dispatch(DummyRequest(), dummy_next))
        r2 = loop.run_until_complete(limiter.dispatch(DummyRequest(), dummy_next))
        r3 = loop.run_until_complete(limiter.dispatch(DummyRequest(), dummy_next))
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r3.status_code, 200)

        r4 = loop.run_until_complete(limiter.dispatch(DummyRequest(), dummy_next))
        self.assertEqual(r4.status_code, 429)
        loop.close()

    # 5. ESCALABILIDAD & HA (ADAPTIVE BATCHER, KAFKA BUFFER)
    def test_adaptive_batcher_dynamic_scaling(self):
        import asyncio
        from collector.parser import NetFlowRecord
        from datetime import datetime, timezone

        flushed_batches = []

        def mock_flush(batch):
            flushed_batches.append(len(batch))

        batcher = AdaptiveBatcher(
            flush_callback=mock_flush,
            min_batch_size=10,
            max_batch_size=100,
            base_interval_secs=0.5,
        )

        test_records = [
            NetFlowRecord(
                timestamp=datetime.now(timezone.utc),
                timestamp_ms=1000,
                src_ip=f"10.0.0.{i}",
                dst_ip="192.168.1.1",
                next_hop="0.0.0.0",
                input_snmp=1,
                output_snmp=2,
                packets=1,
                bytes=64,
                first_switched=1000,
                last_switched=1000,
                src_port=1000 + i,
                dst_port=80,
                tcp_flags=2,
                protocol=6,
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
            )
            for i in range(25)
        ]

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(batcher.enqueue_batch(test_records))
        self.assertEqual(batcher.total_enqueued, 25)

        # Volcado forzado de pendientes
        loop.run_until_complete(batcher._flush_all_pending())
        self.assertEqual(len(flushed_batches), 1)
        self.assertEqual(flushed_batches[0], 25)
        self.assertEqual(batcher.total_flushed, 25)
        loop.close()

    def test_kafka_producer_and_consumer_fallback(self):
        from collector.parser import NetFlowRecord
        from datetime import datetime, timezone

        producer = KafkaFlowProducer(bootstrap_servers="localhost:9092", topic="novaflow.test.flows")
        test_records = [
            NetFlowRecord(
                timestamp=datetime.now(timezone.utc),
                timestamp_ms=1000,
                src_ip=f"10.0.0.{i}",
                dst_ip="192.168.1.1",
                next_hop="0.0.0.0",
                input_snmp=1,
                output_snmp=2,
                packets=1,
                bytes=64,
                first_switched=1000,
                last_switched=1000,
                src_port=1000 + i,
                dst_port=80,
                tcp_flags=2,
                protocol=6,
                tos=0,
                src_as=0,
                dst_as=0,
                src_mask=24,
                dst_mask=24,
            )
            for i in range(5)
        ]

        # Enviar flujos al buffer desacoplado
        producer.publish_flows(test_records, tenant_id="tenant-alpha")
        self.assertEqual(len(producer.fallback_buffer), 5)
        self.assertEqual(producer.fallback_buffer[0]["tenant_id"], "tenant-alpha")

    # 6. MEJORA ML (MODEL REGISTRY, EXPLAINABILITY, ONLINE LEARNER)
    def test_ml_model_registry_and_explainability(self):
        active_model = model_registry.get_active_model()
        self.assertIsNotNone(active_model)
        self.assertEqual(active_model.version, "v1.0.0")
        self.assertIn("accuracy_baseline", active_model.metrics)

        # 2. Explainability
        baseline = {
            "bytes": {"mean": 1000.0, "std": 500.0},
            "packets": {"mean": 10.0, "std": 5.0},
            "bytes_per_sec": {"mean": 2000.0, "std": 1000.0},
        }
        explanation = AnomalyExplainer.explain_anomaly(
            feature_names=["bytes", "packets", "bytes_per_sec"],
            current_values=[50_000_000.0, 10.0, 50_000_000.0],
            baseline_stats=baseline,
        )
        self.assertIn(explanation["primary_feature"], ["bytes", "bytes_per_sec"])
        self.assertGreater(explanation["feature_attributions"][explanation["primary_feature"]], 40.0)
        self.assertIn("human_explanation", explanation)

    def test_online_statistical_learner_updates(self):
        learner = OnlineDistributionLearner(alpha=0.1)

        for _ in range(10):
            learner.update_with_flow({"bytes": 1000.0, "packets": 10.0})

        stats = learner.get_distribution_stats()
        self.assertIn("bytes", stats)
        self.assertAlmostEqual(stats["bytes"]["mean"], 1000.0, delta=100.0)
        self.assertGreater(stats["bytes"]["std"], 0.0)


if __name__ == "__main__":
    unittest.main()
