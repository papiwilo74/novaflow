"""
NovaFlow NDR - Kubernetes Operator & Cloud-Native Test Suite
Valida los 3 Sprints de Cloud-Native:
1. Reconciliación de NovaFlowCluster CRD y generación de manifiestos K8s.
2. Health Probes nativos (/healthz, /livez, /readyz).
3. Sistema de Plugins dinámicos en caliente (NovaFlowPlugin).
4. Federación Multi-Cluster (agregación de telemetría multi-región).
"""

import unittest
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from api.federation.manager import federation_manager, ManagedClusterNode
from api.security.auth import JWTManager, Role
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.plugins import plugin_manager, BaseDetectorPlugin
from collector.parser import NetFlowRecord
from datetime import datetime, timezone

from k8s_operator.models import NovaFlowClusterSpec, NovaFlowPluginSpec
from k8s_operator.manifests_builder import ManifestsBuilder
from k8s_operator.controller import NovaFlowOperator, MockK8sClient


class TestKubernetesOperator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        system_state.initialize(cls.engine)
        cls.client = TestClient(app)

    # -------------------------------------------------------------
    # SPRINT 1: CRD, MANIFESTS BUILDER & CONTROLLER
    # -------------------------------------------------------------
    def test_manifests_builder_generates_valid_k8s_resources(self):
        """Valida que ManifestsBuilder genere Deployments, Services y StatefulSets conformes a Kubernetes."""
        builder = ManifestsBuilder(cluster_name="nf-prod", namespace="security-soc")
        spec = NovaFlowClusterSpec(
            version="1.0.0",
            workers={"replicas": 4, "udp_port": 2055, "batch_size": 10000},
            api={"replicas": 3, "service_type": "LoadBalancer"},
            clickhouse={"replicas": 1, "retention_days": 90, "storage_size": "200Gi"},
        )

        manifests = builder.build_all(spec)
        self.assertEqual(len(manifests), 5)

        kinds = [m["kind"] for m in manifests]
        self.assertIn("Deployment", kinds)
        self.assertIn("Service", kinds)
        self.assertIn("StatefulSet", kinds)

        # Validar API Deployment
        api_dep = next(m for m in manifests if m["kind"] == "Deployment" and m["metadata"]["name"] == "nf-prod-api")
        self.assertEqual(api_dep["spec"]["replicas"], 3)
        self.assertEqual(api_dep["spec"]["strategy"]["type"], "RollingUpdate")
        self.assertEqual(api_dep["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"], 0)

        # Validar Workers UDP Service
        udp_svc = next(m for m in manifests if m["kind"] == "Service" and m["metadata"]["name"] == "nf-prod-collector-udp")
        self.assertEqual(udp_svc["spec"]["type"], "LoadBalancer")
        self.assertEqual(udp_svc["spec"]["ports"][0]["protocol"], "UDP")
        self.assertEqual(udp_svc["spec"]["ports"][0]["port"], 2055)

    def test_operator_cluster_reconciliation_lifecycle(self):
        """Valida el ciclo de vida del reconciliador del operador para NovaFlowCluster."""
        mock_k8s = MockK8sClient()
        op = NovaFlowOperator(k8s_client=mock_k8s)

        spec_data = {
            "version": "1.0.0",
            "workers": {"replicas": 2, "udp_port": 2055},
            "api": {"replicas": 2},
            "clickhouse": {"replicas": 1, "retention_days": 90},
        }

        status = op.reconcile_cluster(name="soc-cluster", namespace="novaflow", spec_dict=spec_data)
        self.assertEqual(status.phase, "Running")
        self.assertEqual(status.workers_ready, 2)
        self.assertEqual(status.api_ready, 2)
        self.assertEqual(status.clickhouse_status, "Ready")

        # Verificar que los objetos fueron persistidos en el cliente K8s
        ch_sts = mock_k8s.get("StatefulSet", "novaflow", "soc-cluster-clickhouse")
        self.assertIsNotNone(ch_sts)
        api_dep = mock_k8s.get("Deployment", "novaflow", "soc-cluster-api")
        self.assertIsNotNone(api_dep)

    # -------------------------------------------------------------
    # SPRINT 1: HEALTH PROBES
    # -------------------------------------------------------------
    def test_kubernetes_health_probes(self):
        """Valida los endpoints nativos de Kubernetes /healthz, /livez y /readyz."""
        resp_live = self.client.get("/livez")
        self.assertEqual(resp_live.status_code, 200)
        self.assertEqual(resp_live.json()["status"], "ALIVE")

        resp_health = self.client.get("/healthz")
        self.assertEqual(resp_health.status_code, 200)
        self.assertEqual(resp_health.json()["status"], "ALIVE")

        resp_ready = self.client.get("/readyz")
        self.assertEqual(resp_ready.status_code, 200)
        data_ready = resp_ready.json()
        self.assertEqual(data_ready["status"], "READY")
        self.assertIn("components", data_ready)
        self.assertEqual(data_ready["components"]["detection_engine"], "READY")

    # -------------------------------------------------------------
    # SPRINT 1: SISTEMA DE PLUGINS DINÁMICOS EN CALIENTE
    # -------------------------------------------------------------
    def test_dynamic_plugin_injection_without_restart(self):
        """Valida que un Custom Resource NovaFlowPlugin compile y ejecute un nuevo detector en caliente."""
        custom_plugin_code = '''
from detector.plugins import BaseDetectorPlugin
from detector.models import SecurityAlert, AlertCategory, AlertSeverity

class CryptominerDetector(BaseDetectorPlugin):
    def evaluate(self, flow):
        # Detectar puertos conocidos de minería Stratum Monero (3333, 4444)
        if flow.dst_port in (3333, 4444):
            return SecurityAlert(
                severity=self.severity,
                category=self.category,
                title="Detección de Minería de Criptomonedas (Stratum)",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                confidence=0.95,
            )
        return None
'''
        op = NovaFlowOperator()
        plugin_spec = {
            "plugin_name": "cryptominer-stratum",
            "category": "ANOMALY_ML",
            "severity": "HIGH",
            "python_code": custom_plugin_code,
            "enabled": True,
        }

        # Reconciliar plugin con el operador
        status = op.reconcile_plugin(name="cryptominer-stratum", namespace="novaflow", spec_dict=plugin_spec)
        self.assertTrue(status.loaded)
        self.assertIsNone(status.last_error)

        # Probar análisis de flujo contra el nuevo detector inyectado
        mining_flow = NetFlowRecord(
            timestamp=datetime.now(timezone.utc),
            timestamp_ms=1000,
            src_ip="192.168.1.100",
            dst_ip="198.51.100.99",
            next_hop="0.0.0.0",
            input_snmp=1,
            output_snmp=2,
            packets=10,
            bytes=1500,
            first_switched=1000,
            last_switched=1000,
            src_port=55123,
            dst_port=3333,  # Stratum port
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

        alerts = self.engine.analyze_flow(mining_flow)
        mining_alerts = [a for a in alerts if "Minería de Criptomonedas" in a.title]
        self.assertGreaterEqual(len(mining_alerts), 1)
        self.assertEqual(mining_alerts[0].dst_port, 3333)

        # Cleanup del plugin
        plugin_manager.unregister_plugin("cryptominer-stratum")

    # -------------------------------------------------------------
    # SPRINT 3: FEDERACIÓN MULTI-CLUSTER
    # -------------------------------------------------------------
    def test_multi_cluster_federation_endpoint(self):
        """Valida la agregación de métricas de clusters distribuidos geográficamente."""
        admin_token = JWTManager.create_token({
            "sub": "global-ciso",
            "role": Role.ADMIN,
            "tenant_id": "*",
        })

        resp = self.client.get(
            "/api/v1/federation/clusters",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertGreaterEqual(data["total_clusters"], 3)
        self.assertGreater(data["global_throughput_mbps"], 1000.0)
        self.assertIn("clusters", data)

        regions = [c["region"] for c in data["clusters"]]
        self.assertIn("us-east-1", regions)
        self.assertIn("eu-west-1", regions)
        self.assertIn("ap-southeast-1", regions)


if __name__ == "__main__":
    unittest.main()
