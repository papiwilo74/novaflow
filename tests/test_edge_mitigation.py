"""
Pruebas unitarias para el Pilar 4: Mitigación Activa en Borde BGP Flowspec (RFC 5575) y Políticas Zero-Trust.
"""

import unittest
from starlette.testclient import TestClient

from api.main import app
from api.security.auth import JWTManager, Role
from detector.edge_mitigation import (
    BGPFlowspecAction,
    BGPFlowspecGenerator,
    BGPFlowspecRule,
    CloudNativeZeroTrustGenerator,
)
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestEdgeMitigation(unittest.TestCase):
    """Batería de validación de mitigación en borde con BGP Flowspec y Zero-Trust Kubernetes."""

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

    def test_bgp_flowspec_exabgp_syntax(self):
        """Valida que la regla genere sintaxis canónica para el demonio ExaBGP."""
        rule = BGPFlowspecRule(
            src_prefix="198.51.100.77",
            dst_prefix="10.0.0.10",
            protocol=6,
            dst_port=443,
            action=BGPFlowspecAction.DROP_TRAFFIC,
        )
        cmd = rule.to_exabgp()
        self.assertIn("announce flow route", cmd)
        self.assertIn("source 198.51.100.77/32;", cmd)
        self.assertIn("destination 10.0.0.10/32;", cmd)
        self.assertIn("protocol tcp;", cmd)
        self.assertIn("destination-port =443;", cmd)
        self.assertIn("rate-limit 0;", cmd)

    def test_bgp_flowspec_junos_and_iosxr_syntax(self):
        """Valida que la regla genere configuraciones válidas para Juniper Junos y Cisco IOS-XR."""
        rule = BGPFlowspecRule(
            dst_prefix="10.0.0.80",
            protocol=6,
            dst_port=80,
            tcp_flags="SYN",
            action=BGPFlowspecAction.DROP_TRAFFIC,
        )
        junos = rule.to_juniper_junos()
        self.assertIn("set routing-options flow route", junos)
        self.assertIn("destination 10.0.0.80/32", junos)
        self.assertIn("protocol tcp", junos)
        self.assertIn("then discard", junos)

        iosxr = rule.to_cisco_iosxr()
        self.assertIn("class-map type traffic match-all", iosxr)
        self.assertIn("match destination-address ipv4 10.0.0.80/32", iosxr)
        self.assertIn("policy-map type pbr", iosxr)
        self.assertIn("drop", iosxr)

    def test_bgp_flowspec_generation_from_alert(self):
        """Verifica la deducción automática de parámetros BGP Flowspec desde una alerta SYN Flood."""
        alert_syn = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.SYN_FLOOD,
            dst_ip="10.0.0.80",
            dst_port=80,
            protocol=6,
        )
        rule = BGPFlowspecGenerator.generate_from_alert(alert_syn)
        self.assertEqual(rule.dst_prefix, "10.0.0.80")
        self.assertEqual(rule.dst_port, 80)
        self.assertEqual(rule.tcp_flags, "SYN")
        self.assertEqual(rule.action, BGPFlowspecAction.DROP_TRAFFIC)

    def test_cloud_native_zero_trust_generation(self):
        """Valida la generación de manifiestos YAML para Cilium y Kubernetes NetworkPolicy."""
        cilium_yaml = CloudNativeZeroTrustGenerator.generate_cilium_quarantine_policy(
            target_ip="10.244.2.15",
            namespace="security-zone",
            incident_id="INC-TEST-99",
        )
        self.assertIn("kind: CiliumNetworkPolicy", cilium_yaml)
        self.assertIn('io.kubernetes.pod.ip: "10.244.2.15"', cilium_yaml)
        self.assertIn("toEntities:", cilium_yaml)
        self.assertIn("- none", cilium_yaml)

        k8s_yaml = CloudNativeZeroTrustGenerator.generate_k8s_network_policy(
            pod_label_key="security.zone",
            pod_label_val="isolated-pod",
            namespace="production",
        )
        self.assertIn("kind: NetworkPolicy", k8s_yaml)
        self.assertIn("security.zone: \"isolated-pod\"", k8s_yaml)
        self.assertIn("- Ingress", k8s_yaml)
        self.assertIn("- Egress", k8s_yaml)

    def test_mitigation_api_endpoints(self):
        """Verifica la API REST de mitigación activa de borde y cloud-native."""
        with TestClient(app) as client:
            # 1. BGP Flowspec endpoint
            res_bgp = client.post(
                "/api/v1/mitigation/bgp-flowspec",
                json={
                    "src_ip": "194.26.29.112",
                    "dst_ip": "10.0.0.5",
                    "protocol": 6,
                    "dst_port": 443,
                    "action": "DROP_TRAFFIC",
                },
                headers=self.auth_headers,
            )
            self.assertEqual(res_bgp.status_code, 200)
            data_bgp = res_bgp.json()
            self.assertIn("exabgp_syntax", data_bgp)
            self.assertIn("juniper_junos_syntax", data_bgp)
            self.assertIn("cisco_iosxr_syntax", data_bgp)

            # 2. Cloud Native endpoint
            res_cn = client.post(
                "/api/v1/mitigation/cloud-native",
                json={
                    "target_ip": "10.244.5.88",
                    "namespace": "finance",
                    "incident_id": "INC-8899",
                },
                headers=self.auth_headers,
            )
            self.assertEqual(res_cn.status_code, 200)
            data_cn = res_cn.json()
            self.assertIn("cilium_network_policy_yaml", data_cn)
            self.assertIn("kubernetes_network_policy_yaml", data_cn)


if __name__ == "__main__":
    unittest.main()
