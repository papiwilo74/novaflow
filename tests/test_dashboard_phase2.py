"""
NovaFlow NDR - Test Suite for Phase 2: Enterprise 360° SOC Command Center Dashboard.
Verifica la integridad del panel web (api/static/index.html) y la correspondencia
entre los esquemas de datos del backend (Campañas Kill Chain, Asset Ledger, Mitigación SDN)
y las funciones controladoras del frontend.
"""

import os
import re
import unittest

from detector.campaign_correlator import (
    BayesianCampaignEngine,
    KillChainStage,
    map_alert_to_stage,
)
from detector.edge_mitigation import (
    BGPFlowspecAction,
    BGPFlowspecGenerator,
    BGPFlowspecRule,
    CloudNativeZeroTrustGenerator,
)
from detector.entity import AssetEntity, AssetRole, EntityLedger
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class TestDashboardPhase2(unittest.TestCase):
    """Batería de verificación integral de Fase 2: SOC Command Center & Integración UI."""

    @classmethod
    def setUpClass(cls):
        cls.html_path = os.path.join(
            os.path.dirname(__file__), "..", "api", "static", "index.html"
        )
        with open(cls.html_path, "r", encoding="utf-8") as f:
            cls.html_content = f.read()

    def test_navigation_tabs_exist(self):
        """Verifica que los tres nuevos botones de navegación existan en el header."""
        self.assertIn('id="tab-campaigns"', self.html_content)
        self.assertIn('id="tab-entities"', self.html_content)
        self.assertIn('id="tab-mitigation"', self.html_content)

    def test_view_sections_exist(self):
        """Verifica que las tres secciones de vista existan con sus identificadores de contenedor."""
        self.assertIn('id="view-campaigns"', self.html_content)
        self.assertIn('id="view-entities"', self.html_content)
        self.assertIn('id="view-mitigation"', self.html_content)

    def test_ui_elements_and_inputs_exist(self):
        """Verifica la presencia de los elementos interactivos clave para cada vista."""
        # Vista 9: Campañas
        self.assertIn('id="stat-campaigns-total"', self.html_content)
        self.assertIn('id="stat-campaigns-active"', self.html_content)
        self.assertIn('id="stat-campaigns-avg-prob"', self.html_content)
        self.assertIn('id="stat-campaigns-critical"', self.html_content)
        self.assertIn('id="campaigns-container"', self.html_content)

        # Vista 10: Activos & DHCP
        self.assertIn('id="stat-entities-total"', self.html_content)
        self.assertIn('id="stat-entities-critical-servers"', self.html_content)
        self.assertIn('id="stat-entities-avg-score"', self.html_content)
        self.assertIn('id="stat-entities-high-risk"', self.html_content)
        self.assertIn('id="dhcp-mac-input"', self.html_content)
        self.assertIn('id="dhcp-ip-input"', self.html_content)
        self.assertIn('id="dhcp-host-input"', self.html_content)
        self.assertIn('id="entities-tbody"', self.html_content)

        # Vista 11: Mitigación SDN
        self.assertIn('id="mit-src-ip"', self.html_content)
        self.assertIn('id="mit-dst-ip"', self.html_content)
        self.assertIn('id="mit-dst-port"', self.html_content)
        self.assertIn('id="mit-protocol"', self.html_content)
        self.assertIn('id="mit-action"', self.html_content)
        self.assertIn('id="mit-k8s-ns"', self.html_content)
        self.assertIn('id="mitigation-code-display"', self.html_content)

    def test_switch_tab_includes_all_views(self):
        """Verifica que switchTab controle las 11 vistas del sistema NovaFlow."""
        expected_views = [
            'overview', 'talkers', 'incidents', 'flows',
            'purple', 'mitre', 'graph', 'copilot',
            'campaigns', 'entities', 'mitigation'
        ]
        for view in expected_views:
            pattern = rf"['\"]\b{view}\b['\"]"
            self.assertTrue(
                re.search(pattern, self.html_content),
                f"La vista {view} debe estar registrada en switchTab",
            )

    def test_javascript_controller_functions_exist(self):
        """Verifica que todas las funciones controladoras requeridas existan en el bloque script."""
        required_functions = [
            "loadCampaigns",
            "updateCampaignStatus",
            "containCampaign",
            "loadEntities",
            "updateEntityRole",
            "submitDhcpLease",
            "prepareMitigationForIp",
            "locateEntityOnGraph",
            "generateAllMitigations",
            "switchMitigationSyntax",
            "renderActiveMitigationCode",
            "copyActiveMitigationSyntax",
            "mitigateCurrentModalAlert",
        ]
        for func_name in required_functions:
            self.assertIn(
                f"function {func_name}",
                self.html_content,
                f"Falta la función {func_name} en index.html",
            )

    def test_campaign_data_binding_contract(self):
        """Verifica que el schema retornado por CampaignCase.to_dict() contenga todas las propiedades usadas en el render de UI."""
        engine = BayesianCampaignEngine()
        a1 = SecurityAlert(
            category=AlertCategory.PORT_SCAN,
            severity=AlertSeverity.MEDIUM,
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
        )
        case, _ = engine.ingest_alert(a1)
        self.assertIsNotNone(case)
        data = case.to_dict()

        # Claves esperadas por loadCampaigns()
        expected_keys = [
            "campaign_id",
            "primary_asset",
            "involved_assets",
            "total_alerts",
            "stages",
            "bayesian_probability",
            "status",
            "created_at",
            "recent_alerts",
        ]
        for k in expected_keys:
            self.assertIn(k, data, f"Campo {k} ausente en CampaignCase.to_dict()")

    def test_entity_data_binding_contract(self):
        """Verifica que AssetEntity.to_dict() suministre todos los atributos consumidos por el render de tabla."""
        entity = AssetEntity(
            current_ip="10.0.0.5",
            mac_address="00:1A:2B:3C:4D:5E",
            hostname="WS-FINANCE-01",
            role=AssetRole.DOMAIN_CONTROLLER,
        )
        entity.raw_threat_score = 40.0
        data = entity.to_dict()

        expected_keys = [
            "entity_id",
            "current_ip",
            "mac_address",
            "hostname",
            "role",
            "role_multiplier",
            "threat_score",
            "alerts_count",
        ]
        for k in expected_keys:
            self.assertIn(k, data, f"Campo {k} ausente en AssetEntity.to_dict()")

        # Validar decaimiento y multiplicador
        self.assertEqual(data["role_multiplier"], 2.5)
        self.assertGreaterEqual(data["threat_score"], 90.0)

    def test_mitigation_generator_contracts(self):
        """Verifica que los generadores de BGP Flowspec y Cloud-Native generen sintaxis multi-vendor válidas."""
        rule = BGPFlowspecRule(
            src_prefix="203.0.113.10",
            dst_prefix="10.0.0.1",
            protocol=6,
            dst_port=445,
            action=BGPFlowspecAction.DROP_TRAFFIC,
        )
        exabgp = rule.to_exabgp()
        juniper = rule.to_juniper_junos()
        cisco = rule.to_cisco_iosxr()

        self.assertIn("flow route", exabgp)
        self.assertIn("rate-limit 0", exabgp)
        self.assertIn("routing-options flow route", juniper)
        self.assertIn("then discard", juniper)
        self.assertIn("class-map type traffic match-all", cisco)
        self.assertIn("drop", cisco)

        # Cloud-Native
        cilium_yaml = CloudNativeZeroTrustGenerator.generate_cilium_quarantine_policy(
            target_ip="203.0.113.10",
            namespace="production",
            incident_id="INC-PHASE2",
        )
        k8s_yaml = CloudNativeZeroTrustGenerator.generate_k8s_network_policy(
            pod_label_key="io.kubernetes.pod.ip",
            pod_label_val="203.0.113.10",
            namespace="production",
        )
        self.assertIn("CiliumNetworkPolicy", cilium_yaml)
        self.assertIn("novaflow-forensics-agent", cilium_yaml)
        self.assertIn("egress:", cilium_yaml)
        self.assertIn("NetworkPolicy", k8s_yaml)


if __name__ == "__main__":
    unittest.main()
