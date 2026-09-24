"""
NovaFlow NDR x OmniBreach - Automated Tests for Purple Team Contract & Benchmark
Valida el contrato formal de telemetría v1.0, la propagación de campaign_id,
el cálculo empírico de métricas (TP, FP, FN, MTTD) y los endpoints API correspondientes.
"""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from schemas.purple_team import (
    PurpleTeamCampaign,
    PurpleTeamEvent,
    VectorEvaluationResult,
    PurpleBenchmarkMetrics,
)
from scripts.run_purple_benchmark import run_benchmark, build_canonical_campaign


class TestPurpleTeamContract(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)
        self.admin_headers = {"X-API-Key": "novaflow-admin-key-9988"}
        self.now = datetime.now(timezone.utc)

    def test_purple_team_event_dataclass_and_serialization(self):
        """Valida que PurpleTeamEvent almacene y serialice metadatos de campaña conforme a v1.0."""
        event = PurpleTeamEvent(
            campaign_id="camp_test_01",
            vector_id="OB-TEST-01",
            vector_name="Test Offensive Vector",
            phase="Reconnaissance",
            mitre_technique="T1046",
            mitre_tactic="Discovery",
            attacker_ip="10.0.50.15",
            target_ip="10.0.0.10",
            target_port=80,
            expected_detector="PortScanDetector",
            expected_severity="MEDIUM",
        )
        d = event.to_dict()
        self.assertEqual(d["campaign_id"], "camp_test_01")
        self.assertEqual(d["vector_id"], "OB-TEST-01")
        self.assertEqual(d["mitre_technique"], "T1046")
        self.assertEqual(d["schema_version"], "1.0.0")

        # Reconstrucción desde diccionario
        reconstructed = PurpleTeamEvent.from_dict(d)
        self.assertEqual(reconstructed.vector_id, event.vector_id)
        self.assertEqual(reconstructed.attacker_ip, event.attacker_ip)

    def test_campaign_dataclass(self):
        """Valida el agrupador de campaña PurpleTeamCampaign."""
        campaign, flows_dict = build_canonical_campaign("camp_unit_test")
        self.assertEqual(campaign.campaign_id, "camp_unit_test")
        self.assertEqual(len(campaign.events), 4)
        self.assertEqual(len(flows_dict), 4)
        c_dict = campaign.to_dict()
        self.assertEqual(c_dict["events_count"], 4)
        self.assertEqual(c_dict["schema_version"], "1.0.0")

    def test_netflow_record_campaign_fields(self):
        """Valida que NetFlowRecord contenga y preserve campaign_id y vector_id."""
        rec = NetFlowRecord(
            timestamp=self.now,
            timestamp_ms=1000,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            next_hop="0.0.0.0",
            input_snmp=1,
            output_snmp=2,
            packets=5,
            bytes=500,
            first_switched=100,
            last_switched=200,
            src_port=1234,
            dst_port=80,
            tcp_flags=2,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id="camp_alpha",
            vector_id="OB-RECON-01",
        )
        self.assertEqual(rec.campaign_id, "camp_alpha")
        self.assertEqual(rec.vector_id, "OB-RECON-01")

    def test_alert_campaign_propagation_and_cef(self):
        """Valida que DetectionEngine propague campaign_id y vector_id a las alertas y a CEF."""
        rec = NetFlowRecord(
            timestamp=self.now,
            timestamp_ms=int(self.now.timestamp() * 1000),
            src_ip="10.0.0.15",
            dst_ip="198.51.100.77",  # IOC Cobalt Strike catalogado
            next_hop="0.0.0.0",
            input_snmp=1,
            output_snmp=2,
            packets=10,
            bytes=1200,
            first_switched=0,
            last_switched=1000,
            src_port=50000,
            dst_port=443,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            campaign_id="camp_cef_test",
            vector_id="OB-C2-04",
        )
        alerts = self.engine.analyze_flow(rec)
        self.assertTrue(len(alerts) >= 1)
        alert = alerts[0]
        self.assertEqual(alert.campaign_id, "camp_cef_test")
        self.assertEqual(alert.vector_id, "OB-C2-04")

        # Validar en to_dict
        ad = alert.to_dict()
        self.assertEqual(ad["campaign_id"], "camp_cef_test")
        self.assertEqual(ad["vector_id"], "OB-C2-04")

        # Validar en to_cef
        cef = alert.to_cef()
        self.assertIn("cs4=camp_cef_test", cef)
        self.assertIn("cs4Label=CampaignId", cef)
        self.assertIn("cs5=OB-C2-04", cef)
        self.assertIn("cs5Label=VectorId", cef)

    def test_benchmark_metrics_derived_calculations(self):
        """Valida que el cálculo de métricas (Precision, Recall, F1, MTTD) sea matemáticamente exacto."""
        m = PurpleBenchmarkMetrics(
            campaign_id="test_calc",
            total_vectors_tested=4,
            true_positives=4,
            false_negatives=0,
            false_positives=0,
            true_negatives=1000,
            total_background_flows=1000,
            total_flows_processed=1004,
            duration_seconds=0.5,
            vector_results=[
                VectorEvaluationResult(
                    campaign_id="test_calc",
                    vector_id="V1",
                    vector_name="V1",
                    mitre_technique="T1046",
                    expected_detector="D1",
                    expected_severity="MEDIUM",
                    detected=True,
                    severity_matched=True,
                    mttd_ms=10.0,
                ),
                VectorEvaluationResult(
                    campaign_id="test_calc",
                    vector_id="V2",
                    vector_name="V2",
                    mitre_technique="T1048",
                    expected_detector="D2",
                    expected_severity="HIGH",
                    detected=True,
                    severity_matched=True,
                    mttd_ms=20.0,
                ),
            ],
        )
        m.calculate_derived_metrics()
        self.assertEqual(m.precision, 1.0)
        self.assertEqual(m.recall, 1.0)
        self.assertEqual(m.f1_score, 1.0)
        self.assertEqual(m.mean_mttd_ms, 15.0)
        self.assertEqual(m.min_mttd_ms, 10.0)
        self.assertEqual(m.max_mttd_ms, 20.0)
        self.assertEqual(m.throughput_fps, 2008.0)

    def test_run_benchmark_integration(self):
        """Valida que run_benchmark() ejecute una prueba cuantitativa con ruido de fondo."""
        metrics = run_benchmark(background_count=200, seed=99)
        self.assertEqual(metrics.total_vectors_tested, 4)
        self.assertEqual(metrics.true_positives, 4)
        self.assertEqual(metrics.false_negatives, 0)
        self.assertGreater(metrics.total_flows_processed, 200)
        self.assertGreater(metrics.mean_mttd_ms, 0.0)
        self.assertGreater(metrics.throughput_fps, 100.0)

    def test_api_contract_and_benchmark_endpoints(self):
        """Valida los endpoints REST /api/v1/purple-team/contract y /benchmark."""
        # 1. GET /contract
        r_contract = self.client.get("/api/v1/purple-team/contract")
        self.assertEqual(r_contract.status_code, 200)
        data_c = r_contract.json()
        self.assertEqual(data_c["contract_version"], "1.0.0")
        self.assertIn("campaign_template", data_c)
        self.assertEqual(len(data_c["supported_vectors"]), 4)

        # 2. POST /benchmark
        r_bench = self.client.post(
            "/api/v1/purple-team/benchmark",
            json={"background_flows": 150, "seed": 42},
            headers=self.admin_headers,
        )
        self.assertEqual(r_bench.status_code, 200)
        data_b = r_bench.json()
        self.assertEqual(data_b["total_vectors_tested"], 4)
        self.assertEqual(data_b["true_positives"], 4)
        self.assertEqual(data_b["precision"], 1.0)
        self.assertIn("mttd_ms", data_b)

    def test_telemetry_hook_with_campaign_id(self):
        """Valida que el endpoint /api/v1/telemetry/hook acepte campaign_id y lo preserve en la alerta."""
        payload = {
            "src_ip": "10.0.0.15",
            "dst_ip": "198.51.100.77",
            "src_port": 49000,
            "dst_port": 443,
            "protocol": 6,
            "bytes": 2000,
            "packets": 15,
            "tcp_flags": 24,
            "campaign_id": "camp_hook_99",
            "vector_id": "OB-C2-04",
        }
        r = self.client.post("/api/v1/telemetry/hook", json=payload, headers=self.admin_headers)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["success"])
        self.assertGreater(data["alerts_count"], 0)
        alert = data["alerts"][0]
        self.assertEqual(alert["campaign_id"], "camp_hook_99")
        self.assertEqual(alert["vector_id"], "OB-C2-04")


if __name__ == "__main__":
    unittest.main()
