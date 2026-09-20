"""
NovaFlow NDR - Automated Tests for Attack Graph & Blast Radius Engine
Valida el modelado de red G=(V,E), el algoritmo de Patient Zero y el cálculo de Blast Radius.
"""

from datetime import datetime, timezone, timedelta
import unittest
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from api.security.auth import JWTManager, Role
from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.graph import AttackGraphEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.profiler import AssetRole


class TestAttackGraphEngine(unittest.TestCase):
    def setUp(self):
        self.graph = AttackGraphEngine()
        self.now = datetime.now(timezone.utc)

    def _make_flow(
        self,
        src: str,
        dst: str,
        src_port: int = 49152,
        dst_port: int = 445,
        protocol: int = 6,
        bytes_count: int = 5000,
        packets_count: int = 10,
        delta_seconds: int = 0,
    ) -> NetFlowRecord:
        ts = self.now + timedelta(seconds=delta_seconds)
        return NetFlowRecord(
            timestamp=ts,
            timestamp_ms=int(ts.timestamp() * 1000),
            src_ip=src,
            dst_ip=dst,
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=packets_count,
            bytes=bytes_count,
            first_switched=1000,
            last_switched=2000,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=0x18,
            protocol=protocol,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )

    def test_flow_topology_aggregation(self):
        """Verifica que los flujos construyan nodos, aristas y grados correctamente."""
        f1 = self._make_flow("10.0.0.15", "10.0.0.20", dst_port=445, bytes_count=1000)
        f2 = self._make_flow("10.0.0.15", "10.0.0.20", dst_port=3389, bytes_count=2000)
        f3 = self._make_flow("10.0.0.15", "10.0.0.30", dst_port=80, bytes_count=500)

        self.graph.ingest_flow(f1)
        self.graph.ingest_flow(f2)
        self.graph.ingest_flow(f3)

        self.assertIn("10.0.0.15", self.graph.nodes)
        self.assertIn("10.0.0.20", self.graph.nodes)
        self.assertIn("10.0.0.30", self.graph.nodes)

        # Grados
        src_node = self.graph.nodes["10.0.0.15"]
        self.assertEqual(src_node.out_degree, 2)
        self.assertEqual(src_node.in_degree, 0)

        # Arista agregada
        edge = self.graph.edges[("10.0.0.15", "10.0.0.20")]
        self.assertEqual(edge.flow_count, 2)
        self.assertEqual(edge.total_bytes, 3000)
        self.assertIn(445, edge.dst_ports)
        self.assertIn(3389, edge.dst_ports)

    def test_alert_ingestion_and_compromise_tagging(self):
        """Verifica que las alertas eleven el riesgo y marquen los nodos comprometidos."""
        f = self._make_flow("10.0.0.50", "198.51.100.77", dst_port=443)
        self.graph.ingest_flow(f)

        alert = SecurityAlert(
            category=AlertCategory.MALICIOUS_C2,
            severity=AlertSeverity.CRITICAL,
            title="Conexión con C2",
            description="Beaconing a Cobalt Strike",
            src_ip="10.0.0.50",
            dst_ip="198.51.100.77",
            dst_port=443,
            protocol=6,
            confidence=0.98,
            timestamp=self.now,
        )
        self.graph.ingest_alert(alert)

        node = self.graph.nodes["10.0.0.50"]
        self.assertTrue(node.compromised)
        self.assertGreaterEqual(node.risk_score, 90.0)
        self.assertIn(alert.id, node.alert_ids)

        edge = self.graph.edges[("10.0.0.50", "198.51.100.77")]
        self.assertTrue(edge.has_c2_communication)

    def test_patient_zero_backtracking(self):
        """
        Simula una cadena de infección:
        Atacante / Paciente Cero (10.0.0.10) infecta a Host B (10.0.0.25) vía SMB.
        Host B (10.0.0.25) infecta al Domain Controller (10.0.0.100) vía WinRM.
        El algoritmo debe identificar a 10.0.0.10 como el Patient Zero de 10.0.0.100.
        """
        t0 = self.now
        t1 = t0 + timedelta(minutes=5)
        t2 = t0 + timedelta(minutes=10)

        # Flujo 1: Paciente Cero -> Host B
        f1 = self._make_flow("10.0.0.10", "10.0.0.25", dst_port=445)
        f1.timestamp = t1
        self.graph.ingest_flow(f1)

        alert1 = SecurityAlert(
            category=AlertCategory.LATERAL_MOVEMENT,
            severity=AlertSeverity.HIGH,
            title="Movimiento Lateral",
            description="Exploit SMB",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.25",
            dst_port=445,
            protocol=6,
            confidence=0.92,
            timestamp=t1,
        )
        self.graph.ingest_alert(alert1)

        # Flujo 2: Host B -> Domain Controller
        f2 = self._make_flow("10.0.0.25", "10.0.0.100", dst_port=5985)
        f2.timestamp = t2
        self.graph.ingest_flow(f2)

        # Marcar rol del DC
        dc_node = self.graph.get_or_create_node("10.0.0.100", role=AssetRole.INFRASTRUCTURE_DC)

        alert2 = SecurityAlert(
            category=AlertCategory.LATERAL_MOVEMENT,
            severity=AlertSeverity.CRITICAL,
            title="Ataque a DC",
            description="Compromiso de WinRM en Domain Controller",
            src_ip="10.0.0.25",
            dst_ip="10.0.0.100",
            dst_port=5985,
            protocol=6,
            confidence=0.96,
            timestamp=t2,
        )
        self.graph.ingest_alert(alert2)

        # Rastreo causal de Patient Zero para el Domain Controller
        pz_result = self.graph.find_patient_zero("10.0.0.100")
        self.assertIsNotNone(pz_result)
        self.assertEqual(pz_result["patient_zero_ip"], "10.0.0.10")
        self.assertEqual(pz_result["target_ip"], "10.0.0.100")
        self.assertEqual(pz_result["total_hops"], 2)
        self.assertEqual(pz_result["infection_path"], ["10.0.0.10", "10.0.0.25", "10.0.0.100"])
        self.assertFalse(pz_result["is_self_originating"])

    def test_blast_radius_calculation(self):
        """Valida que el cálculo de Blast Radius identifique activos críticos alcanzables y compute el score."""
        # Host A conecta a 3 Workstations y a un Domain Controller
        self.graph.get_or_create_node("10.0.0.10", role=AssetRole.WORKSTATION)
        self.graph.get_or_create_node("10.0.0.200", role=AssetRole.INFRASTRUCTURE_DC)
        self.graph.get_or_create_node("10.0.0.201", role=AssetRole.INTERNAL_SERVER)

        self.graph.ingest_flow(self._make_flow("10.0.0.10", "10.0.0.200", dst_port=88))   # Kerberos a DC
        self.graph.ingest_flow(self._make_flow("10.0.0.10", "10.0.0.201", dst_port=5432)) # DB Server
        self.graph.ingest_flow(self._make_flow("10.0.0.10", "10.0.0.30", dst_port=445))   # Workstation
        self.graph.ingest_flow(self._make_flow("10.0.0.10", "10.0.0.31", dst_port=445))   # Workstation

        blast = self.graph.calculate_blast_radius("10.0.0.10", max_depth=2)

        self.assertEqual(blast["start_ip"], "10.0.0.10")
        self.assertEqual(blast["reachable_hosts_count"], 4)
        self.assertGreater(blast["blast_score"], 30.0)

        critical_ips = [c["ip"] for c in blast["critical_assets_exposed"]]
        self.assertIn("10.0.0.200", critical_ips)
        self.assertIn("10.0.0.201", critical_ips)

    def test_topology_export_schema(self):
        """Valida que la exportación Cytoscape/D3 cumpla con el formato estándar."""
        self.graph.ingest_flow(self._make_flow("10.0.0.5", "10.0.0.6", dst_port=80))
        export = self.graph.export_topology_json()

        self.assertIn("nodes", export)
        self.assertIn("edges", export)
        self.assertIn("summary", export)

        self.assertGreaterEqual(len(export["nodes"]), 2)
        self.assertGreaterEqual(len(export["edges"]), 1)
        self.assertIn("data", export["nodes"][0])
        self.assertIn("data", export["edges"][0])


class TestAttackGraphAPI(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()
        system_state.initialize(self.engine)
        self.client = TestClient(app)
        self.token = JWTManager.create_token({"sub": "admin_user", "role": Role.ADMIN, "tenant_id": "*"})
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_api_graph_endpoints(self):
        """Prueba los endpoints REST de topología, blast radius y patient zero."""
        # Poblar topología con un flujo
        now = datetime.now(timezone.utc)
        flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=int(now.timestamp() * 1000),
            src_ip="10.0.5.10",
            dst_ip="10.0.5.20",
            next_hop="10.0.5.1",
            input_snmp=1,
            output_snmp=2,
            packets=15,
            bytes=1200,
            first_switched=1000,
            last_switched=2000,
            src_port=49200,
            dst_port=445,
            tcp_flags=0x18,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        self.engine.analyze_flow(flow)

        # 1. GET /api/v1/graph/topology
        res_topo = self.client.get("/api/v1/graph/topology", headers=self.headers)
        self.assertEqual(res_topo.status_code, 200)
        data_topo = res_topo.json()
        self.assertIn("nodes", data_topo)
        self.assertIn("edges", data_topo)
        self.assertGreaterEqual(len(data_topo["nodes"]), 2)

        # 2. GET /api/v1/graph/blast-radius/10.0.5.10
        res_blast = self.client.get("/api/v1/graph/blast-radius/10.0.5.10", headers=self.headers)
        self.assertEqual(res_blast.status_code, 200)
        data_blast = res_blast.json()
        self.assertEqual(data_blast["start_ip"], "10.0.5.10")
        self.assertIn("blast_score", data_blast)

        # 3. GET /api/v1/graph/patient-zero/10.0.5.20
        res_pz = self.client.get("/api/v1/graph/patient-zero/10.0.5.20", headers=self.headers)
        self.assertEqual(res_pz.status_code, 200)
        data_pz = res_pz.json()
        self.assertEqual(data_pz["target_ip"], "10.0.5.20")


if __name__ == "__main__":
    unittest.main()
