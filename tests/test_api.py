"""
NovaFlow NDR - API Gateway & WebSockets Test Suite (Phase 3)
Valida los endpoints REST de telemetría, gestión de incidentes y streaming por WebSockets.
"""

import unittest
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.engine import DetectionEngine


class TestNovaFlowAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        engine = DetectionEngine()
        system_state.initialize(engine)
        cls.client = TestClient(app)

    def test_root_catalog(self):
        """Valida que el endpoint raíz responda con el catálogo de servicios."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "OPERATIONAL")
        self.assertIn("endpoints", data)
        self.assertIn("dashboard", data["endpoints"])
        self.assertIn("metrics_overview", data["endpoints"])
        self.assertIn("websocket_stream", data["endpoints"])

    def test_dashboard_html_view(self):
        """Valida que el endpoint /dashboard sirva la interfaz web del SOC."""
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("NOVAFLOW", response.text)

    def test_metrics_overview(self):
        """Valida el endpoint de pulso de red y telemetría general."""
        response = self.client.get("/api/v1/metrics/overview")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("network_pulse", data)
        self.assertIn("current_mbps", data["network_pulse"])
        self.assertIn("stats", data)

    def test_metrics_protocols_and_top_talkers(self):
        """Valida los endpoints de distribución de protocolos y top talkers."""
        resp_proto = self.client.get("/api/v1/metrics/protocols")
        self.assertEqual(resp_proto.status_code, 200)
        self.assertIsInstance(resp_proto.json(), list)

        resp_talkers = self.client.get("/api/v1/metrics/top-talkers")
        self.assertEqual(resp_talkers.status_code, 200)
        self.assertIsInstance(resp_talkers.json(), list)

    def test_alerts_lifecycle(self):
        """Valida la consulta, filtrado y actualización de incidentes."""
        # Inyectar alerta de prueba en el motor
        test_alert = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.PORT_SCAN,
            title="Alerta de Prueba API",
            src_ip="192.168.1.99",
            dst_ip="10.0.0.5",
            dst_port=80,
            confidence=0.91,
        )
        if system_state.engine:
            system_state.engine._record_alert(test_alert)

        # Consultar listado
        resp = self.client.get("/api/v1/alerts")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total"], 1)

        # Filtrar por severidad
        resp_filtered = self.client.get("/api/v1/alerts?severity=HIGH")
        self.assertEqual(resp_filtered.status_code, 200)
        for a in resp_filtered.json()["alerts"]:
            self.assertEqual(a["severity"], "HIGH")

        # Consultar detalle por ID
        resp_detail = self.client.get(f"/api/v1/alerts/{test_alert.alert_id}")
        self.assertEqual(resp_detail.status_code, 200)
        self.assertEqual(resp_detail.json()["alert_id"], test_alert.alert_id)

        # Actualizar estado a INVESTIGATING
        resp_patch = self.client.patch(
            f"/api/v1/alerts/{test_alert.alert_id}/status",
            json={"status": "INVESTIGATING"},
        )
        self.assertEqual(resp_patch.status_code, 200)
        self.assertEqual(resp_patch.json()["alert"]["status"], "INVESTIGATING")

    def test_forensic_flows_explorer(self):
        """Valida el buscador de flujos forenses."""
        # Agregar flujos simulados
        system_state.recent_flows.append({
            "timestamp": "2026-09-10T10:00:00Z",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.2",
            "src_port": 51234,
            "dst_port": 22,
            "protocol": 6,
            "protocol_name": "TCP",
            "packets": 15,
            "bytes": 2400,
            "tcp_flags": 0x10,
        })

        resp = self.client.get("/api/v1/flows?port=22")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total_matched"], 1)
        self.assertEqual(data["flows"][0]["dst_port"], 22)

    def test_websocket_stream_handshake_and_ping(self):
        """Valida el protocolo de conexión WebSocket y respuesta en tiempo real."""
        with self.client.websocket_connect("/ws/stream") as websocket:
            # 1. Verificar handshake inicial
            initial_msg = websocket.receive_json()
            self.assertEqual(initial_msg["type"], "CONNECTION_ESTABLISHED")
            self.assertIn("data", initial_msg)
            self.assertIn("current_mbps", initial_msg["data"])

            # 2. Ping-Pong
            websocket.send_text("ping")
            reply = websocket.receive_text()
            self.assertEqual(reply, "pong")

    def test_alerts_export_cef_and_syslog(self):
        """Valida que los endpoints de exportación /alerts/export/cef y /alerts/export/syslog respondan con texto plano estándar."""
        resp_cef = self.client.get("/api/v1/alerts/export/cef")
        self.assertEqual(resp_cef.status_code, 200)
        self.assertIn("text/plain", resp_cef.headers["content-type"])
        # Si hay alertas, debe contener la firma CEF:0
        if resp_cef.text.strip():
            self.assertIn("CEF:0|NovaSec|NovaFlow", resp_cef.text)

        resp_syslog = self.client.get("/api/v1/alerts/export/syslog")
        self.assertEqual(resp_syslog.status_code, 200)
        self.assertIn("text/plain", resp_syslog.headers["content-type"])
        if resp_syslog.text.strip():
            self.assertIn("novaflow-ndr", resp_syslog.text)


if __name__ == "__main__":
    unittest.main()
