"""
NovaFlow NDR - Tests para Sonda de Red Local en Vivo (Live Flow Probe) y Hooks REST
Valida el funcionamiento de tools/live_probe.py en modo Target, Relay y la API de Telemetría.
"""

import http.server
import json
import threading
import time
import unittest
import urllib.request
from typing import List

from fastapi.testclient import TestClient

from api.main import app
from api.state import system_state
from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from tools.live_probe import FlowAggregator, NetFlowEmitter, TargetHTTPRequestHandler


class DummyNetFlowEmitter(NetFlowEmitter):
    """Emisor mock que almacena los flujos en memoria para aserciones de prueba."""

    def __init__(self):
        super().__init__("127.0.0.1", 2055)
        self.emitted_flows: List[NetFlowRecord] = []

    def send_flows(self, flows: List[NetFlowRecord]):
        self.emitted_flows.extend(flows)


class TestLiveProbeAndTelemetry(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        system_state.initialize(cls.engine)
        cls.client = TestClient(app)

    def test_flow_aggregator_and_emitter(self):
        """Valida que FlowAggregator acumule actividad de red y emita registros NetFlow v5."""
        emitter = DummyNetFlowEmitter()
        aggregator = FlowAggregator(emitter, flush_interval_secs=10.0)

        # Simular actividad entre dos IPs
        aggregator.record_activity(
            src_ip="10.0.50.99",
            dst_ip="10.0.0.5",
            src_port=54321,
            dst_port=80,
            protocol=6,
            bytes_count=1200,
            packets_count=5,
            tcp_flags=24,
        )

        # Flujo en sentido contrario
        aggregator.record_activity(
            src_ip="10.0.0.5",
            dst_ip="10.0.50.99",
            src_port=80,
            dst_port=54321,
            protocol=6,
            bytes_count=4500,
            packets_count=8,
            tcp_flags=24,
        )

        count = aggregator.flush()
        self.assertEqual(count, 2)
        self.assertEqual(len(emitter.emitted_flows), 2)

        # Validar primer registro
        f1 = emitter.emitted_flows[0]
        self.assertEqual(f1.src_ip, "10.0.50.99")
        self.assertEqual(f1.dst_ip, "10.0.0.5")
        self.assertEqual(f1.bytes, 1200)
        self.assertEqual(f1.packets, 5)

        # Validar segundo registro
        f2 = emitter.emitted_flows[1]
        self.assertEqual(f2.src_ip, "10.0.0.5")
        self.assertEqual(f2.dst_ip, "10.0.50.99")
        self.assertEqual(f2.bytes, 4500)
        self.assertEqual(f2.packets, 8)
        emitter.close()

    def test_target_http_server_captures_real_requests(self):
        """Valida que un servidor objetivo real capture peticiones HTTP y registre flujos bidireccionales."""
        emitter = DummyNetFlowEmitter()
        aggregator = FlowAggregator(emitter, flush_interval_secs=10.0)

        # Iniciar servidor objetivo en puerto efímero libre
        TargetHTTPRequestHandler.aggregator = aggregator
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TargetHTTPRequestHandler)
        port = server.server_address[1]
        TargetHTTPRequestHandler.server_port = port

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        time.sleep(0.1)

        try:
            # 1. Petición GET raíz
            req = urllib.request.Request(f"http://127.0.0.1:{port}/")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                self.assertEqual(resp.status, 200)
                body = resp.read()
                self.assertIn(b"Enterprise Target App", body)

            # 2. Petición POST a /login (simulando ataque de fuerza bruta)
            post_data = b'{"username": "admin", "password": "password123"}'
            post_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/login",
                data=post_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(post_req, timeout=3.0)
            except urllib.error.HTTPError as e:
                # 401 Unauthorized esperado
                self.assertEqual(e.code, 401)

            # Volcar flujos acumulados por el servidor
            flushed = aggregator.flush()
            self.assertGreaterEqual(flushed, 2)
            self.assertGreater(len(emitter.emitted_flows), 0)

            # Verificar que los flujos tengan el puerto destino correcto
            ports = [f.dst_port for f in emitter.emitted_flows]
            self.assertIn(port, ports)
        finally:
            server.shutdown()
            server.server_close()
            emitter.close()

    def test_telemetry_rest_hook_endpoint(self):
        """Valida que POST /api/v1/telemetry/hook inyecte flujos y retorne alertas en tiempo real."""
        # Flujo de conexión hacia un C2 catalogado en Threat Intel
        payload = {
            "src_ip": "10.0.1.55",
            "dst_ip": "198.51.100.77",
            "src_port": 50123,
            "dst_port": 443,
            "protocol": 6,
            "bytes": 2400,
            "packets": 15,
            "tcp_flags": 24,
            "attack_label": "OmniBreach Cobalt Strike Probe",
        }

        resp = self.client.post("/api/v1/telemetry/hook", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "PROCESSED")
        self.assertGreaterEqual(data["alerts_count"], 1)

        # Validar que la alerta sea de tipo C2 / Maliciosa
        alerts = data["alerts"]
        alert_cats = [a["category"] for a in alerts]
        self.assertIn("MALICIOUS_C2", alert_cats)

    def test_telemetry_status_endpoint(self):
        """Valida el endpoint de estado de telemetría GET /api/v1/telemetry/status."""
        resp = self.client.get("/api/v1/telemetry/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertIn("ingestion_modes", data)
        self.assertEqual(data["ingestion_modes"]["netflow_udp_port"], 2055)


if __name__ == "__main__":
    unittest.main()
