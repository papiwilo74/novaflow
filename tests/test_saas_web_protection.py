"""
NovaFlow NDR - Tests para Protección Especializada de Aplicaciones Web y SaaS
Valida que NovaFlow NDR actúe como escudo integral para aplicaciones web y plataformas SaaS:
1. Detección de Credential Stuffing & Fuerza Bruta de Autenticación (T1110)
2. Detección de Inundación L7 y Abuso de Rate Limiting en APIs (T1498)
3. Detección de SSRF y Extracción de Metadatos Cloud (169.254.169.254 - T1190)
4. Detección de Intrusión Este-Oeste contra Bases de Datos Internas (PostgreSQL, Redis, MySQL)
5. Detección de Escáneres Ofensivos y Bots (SQLMap, Nikto, Scrapy)
6. Decodificación de Carga Útil HTTP en el cable (HTTPWireParser)
7. Escudo de Contención Activa en Sonda Relay (Reverse Proxy Protection)
"""

import http.server
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone

from collector.l7_parsers import HTTPWireMessage, HTTPWireParser
from collector.parser import NetFlowRecord
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity
from detector.rules.web_threat import WebThreatDetector
from tools.live_probe import FlowAggregator, NetFlowEmitter, RelayHTTPRequestHandler


class TestSaaSWebApplicationProtection(unittest.TestCase):

    def setUp(self):
        self.engine = DetectionEngine()
        self.web_detector = WebThreatDetector(
            auth_rate_threshold=5,
            auth_window_secs=10.0,
            api_flood_threshold=15,
            api_flood_window_secs=5.0,
            alert_cooldown_secs=0.1,  # Reducido para pruebas rápidas
        )

    def test_http_wire_parser_decoding(self):
        """Valida que HTTPWireParser extraiga método, ruta, cabeceras y agente de usuario."""
        raw_http = (
            b"POST /api/v1/auth/login HTTP/1.1\r\n"
            b"Host: saas.app.internal\r\n"
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 42\r\n"
            b"\r\n"
            b'{"username": "admin", "password": "secret"}'
        )
        msg = HTTPWireParser.parse(raw_http)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.method, "POST")
        self.assertEqual(msg.path, "/api/v1/auth/login")
        self.assertEqual(msg.host, "saas.app.internal")
        self.assertIn("Mozilla/5.0", msg.user_agent)
        self.assertEqual(msg.content_type, "application/json")
        self.assertIn(b"admin", msg.body_sample)

    def test_credential_stuffing_detection(self):
        """Valida la detección de ráfagas masivas contra endpoints de login del SaaS."""
        src_attacker = "198.51.100.42"
        http_raw = (
            b"POST /api/v1/auth HTTP/1.1\r\n"
            b"Host: api.saas.io\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"user": "test", "pass": "123456"}'
        )
        msg = HTTPWireParser.parse(http_raw)
        self.assertIsNotNone(msg)

        alert = None
        # Enviar 6 peticiones consecutivas (umbral = 5)
        for _ in range(6):
            res = self.web_detector.evaluate_http_message(
                msg=msg,
                src_ip=src_attacker,
                dst_ip="10.0.1.10",
                dst_port=443,
            )
            if res:
                alert = res

        self.assertIsNotNone(alert, "Debe generar alerta tras superar el umbral de login")
        self.assertEqual(alert.category, AlertCategory.WEB_APP_THREAT)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.metrics["attack_vector"], "CREDENTIAL_STUFFING")
        self.assertIn("Credential Stuffing", alert.title)

    def test_api_flood_rate_abuse_detection(self):
        """Valida la detección de saturación y abuso de tasa en APIs del SaaS."""
        src_client = "198.51.100.88"
        http_raw = (
            b"GET /api/v2/reports/export?tenant=acme HTTP/1.1\r\n"
            b"Host: app.saas.com\r\n"
            b"User-Agent: Python-SDK/1.0\r\n"
            b"\r\n"
        )
        msg = HTTPWireParser.parse(http_raw)
        self.assertIsNotNone(msg)

        alert = None
        # Enviar 16 peticiones consecutivas (umbral = 15)
        for _ in range(16):
            res = self.web_detector.evaluate_http_message(
                msg=msg,
                src_ip=src_client,
                dst_ip="10.0.1.10",
                dst_port=80,
            )
            if res:
                alert = res

        self.assertIsNotNone(alert, "Debe generar alerta de inundación API L7")
        self.assertEqual(alert.category, AlertCategory.WEB_APP_THREAT)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.metrics["attack_vector"], "API_FLOOD_RATE_ABUSE")

    def test_ssrf_cloud_metadata_detection(self):
        """Valida la detección de intentos de robo de credenciales IAM via SSRF hacia 169.254.169.254."""
        # Prueba 1: SSRF a nivel L7 HTTP
        ssrf_http = (
            b"GET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\n"
            b"Host: 169.254.169.254\r\n"
            b"\r\n"
        )
        msg = HTTPWireParser.parse(ssrf_http)
        self.assertIsNotNone(msg)

        alert_l7 = self.web_detector.evaluate_http_message(
            msg=msg,
            src_ip="10.244.0.15",  # Pod web interno del SaaS
            dst_ip="169.254.169.254",
            dst_port=80,
        )
        self.assertIsNotNone(alert_l7)
        self.assertEqual(alert_l7.category, AlertCategory.WEB_APP_THREAT)
        self.assertEqual(alert_l7.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert_l7.metrics["attack_vector"], "SSRF_CLOUD_METADATA")

        # Prueba 2: SSRF a nivel L3/L4 (NetFlow flow directo)
        now = datetime.now(timezone.utc)
        ssrf_flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=1000,
            src_ip="10.244.0.15",
            dst_ip="169.254.169.254",
            next_hop="10.244.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=5,
            bytes=420,
            first_switched=1000,
            last_switched=1005,
            src_port=48922,
            dst_port=80,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=32,
        )
        alert_flow = self.web_detector.evaluate_east_west_flow(ssrf_flow)
        self.assertIsNotNone(alert_flow)
        self.assertEqual(alert_flow.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert_flow.metrics["attack_vector"], "SSRF_CLOUD_METADATA")

    def test_east_west_database_exposure(self):
        """Valida que un pod web intentando acceder a Redis o PostgreSQL sin autorización sea alertado."""
        now = datetime.now(timezone.utc)
        # Pod web comprometido intentando consultar Redis en el puerto 6379
        db_flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=2000,
            src_ip="10.244.2.45",
            dst_ip="10.0.99.15",
            next_hop="10.244.2.1",
            input_snmp=1,
            output_snmp=2,
            packets=12,
            bytes=8500,
            first_switched=2000,
            last_switched=2010,
            src_port=52300,
            dst_port=6379,  # Redis
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
        )
        alert = self.web_detector.evaluate_east_west_flow(db_flow)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.WEB_APP_THREAT)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.metrics["database_service"], "Redis In-Memory Cache")

    def test_offensive_dast_scanner_detection(self):
        """Valida la detección de escáneres DAST como SQLMap o Nikto atacando la aplicación SaaS."""
        sqlmap_req = (
            b"GET /api/v1/items?id=1%20UNION%20SELECT%20null,table_name%20FROM%20information_schema.tables HTTP/1.1\r\n"
            b"Host: saas.app.com\r\n"
            b"User-Agent: sqlmap/1.6#stable (https://sqlmap.org)\r\n"
            b"\r\n"
        )
        msg = HTTPWireParser.parse(sqlmap_req)
        self.assertIsNotNone(msg)

        alert = self.web_detector.evaluate_http_message(
            msg=msg,
            src_ip="198.51.100.7",
            dst_ip="10.0.0.5",
            dst_port=80,
        )
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.WEB_APP_THREAT)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.metrics["attack_vector"], "OFFENSIVE_TOOL_OR_BOT")
        self.assertIn("SQLMap", alert.metrics["tool"])

    def test_integrated_detection_engine_with_web_threat(self):
        """Valida que DetectionEngine unifique la detección web con el pipeline global."""
        now = datetime.now(timezone.utc)
        sqlmap_payload = (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: target-saas.com\r\n"
            b"User-Agent: nikto/2.1.6\r\n"
            b"\r\n"
        )
        flow = NetFlowRecord(
            timestamp=now,
            timestamp_ms=5000,
            src_ip="203.0.113.88",
            dst_ip="10.0.0.10",
            next_hop="10.0.0.1",
            input_snmp=1,
            output_snmp=2,
            packets=3,
            bytes=len(sqlmap_payload),
            first_switched=5000,
            last_switched=5005,
            src_port=49152,
            dst_port=8080,
            tcp_flags=24,
            protocol=6,
            tos=0,
            src_as=0,
            dst_as=0,
            src_mask=24,
            dst_mask=24,
            payload=sqlmap_payload,
        )
        alerts = self.engine.analyze_flow(flow)
        self.assertGreaterEqual(len(alerts), 1)
        web_alerts = [a for a in alerts if a.category == AlertCategory.WEB_APP_THREAT]
        self.assertEqual(len(web_alerts), 1)
        self.assertIn("Nikto", web_alerts[0].title)

    def test_relay_proxy_shields_saas_backend(self):
        """Valida que RelayHTTPRequestHandler proteja un backend SaaS y aplique contención SOAR."""
        # 1. Iniciar un servidor backend SaaS mock
        class SaaSBackendHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                resp = json.dumps({"tenant": "AlphaCorp", "saas_status": "ONLINE"}).encode("utf-8")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        backend_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SaaSBackendHandler)
        backend_port = backend_server.server_address[1]
        t_backend = threading.Thread(target=backend_server.serve_forever, daemon=True)
        t_backend.start()

        # 2. Iniciar RelayHTTPRequestHandler frente al backend SaaS
        class MockEmitter(NetFlowEmitter):
            def __init__(self):
                super().__init__("127.0.0.1", 2055)
                self.captured = []
            def send_flows(self, flows):
                self.captured.extend(flows)

        emitter = MockEmitter()
        aggregator = FlowAggregator(emitter, flush_interval_secs=10.0)
        RelayHTTPRequestHandler.aggregator = aggregator
        RelayHTTPRequestHandler.relay_target_url = f"http://127.0.0.1:{backend_port}"

        relay_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RelayHTTPRequestHandler)
        relay_port = relay_server.server_address[1]
        RelayHTTPRequestHandler.server_port = relay_port

        t_relay = threading.Thread(target=relay_server.serve_forever, daemon=True)
        t_relay.start()

        try:
            # 3. Petición normal a través del Relay -> Debe llegar al backend SaaS
            req = urllib.request.Request(f"http://127.0.0.1:{relay_port}/api/v1/health")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(data["saas_status"], "ONLINE")

            # 4. Activar contención activa SOAR sobre la IP del cliente (127.0.0.1)
            RelayHTTPRequestHandler.blocked_ips.add("127.0.0.1")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=2.0)
            self.assertEqual(ctx.exception.code, 403)
            body = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(body["status"], "BLOCKED")
            self.assertIn("NovaFlow NDR SOAR", body["shield"])
        finally:
            RelayHTTPRequestHandler.blocked_ips.discard("127.0.0.1")
            relay_server.shutdown()
            relay_server.server_close()
            backend_server.shutdown()
            backend_server.server_close()
            aggregator.stop()
            emitter.close()

    def test_multi_tenant_idor_hopping_detection(self):
        """Valida la detección de escaneo horizontal de tenants (IDOR / Tenant Hopping)."""
        src_attacker = "198.51.100.99"
        tenants = ["acme_corp", "globex_inc", "initech_llc"]
        alert = None

        for t in tenants:
            raw_http = (
                f"GET /api/v1/billing/invoices HTTP/1.1\r\n"
                f"Host: saas.app.com\r\n"
                f"X-Tenant-ID: {t}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"\r\n"
            ).encode("utf-8")
            msg = HTTPWireParser.parse(raw_http)
            self.assertIsNotNone(msg)
            res = self.web_detector.evaluate_http_message(
                msg=msg,
                src_ip=src_attacker,
                dst_ip="10.0.1.10",
                dst_port=443,
            )
            if res:
                alert = res

        self.assertIsNotNone(alert, "Debe alertar tras superar el umbral de tenant hopping")
        self.assertEqual(alert.category, AlertCategory.WEB_APP_THREAT)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.metrics["attack_vector"], "MULTI_TENANT_IDOR_HOPPING")
        self.assertIn("Multi-Tenant", alert.title)

    def test_saas_asgi_middleware_protection(self):
        """Valida que NovaFlowSaaSMiddleware intercepte y descarte peticiones de atacantes en ASGI."""
        import asyncio
        from collector.saas_middleware import NovaFlowSaaSMiddleware

        # Dummy ASGI app
        async def dummy_app(scope, receive, send):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"status": "ok"}',
            })

        middleware = NovaFlowSaaSMiddleware(dummy_app, enable_active_defense=True)
        attacker_ip = "203.0.113.199"

        # 1. Petición normal no bloqueada
        scope_ok = {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/dashboard",
            "headers": [(b"cf-connecting-ip", b"198.51.100.5"), (b"host", b"saas.com")],
            "client": ("198.51.100.5", 54321),
        }
        sent_messages = []
        async def mock_send(msg):
            sent_messages.append(msg)

        async def run_ok():
            await middleware(scope_ok, None, mock_send)

        asyncio.run(run_ok())
        self.assertEqual(sent_messages[0]["status"], 200)

        # 2. Bloquear IP del atacante en el middleware
        NovaFlowSaaSMiddleware.block_ip(attacker_ip)
        try:
            scope_blocked = {
                "type": "http",
                "method": "POST",
                "path": "/api/v1/login",
                "headers": [(b"x-forwarded-for", attacker_ip.encode()), (b"host", b"saas.com")],
                "client": (attacker_ip, 49999),
            }
            blocked_messages = []
            async def mock_send_blocked(msg):
                blocked_messages.append(msg)

            async def run_blocked():
                await middleware(scope_blocked, None, mock_send_blocked)

            asyncio.run(run_blocked())
            self.assertEqual(blocked_messages[0]["status"], 403)
            body = json.loads(blocked_messages[1]["body"].decode())
            self.assertEqual(body["status"], "BLOCKED")
            self.assertIn("NovaFlow", body["shield"])
        finally:
            NovaFlowSaaSMiddleware.unblock_ip(attacker_ip)
            middleware.close()


if __name__ == "__main__":

    unittest.main()

