"""
NovaFlow NDR - AI SOC Copilot & Explainability Test Suite
Valida las capacidades del Copiloto SOC Híbrido:
- Diagnóstico de salud e inferencia GPU
- Explicabilidad pericial de incidentes (X-NDR)
- Recomendaciones de contención activa SOAR
- Traducción de lenguaje natural a Threat Hunting DSL
- Canal de conversación interactivo SOC
- Resiliencia Zero-Crash (fallback determinista ante caídas de LLM)
- Filtro de Cero Emojis
"""

import unittest
from unittest.mock import patch, AsyncMock
from starlette.testclient import TestClient

from api.main import app
from api.state import system_state
from detector.engine import DetectionEngine
from detector.models import AlertCategory, AlertSeverity, SecurityAlert
from detector.copilot import NovaFlowSOCCopilot, soc_copilot


class TestNovaFlowSOCCopilot(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = DetectionEngine()
        system_state.initialize(cls.engine)
        cls.client = TestClient(app)

        # Inyectar una alerta de prueba en el historial
        from datetime import datetime, timezone
        cls.sample_alert = SecurityAlert(
            alert_id="c0p1l0t-0001-aaaa-bbbb-ccccdddd0001",
            timestamp=datetime.now(timezone.utc),
            category=AlertCategory.PORT_SCAN,
            severity=AlertSeverity.HIGH,
            title="Escaneo Horizontal de Puertos",
            description="El host 192.168.1.50 escaneó 120 puertos en 2 segundos.",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            dst_port=445,
            protocol=6,
            confidence=0.95,
            metrics={"scanned_ports_count": 120, "scan_rate": 60.0},
        )
        cls.engine.alerts_history.append(cls.sample_alert)

        # Inyectar flujos de prueba
        flow1 = {
            "timestamp": "2026-09-24T18:00:00Z",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 49152,
            "dst_port": 445,
            "protocol": 6,
            "protocol_name": "TCP",
            "bytes": 15000000,
            "packets": 12000,
            "tcp_flags": 2,
        }
        system_state.recent_flows.append(flow1)

    # -------------------------------------------------------------------------
    # 1. PRUEBAS UNITARIAS DE CLASE Y UTILIDADES
    # -------------------------------------------------------------------------

    def test_strip_emojis(self):
        """Valida la política de CERO EMOJIS eliminando cualquier pictograma decorativo."""
        dirty_text = "🚨 ALERTA CRÍTICA: Se detectó SYN Flood 🛑 en el servidor 10.0.0.1 💻🔥!"
        clean_text = NovaFlowSOCCopilot._strip_emojis(dirty_text)
        self.assertNotIn("🚨", clean_text)
        self.assertNotIn("🛑", clean_text)
        self.assertNotIn("💻", clean_text)
        self.assertNotIn("🔥", clean_text)
        self.assertIn("ALERTA CRÍTICA: Se detectó SYN Flood", clean_text)
        self.assertIn("10.0.0.1", clean_text)

    def test_deterministic_fallback_generation(self):
        """Valida que el motor determinista construya un reporte pericial sin fallos."""
        copilot = NovaFlowSOCCopilot()
        prompt = (
            "Categoría: SYN_FLOOD\n"
            "Severidad: CRITICAL\n"
            "Host Origen: 185.220.101.5\n"
            "Host Destino: 10.0.0.2:80\n"
            "Descripción: Sobrecarga masiva de paquetes SYN."
        )
        fallback = copilot._generate_deterministic_fallback(prompt)
        self.assertIn("SYN_FLOOD", fallback)
        self.assertIn("CRITICAL", fallback)
        self.assertIn("185.220.101.5", fallback)
        self.assertIn("10.0.0.2:80", fallback)
        self.assertIn("T1498.001", fallback)
        self.assertIn("Diagnóstico del Incidente", fallback)
        self.assertIn("Acciones Tácticas Inmediatas", fallback)

    # -------------------------------------------------------------------------
    # 2. PRUEBAS DE ENDPOINTS REST API
    # -------------------------------------------------------------------------

    def test_copilot_health_endpoint(self):
        """Valida GET /api/v1/copilot/health."""
        response = self.client.get("/api/v1/copilot/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertIn("active_tier", data)
        self.assertIn("configured_model", data)
        self.assertIn("latency_ms", data)
        self.assertIn(data["status"], ["HEALTHY", "DEGRADED"])

    def test_copilot_explain_by_alert_id(self):
        """Valida POST /api/v1/copilot/explain usando un alert_id existente."""
        response = self.client.post(
            "/api/v1/copilot/explain",
            json={"alert_id": "c0p1l0t-0001-aaaa-bbbb-ccccdddd0001"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["alert_id"], "c0p1l0t-0001-aaaa-bbbb-ccccdddd0001")
        self.assertIn("report_markdown", data)
        self.assertIn("backend_used", data)
        self.assertGreater(len(data["report_markdown"]), 50)
        # Verificar que no contenga emojis
        self.assertNotIn("🚨", data["report_markdown"])
        self.assertNotIn("🔥", data["report_markdown"])

    def test_copilot_explain_by_raw_payload(self):
        """Valida POST /api/v1/copilot/explain usando datos ad-hoc en alert_data."""
        raw_alert = {
            "alert_id": "adhoc-alert-99",
            "category": "MALICIOUS_C2",
            "severity": "CRITICAL",
            "title": "Tráfico Beaconing C2",
            "description": "Intervalo periódico de baliza hacia dominio no categorizado.",
            "src_ip": "172.16.0.40",
            "dst_ip": "198.51.100.22",
            "dst_port": 8443,
            "protocol": 6,
        }
        response = self.client.post(
            "/api/v1/copilot/explain",
            json={"alert_data": raw_alert},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("report_markdown", data)
        self.assertIn("backend_used", data)

    def test_copilot_explain_not_found(self):
        """Valida que alert_id inexistente sin alert_data devuelva 404."""
        response = self.client.post(
            "/api/v1/copilot/explain",
            json={"alert_id": "non-existent-alert-id-12345"},
        )
        self.assertEqual(response.status_code, 404)

    def test_copilot_containment(self):
        """Valida POST /api/v1/copilot/containment."""
        response = self.client.post(
            "/api/v1/copilot/containment",
            json={"alert_id": "c0p1l0t-0001-aaaa-bbbb-ccccdddd0001"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("containment_advice", data)
        self.assertIn("target_ip", data)
        self.assertEqual(data["target_ip"], "192.168.1.50")

    def test_copilot_hunt_translate(self):
        """Valida POST /api/v1/copilot/hunt-translate con y sin ejecución."""
        response = self.client.post(
            "/api/v1/copilot/hunt-translate",
            json={
                "query": "Conexiones TCP con flag SYN y bytes mayores a 10 megas",
                "execute": True,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("translated_dsl", data)
        self.assertIn("backend_used", data)
        self.assertIn("executed", data)

    def test_copilot_chat(self):
        """Valida POST /api/v1/copilot/chat con contexto del motor."""
        response = self.client.post(
            "/api/v1/copilot/chat",
            json={
                "message": "¿Qué técnicas MITRE detecta actualmente NovaFlow NDR?",
                "include_system_context": True,
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("response", data)
        self.assertIn("backend_used", data)
        self.assertGreater(len(data["response"]), 20)

    # -------------------------------------------------------------------------
    # 3. PRUEBA DE RESILIENCIA ZERO-CRASH (FALLBACK DETERMINISTA)
    # -------------------------------------------------------------------------

    def test_zero_crash_fallback_when_ollama_unreachable(self):
        """Valida que ante desconexión o fallo total de red, el copiloto nunca lance 500 y active fallback."""
        with patch.object(NovaFlowSOCCopilot, "_call_llm", AsyncMock(return_value=(
            "### Diagnóstico del Incidente\nAnomalía detectada en modo offline.",
            "deterministic_heuristic_fallback",
            12.5,
        ))):
            response = self.client.post(
                "/api/v1/copilot/explain",
                json={"alert_id": "c0p1l0t-0001-aaaa-bbbb-ccccdddd0001"},
            )
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data["success"])
            self.assertEqual(data["backend_used"], "deterministic_heuristic_fallback")
            self.assertIn("Diagnóstico del Incidente", data["report_markdown"])


if __name__ == "__main__":
    unittest.main()
