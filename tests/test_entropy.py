"""
NovaFlow NDR - Shannon Information Entropy & DGA Detection Tests
Verifica el cálculo de entropía H(X), detección de subdominios DGA y alertas de túnel DNS.
"""

import math
import unittest
from collector.parser import NetFlowRecord
from detector.entropy import calculate_shannon_entropy, evaluate_domain_entropy
from detector.models import AlertCategory, AlertSeverity
from detector.rules.dns_tunnel import DnsTunnelDetector


class TestShannonEntropy(unittest.TestCase):
    """Pruebas unitarias para el motor de entropía de Shannon."""

    def test_zero_entropy_for_uniform_string(self):
        """Cadenas de caracteres idénticos deben tener entropía exacta de 0.0."""
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy("aaaaaaaaaa"), 0.0)
        self.assertEqual(calculate_shannon_entropy(b"\x00\x00\x00\x00"), 0.0)

    def test_natural_language_entropy_range(self):
        """Dominios legítimos y palabras en lenguaje natural deben tener entropía típica < 3.4."""
        # Palabras comunes y nombres legibles
        entropy_google = calculate_shannon_entropy("google")
        entropy_microsoft = calculate_shannon_entropy("microsoft")
        entropy_github = calculate_shannon_entropy("github")
        
        self.assertLess(entropy_google, 3.0)
        self.assertLess(entropy_microsoft, 3.2)
        self.assertLess(entropy_github, 3.0)

    def test_maximum_entropy_for_random_dga(self):
        """Cadenas generadas por DGA o datos codificados en Base64/Hex deben tener alta entropía (> 3.8)."""
        # Carga útil típica de Iodine o DNSCat2 (hexadecimal/pseudoaleatorio)
        hex_tunnel = "7b9f8a2c4e10d3f8a9e5b7c1"
        entropy_hex = calculate_shannon_entropy(hex_tunnel)
        self.assertGreaterEqual(entropy_hex, 3.8)

        # Cadenas pseudoaleatorias de DGA (Conficker, Locky, etc.)
        dga_label = "xqkjzvpmwltnbrfsdh"
        entropy_dga = calculate_shannon_entropy(dga_label)
        self.assertGreaterEqual(entropy_dga, 4.0)

    def test_evaluate_domain_entropy_natural_domains(self):
        """Dominios corporativos legítimos deben clasificarse como NATURAL_LANGUAGE."""
        result1 = evaluate_domain_entropy("api.google.com")
        self.assertEqual(result1["classification"], "NATURAL_LANGUAGE")
        self.assertFalse(result1["is_dga_candidate"])

        result2 = evaluate_domain_entropy("portal.empresa-segura.com.co")
        self.assertEqual(result2["classification"], "NATURAL_LANGUAGE")
        self.assertFalse(result2["is_dga_candidate"])

    def test_evaluate_domain_entropy_dga_tunnel(self):
        """Subdominios de túnel DNS o DGA deben ser clasificados como HIGH_ENTROPY_DGA."""
        dga_domain = "4f8a9b2c3d7e1f6a.tunnel.evil-attacker.org"
        result = evaluate_domain_entropy(dga_domain)
        self.assertTrue(result["is_dga_candidate"])
        self.assertEqual(result["classification"], "HIGH_ENTROPY_DGA")
        self.assertGreaterEqual(result["entropy"], 3.5)

    def test_dns_tunnel_detector_entropy_alert(self):
        """DnsTunnelDetector debe emitir una alerta crítica/alta ante un subdominio DGA."""
        detector = DnsTunnelDetector()
        alert = detector.analyze_dns_query(
            src_ip="192.168.1.45",
            dst_ip="8.8.8.8",
            domain="c7a8f9e0b1d2c3e4f5a6b7.exfil.darknet.com",
        )

        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, AlertCategory.DNS_TUNNEL)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertIn("c7a8f9e0b1d2c3e4f5a6b7", alert.description)
        self.assertGreaterEqual(alert.confidence, 0.88)
        self.assertIn("shannon_entropy", alert.metrics)

    def test_dns_tunnel_detector_ignores_benign_query(self):
        """DnsTunnelDetector no debe alertar sobre consultas a servicios estándar."""
        detector = DnsTunnelDetector()
        alert = detector.analyze_dns_query(
            src_ip="192.168.1.45",
            dst_ip="1.1.1.1",
            domain="updates.microsoft.com",
        )
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
