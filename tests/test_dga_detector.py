"""
Pruebas unitarias para el Pilar 1: Motor DGA (N-Gramas) y Fast-Flux DNS.
"""

import unittest

from detector.dga import DGADetector, FastFluxTracker
from detector.models import AlertCategory, AlertSeverity
from detector.rules.dga_threat import DGAThreatDetector


class TestDGADetector(unittest.TestCase):
    """Batería de validación de detección de DGA y redes Fast-Flux."""

    def test_benign_domains_classification(self):
        """Verifica que dominios comerciales y corporativos legítimos no sean clasificados como DGA."""
        benign_domains = [
            "google.com",
            "microsoft.com",
            "api.github.com",
            "portal.bankofamerica.com",
            "cdn.cloudflare.com",
            "telemetry.internal.corp",
        ]
        for d in benign_domains:
            res = DGADetector.evaluate_domain(d)
            self.assertFalse(
                res["is_dga"],
                f"El dominio legítimo '{d}' no debe clasificarse como DGA (Score: {res['dga_score']})",
            )
            self.assertLess(res["dga_score"], 0.60)

    def test_dga_domains_detection(self):
        """Valida la detección de dominios generados algorítmicamente (Conficker, Locky, Sunburst)."""
        dga_domains = [
            "vzkqpmzljwtfrq.com",          # Ráfaga severa de consonantes
            "x839d012kd0291kd.net",         # Patrón alfanumérico Locky
            "flqwoiruzxnvbkp.biz",          # Fonética aleatoria
            "qy72bc91mq04x781290.org",      # Alta densidad de dígitos y baja alternancia
        ]
        for d in dga_domains:
            res = DGADetector.evaluate_domain(d)
            self.assertTrue(
                res["is_dga"],
                f"El dominio DGA '{d}' debe ser detectado positivamente (Score: {res['dga_score']})",
            )
            self.assertGreaterEqual(res["dga_score"], 0.60)
            self.assertIsNotNone(res["family_guess"])

    def test_fast_flux_tracking(self):
        """Verifica la detección de infraestructura Fast-Flux por rotación rápida de IPs y TTLs bajos."""
        tracker = FastFluxTracker(window_seconds=600.0)

        # 1. Dominio benigno con IP estable y TTL de 3600s
        for _ in range(5):
            tracker.record_resolution("service.corp.internal", ["10.0.0.10"], ttl=3600)
        res_benign = tracker.evaluate_flux("service.corp.internal")
        self.assertFalse(res_benign["is_fast_flux"])

        # 2. Dominio malicioso Fast-Flux rotando 6 IPs en diferentes subredes con TTL de 60s
        flux_domain = "c2-hidden-mesh.biz"
        fast_ips = [
            "185.220.101.5",
            "194.26.29.112",
            "45.33.32.156",
            "198.51.100.88",
            "203.0.113.19",
            "91.240.118.4",
        ]
        for ip in fast_ips:
            tracker.record_resolution(flux_domain, [ip], ttl=60)

        res_flux = tracker.evaluate_flux(flux_domain)
        self.assertTrue(res_flux["is_fast_flux"])
        self.assertEqual(res_flux["unique_ips_count"], 6)
        self.assertEqual(res_flux["average_ttl"], 60.0)
        self.assertGreaterEqual(res_flux["subnets_count"], 4)

    def test_dga_threat_detector_rule(self):
        """Prueba la emisión de alertas de seguridad formal ante dominios DGA."""
        detector = DGAThreatDetector()

        # Dominio benigno -> No alerta
        alert_benign = detector.evaluate_dns_query("login.microsoft.com", src_ip="10.0.1.20")
        self.assertIsNone(alert_benign)

        # Dominio DGA -> Alerta
        alert_dga = detector.evaluate_dns_query("vzkqpmzljwtfrq.com", src_ip="10.0.1.20")
        self.assertIsNotNone(alert_dga)
        self.assertEqual(alert_dga.category, AlertCategory.DGA_DOMAIN)
        self.assertEqual(alert_dga.src_ip, "10.0.1.20")
        self.assertIn("vzkqpmzljwtfrq.com", alert_dga.title)
        self.assertEqual(alert_dga.mitre["technique_id"], "T1568")


if __name__ == "__main__":
    unittest.main()
