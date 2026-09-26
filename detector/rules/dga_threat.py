"""
NovaFlow NDR - DGA & Fast-Flux DNS Threat Detection Rule
Evalúa resoluciones y consultas DNS corporativas para identificar dominios
algorítmicos generados por malware y redes Fast-Flux de evasión.
"""

from typing import Any, Dict, List, Optional

from detector.dga import DGADetector, FastFluxTracker
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


class DGAThreatDetector:
    """Regla analítica para detección de dominios DGA y redes Fast-Flux."""

    def __init__(self, flux_tracker: Optional[FastFluxTracker] = None):
        self.dga_classifier = DGADetector()
        self.flux_tracker = flux_tracker or FastFluxTracker()

    def evaluate_dns_query(
        self,
        domain: str,
        src_ip: str = "10.0.0.1",
        dst_ip: str = "10.0.0.53",
        dst_port: int = 53,
    ) -> Optional[SecurityAlert]:
        """Evalúa un nombre de dominio consultado por un host interno."""
        res = self.dga_classifier.evaluate_domain(domain)
        if not res["is_dga"]:
            return None

        score = res["dga_score"]
        severity = AlertSeverity.CRITICAL if score >= 0.85 else AlertSeverity.HIGH
        family = res.get("family_guess") or "Algorítmico"

        return SecurityAlert(
            severity=severity,
            category=AlertCategory.DGA_DOMAIN,
            title=f"Dominio DGA Detectado ({family}): {domain}",
            description=(
                f"El host interno {src_ip} consultó el dominio sospechoso '{domain}'. "
                f"El análisis lingüístico y de n-gramas determinó un puntaje DGA de {score:.2f} "
                f"propio de familias de malware ({family})."
            ),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=17,
            confidence=score,
            metrics={
                "domain": domain,
                "dga_score": score,
                "family_guess": family,
                "sld": res["sld"],
                "linguistic_metrics": res["metrics"],
            },
        )

    def evaluate_dns_response(
        self,
        domain: str,
        resolved_ips: List[str],
        ttl: int,
        src_ip: str = "10.0.0.1",
        dns_server: str = "10.0.0.53",
    ) -> Optional[SecurityAlert]:
        """Evalúa la respuesta DNS recibida para detectar comportamiento Fast-Flux."""
        self.flux_tracker.record_resolution(domain, resolved_ips, ttl)
        flux_info = self.flux_tracker.evaluate_flux(domain)

        if not flux_info["is_fast_flux"]:
            return None

        return SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.DGA_DOMAIN,
            title=f"Resolución DNS Fast-Flux Detectada: {domain}",
            description=(
                f"El dominio '{domain}' presenta rotación rápida de direcciones IP "
                f"({flux_info['unique_ips_count']} IPs únicas en {flux_info['subnets_count']} subredes) "
                f"con un TTL promedio anómalamente bajo ({flux_info['average_ttl']}s), "
                f"patrón característico de infraestructura C2 Fast-Flux."
            ),
            src_ip=src_ip,
            dst_ip=dns_server,
            dst_port=53,
            protocol=17,
            confidence=0.92,
            metrics={
                "domain": domain,
                "fast_flux": True,
                "unique_ips_count": flux_info["unique_ips_count"],
                "subnets_count": flux_info["subnets_count"],
                "average_ttl": flux_info["average_ttl"],
                "sample_ips": flux_info["sample_ips"],
            },
        )
