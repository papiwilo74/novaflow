"""
NovaFlow NDR - Threat Intelligence & C2 Feeds Matcher
Coteja en tiempo real las direcciones IP contra listas de indicadores de compromiso (IoC).
"""

import ipaddress
from typing import Dict, List, Optional, Set, Tuple

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert

# Base de datos de reputación inicial / IoCs conocidos (Feodo, CobaltStrike C2, Ransomware)
DEFAULT_MALICIOUS_IPS: Dict[str, Dict[str, str]] = {
    "198.51.100.77": {"family": "Cobalt Strike C2", "actor": "APT29", "severity": "CRITICAL"},
    "185.220.101.5": {"family": "Tor Exit Node / Scanner", "actor": "Unknown", "severity": "HIGH"},
    "45.33.32.156": {"family": "Mirai Botnet C2", "actor": "Botnet Operator", "severity": "CRITICAL"},
    "194.26.29.112": {"family": "QakBot Loader", "actor": "TA577", "severity": "CRITICAL"},
}


class ThreatIntelMatcher:
    """Compara IPs de origen y destino contra bases de datos de Threat Intelligence (IPs y CIDR)."""

    def __init__(self, feed_db: Optional[Dict[str, Dict[str, str]]] = None):
        self._threat_db: Dict[str, Dict[str, str]] = {}
        self._cidr_db: List[Tuple[ipaddress.IPv4Network, Dict[str, str]]] = []

        initial = feed_db or DEFAULT_MALICIOUS_IPS
        for target, meta in initial.items():
            self.add_ioc(
                target,
                family=meta.get("family", "Malware C2"),
                severity=meta.get("severity", "HIGH"),
                actor=meta.get("actor", "Unknown"),
            )

    def add_ioc(self, target: str, family: str, severity: str = "HIGH", actor: str = "Unknown"):
        meta = {"family": family, "actor": actor, "severity": severity}
        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                self._cidr_db.append((net, meta))
            except ValueError:
                self._threat_db[target] = meta
        else:
            self._threat_db[target] = meta

    def _match_ip(self, ip_str: str) -> Optional[Dict[str, str]]:
        # 1. Búsqueda exacta O(1)
        if ip_str in self._threat_db:
            return self._threat_db[ip_str]

        # 2. Búsqueda en rangos CIDR si existen
        if self._cidr_db:
            try:
                addr = ipaddress.ip_address(ip_str)
                for net, meta in self._cidr_db:
                    if addr in net:
                        return meta
            except ValueError:
                pass

        return None

    def analyze_flow(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        # Revisar si destino u origen está en base de IoC (individual o CIDR)
        threat_info = self._match_ip(flow.dst_ip)
        matched_ip = flow.dst_ip
        direction = "Saliente hacia C2"

        if not threat_info:
            threat_info = self._match_ip(flow.src_ip)
            matched_ip = flow.src_ip
            direction = "Entrante desde C2"

        if threat_info:
            sev_str = threat_info.get("severity", "HIGH")
            severity = AlertSeverity.CRITICAL if sev_str == "CRITICAL" else AlertSeverity.HIGH
            family = threat_info.get("family", "Malware C2")
            actor = threat_info.get("actor", "Desconocido")

            return SecurityAlert(
                severity=severity,
                category=AlertCategory.MALICIOUS_C2,
                title=f"Conexión con C2 / IP Maliciosa ({family}): {matched_ip}",
                description=(
                    f"Se detectó tráfico de red ({direction}) con la dirección {matched_ip}:{flow.dst_port} "
                    f"asociada a la amenaza '{family}' (Actor: {actor}). "
                    f"Flujo: {flow.packets} paquetes, {flow.bytes} bytes transferidos."
                ),
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                confidence=0.98,
                metrics={
                    "threat_actor": actor,
                    "malware_family": family,
                    "matched_ip": matched_ip,
                    "direction": direction,
                },
            )

        return None
